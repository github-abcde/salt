# -*- coding: utf-8 -*-
'''
Module for Amazon S3-services

:configuration: This module accepts explicit s3 credentials but can also utilize
    IAM roles assigned to the instance through Instance Profiles. Dynamic
    credentials are then automatically obtained from AWS API and no further
    configuration is necessary. More Information available at::

       http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file::

        s3.keyid: GKTADJGHEIQSXMKKRBJ08H
        s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    (Note: this is literally the pillar key 's3.keyid' or the config option 's3.keyid',
      not a nested dict like:
        s3:
          keyid: GKTADJGHEIQSXMKKRBJ08H
          key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
    )

    A service_url may also be specified in the configuration::

        s3.service_url: s3.amazonaws.com

    A role_arn may also be specified in the configuration::

        s3.role_arn: arn:aws:iam::111111111111:role/my-role-to-assume

    AWS region may be specified in the configuration:

        s3.region: eu-central-1

    Default is us-east-1.

    So concluding, in order of presedence, the key/keyid/region/role_arn credentials
    will be retrieved from:
    - pillar
    - configuration options
    - EC2 linked IAM role (via metadata URL http://169.254.169.254) (key/keyid/region)

    If a service_url is not specified, the default is s3.amazonaws.com. This
    may appear in various documentation as an "endpoint". A comprehensive list
    for Amazon S3 may be found at::

        http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region

    The service_url will form the basis for the final endpoint that is used to
    query the service.

    Path style can be enabled:

        s3.path_style: True

    This can be useful if you need to use salt with a proxy for an s3 compatible storage

    You can use either https protocol or http protocol:

        s3.https_enable: True

    SSL verification may also be turned off in the configuration:

        s3.verify_ssl: False

    This is required if using S3 bucket names that contain a period, as
    these will not match Amazon's S3 wildcard certificates. Certificate
    verification is enabled by default.

:depends: requests
'''
from __future__ import absolute_import

# Import Python libs
import logging
import hashlib
import base64

# Import 3rd-party libs
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Import Salt libs
import salt.utils
import salt.utils.s3
import salt.utils.xmlutil as xml
from salt._compat import ElementTree as ET
from salt.ext import six
from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Requires requests library.
    '''
    if not HAS_REQUESTS:
        log.error('salt/modules/s3 uses the "requests" library for s3 access')
    return HAS_REQUESTS


def delete_bucket(name, subresource='', configuration_id=None):
    '''
    Deletes a bucket, or deletes a subresource of a bucket
    The subresources 'analytics', 'inventory' and 'metrics' require an
    additional argument 'configuration_id'.
    Returns True on success, False on error. The error will also get logged.
    '''
    res = False
    kwargs = _get_defaults(**{})
    try:
        res = salt.utils.s3.delete_bucket(name, subresource=subresource, configuration_id=configuration_id, **kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':delete_bucket: Error deleting {0}?{1}: {2}'.format(name, subresource, ex))
    return res


def delete_bucket_object(bucket, name, subresource=''):
    '''
    Deletes (the subresource of) an object in a bucket.
    '''
    res = False
    kwargs = _get_defaults(**{})
    try:
        if isinstance(name, str):
            res = salt.utils.s3.delete_bucket_object(bucket, name, subresource=subresource, **kwargs)
        elif isinstance(name, list) and subresource == '':
            res = salt.utils.s3.delete_bucket_multiple_object(bucket, name, subresource='delete', **kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':delete_bucket_object:\n'
                  'Error deleting {0}/{1}?{2}: {3}'.format(bucket, name, subresource, ex))
    return res


def list_buckets(region=None):
    '''
    Lists all buckets in the region specified or the region of the EC2 instance
    from where this is called.
    '''
    ret = {}
    kwargs = _get_defaults(region=region)
    try:
        ret = salt.utils.s3.list_buckets(**kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':list_buckets:\n'
                  '\t\tError listing buckets: {}'.format(ex))
    return ret


def get_bucket(name, subresource='', delimiter=None, encoding_type=None,
               max_keys=1000, prefix=None, fetch_owner=False, start_after=None,
               configuration_id=None, key_marker=None, version_id_marker=None):
    '''
    List the contents of a bucket or get subresources of a bucket.
    In case of no subresource:
        Returns a list of dicts, each entry with the keys:
        - Key
        - LastModified
        - ETag
        - Size
        - StorageClass
    Specifying subresource 'tagging' results in a dict of tags.

    CLI Example to list the contents of a bucket:

    .. code-block:: bash
        salt myminion s3.get mybucket

    Amazon currently supports the following subresources:
        accelerate, acl, analytics, cors, inventory, lifecycle, location, logging,
        metrics, notification, versions, policy, replication, requestPayment,
        tagging, versioning, website.
    '''
    ret = None
    kwargs = _get_defaults(**{})
    param_translations = {'delimiter': delimiter, 'encoding-type': encoding_type,
                          'max-keys': max_keys, 'prefix': prefix, 'fetch-owner': fetch_owner,
                          'start-after': start_after, 'id': configuration_id,
                          'key-marker': key_marker, 'version-id-marker': version_id_marker}
    for their_name, our_value in six.iteritems(param_translations):
        if our_value is not None:
            kwargs[their_name] = our_value
    if subresource in ['', 'versions']:
        ret = []
        list_base_tag = {'': 'Contents', 'versions': 'Version'}
        for delete_this in ['continuation_token', 'key-marker', 'version-id-marker']:
            if delete_this in kwargs:
                del kwargs[delete_this]
        try:
            result = salt.utils.s3.get_bucket(name,
                                 subresource=subresource,
                                 **kwargs)
            if 'start-after' in kwargs:
                del kwargs['start-after']
            content_tag = list_base_tag[subresource]
            ret.extend(_parse_bucket_contents(result, content_tag))
            while result['IsTruncated'] == 'true' and _set_get_continuation(result, kwargs):
                result = salt.utils.s3.get_bucket(name,
                                     subresource=subresource,
                                     **kwargs)
                ret.extend(_parse_bucket_contents(result, content_tag))
        except CommandExecutionError as ex:
            log.error(__name__ + ':get_bucket:\n'
                      '\t\tError retrieving contents of {0}?{1}: {2}'.format(name,
                                                                             subresource,
                                                                             ex))
    else:
        try:
            result = salt.utils.s3.get_bucket(name,
                                 subresource=subresource,
                                 **kwargs)
            if subresource == 'tagging':
                ret = _s3_tagging_to_dict(result)
            else:
                ret = result
        except CommandExecutionError as ex:
            log.error(__name__ + ':get_bucket:\n'
                      '\t\tError retrieving contents of {0}?{1}: {2}'.format(name,
                                                                             subresource,
                                                                             ex))
    return ret


def get_bucket_object(bucket,
                      name,
                      subresource='',
                      local_file=None,
                      return_contents=False,
                      region=None,
                      version_id=None):
    '''
    Returns (subresource of) object at path in bucket.
    When returning an object, you can choose between having it stored in the file designated by local_file,
    or to have its contents returned as-is (using return_contents=True).
    '''
    kwargs = _get_defaults(**{'subresource': subresource, 'local_file': local_file,
                              'return_contents': return_contents, 'versionId': version_id})
    ret = None
    if subresource == 'torrent' and (local_file is None or not return_contents):
        log.error(__name__ + ':get_bucket_object:\n'
                  '\t\tError retrieving contents of {0}/{1}?{2}: '.format(bucket, name, subresource) +
                  'For subresource torrent, '
                  'either local_file or return_content must be specified.')
        return ret
    if subresource in ['tagging', 'acl']:
        return_contents = True
    try:
        result = salt.utils.s3.get_bucket_object(bucket, name, **kwargs)
        if local_file is not None:
            with salt.utils.fopen(local_file, 'wb') as filehandle:
                if result.headers.get('Transfer-Encoding', '') == 'chunked':
                    for chunk in result.iter_content(chunk_size=16384):
                        filehandle.write(chunk)
                elif result.headers.get('Content-Type', '') in ['binary/octet-stream', 'application/x-bittorrent']:
                    filehandle.write(result.content)
            ret = True
        elif return_contents:
            if result.headers.get('Transfer-Encoding', '') == 'chunked':
                ret = ''
                for chunk in result.iter_content(chunk_size=16384):
                    ret += chunk
            else:
                ret = result.content
            if subresource not in ['', 'torrent']:
                ret = xml.to_dict(ET.fromstring(ret))
                if subresource == 'tagging':
                    log.debug('HERBERT: ret: {}'.format(ret))
                    ret = _s3_tagging_to_dict(ret)
        else:
            ret = True
    except CommandExecutionError as ex:
        log.error(__name__ + ':get_bucket_object:\n'
                  '\t\tError retrieving contents of {0}/{1}?{2}: {3}'.format(bucket,
                                                                             name,
                                                                             subresource,
                                                                             ex))
    return ret


def head_bucket(name, region=None):
    '''
    Returns True if the bucket exists and there are enough permissions to access it.
    '''
    ret = {}
    kwargs = _get_defaults(region=region)
    try:
        ret = salt.utils.s3.head_bucket(name, **kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':head_bucket:\n'
                  '\t\tError during HEAD-request of bucket: {}'.format(ex))
    return ret


def put_bucket(name, subresource='', **kwargs):
    '''
    Publicly exposed function for putting buckets
    '''
    kwargs = _get_defaults(**kwargs)
    try:
        ret = salt.utils.s3.put_bucket(name, subresource=subresource, **kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':put_bucket:\n'
                  '\t\tError putting bucket: {}'.format(ex))
        ret = '{}'.format(ex)
    return ret


def put_bucket_object(bucket, name, subresource='', local_file=None, **kwargs):
    '''
    Publicly exposed function for putting stuff in buckets.

    Usage:
        salt minion s3.put_bucket_object bucketname path=objectname local_file=/path/to/file
    or, with data supplied directly:
        salt minion s3.put_bucket_object bucketname path=objectname data="Some data"

    For subresource=tagging, supply a dict of tags under 'tags'.

    Usage:
        salt minion s3.put_bucket_object bucketname subresource=tagging tags="{'key': 'value', 'key2': 'value2'}"
    '''
    ret = {}
    new_kwargs = _get_defaults(**kwargs)
    if subresource == 'tagging':
        new_kwargs['data'] = _dict_to_s3_tagging(kwargs.get('tags', {})) \
                                if 'tags' in kwargs else kwargs.get('data', None)
    try:
        ret = salt.utils.s3.put_bucket_object(bucket,
                                 name,
                                 subresource=subresource,
                                 local_file=local_file,
                                 **new_kwargs)
    except CommandExecutionError as ex:
        log.error(__name__ + ':put_bucket_object:\n'
                  '\t\tError putting bucket: {}'.format(ex))
    return ret


def _get_defaults(**kwargs):
    '''
    Gets defaults from config or provides some from here.
    The following items are supported:
        key, keyid, kms_keyid, region, path_style, role_arn, service_url and verify_ssl.
    Modifies kwargs
    '''
    ret = kwargs.copy()
    options = {'https_enable': ('s3.https_enable', True),
               'key': ('s3.key', salt.utils.aws.IROLE_CODE),
               'keyid': ('s3.keyid', salt.utils.aws.IROLE_CODE),
               'kms_keyid': ('aws.kms.keyid', None),
               'region': ('s3.region', salt.utils.aws.get_location()),
               'path_style': ('s3.path_style', False),
               'role_arn': ('s3.role_arn', None),
               'service_url': ('s3.service_url', 's3.amazonaws.com'),
               'verify_ssl': ('s3.verify_ssl', True)}
    for item, value in six.iteritems(options):
        if kwargs.get(item, None) is not None:
            ret[item] = kwargs[item]
        elif __opts__.get(item, None) is not None:
            ret[item] = __opts__[item]
        elif __pillar__.get(item, None) is not None:
            ret[item] = __pillar__[item]
        else:
            ret[item] = value[-1]
    log.debug(__name__ + ': _get_defaults: ret: {0}'.format(ret))
    return ret


def _parse_bucket_contents(result, content_tag):
    '''
    Returns list of bucket contents
    '''
    ret = []
    if content_tag in result:
        if isinstance(result[content_tag], list):
            for entry in result[content_tag]:
                ret.append(entry)
        else:
            ret.append(result[content_tag])
    return ret


def _dict_to_s3_tagging(tags):
    '''
    Encodes a dict with key-value-tags to the dict structure required for PUTting them in S3.
    '''
    ret = {'Tagging': {'TagSet': []}}
    for key, value in six.iteritems(tags):
        ret['Tagging']['TagSet'].append({'Tag': {'Key': key, 'Value': value}})
    return ret


def _s3_tagging_to_dict(input):
    '''
    Decodes the dict-structure from S3 to a single dict with key-value tags.
    '''
    ret = {}
    if input is None or input['TagSet'] is None:
        return ret
    data = input['TagSet']['Tag']
    if not isinstance(data, list):
        data = [data]
    for item in data:
        ret[item['Key']] = item['Value']
    return ret


def _set_get_continuation(result, kwargs):
    '''
    Helper function to set required kwargs for the next iteration of a truncated GET request.
    Returns whether or not another iteration is possible.
    '''
    ret = False
    for token, param in six.iteritems({'NextContinuationToken': 'continuation-token',
                                       'NextKeyMarker': 'key-marker',
                                       'NextVersionIdMarker': 'version-id-marker'}):
        if token in result:
            kwargs[param] = result[token]
            ret = True
    return ret
