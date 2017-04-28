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
import salt.utils.aws
from salt.ext import six
import salt.utils.xmlutil as xml
from salt._compat import ElementTree as ET
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
    try:
        res = _delete_bucket(name, subresource=subresource, configuration_id=configuration_id)
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:delete_bucket: Error deleting {0}?{1}: {2}'.format(name, subresource, ex))
    return res


def _delete_bucket(bucket, subresource='', **kwargs):
    '''
    Delete a bucket, or delete subresources of a bucket.
    Returnvalue: True on success
    Exceptions: SaltInvocationError, CommandExecutionError
    '''
    kwargs = _get_defaults(**kwargs)
    subresource_data = {'': {},
                        'analytics': {'parameters': {'configuration_id': True}},
                        'cors': {},
                        'inventory': {'parameters': {'configuration_id': True}},
                        'lifecycle': {},
                        'metrics': {'parameters': {'configuration_id': True}},
                        'policy': {},
                        'replication': {},
                        'tagging': {},
                        'website': {}}
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_delete_bucket:\n'
              '\t\tparams: {}'.format(params))
    del params['']
    # Rename configuration_id to id
    if 'configuration_id' in params:
        params['id'] = params.pop('configuration_id')
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, **kwargs)
    headers, requesturl = _generate_headers_request_url(method='DELETE',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('DELETE',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_delete_bucket:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 DELETE operation failed: {0}'.format(err))
    elif subresource:
        log.debug('salt/modules/s3:_delete_bucket:\n'
                  '\t\tRemoved {0} from bucket {1}'.format(subresource, bucket))
    else:
        log.debug('salt/modules/s3:_delete_bucket:\n'
                  '\t\tDeleted bucket {0}'.format(bucket))
    return True


def delete_bucket_object(bucket, name, subresource=''):
    '''
    Deletes (the subresource of) an object in a bucket.
    '''
    res = False
    try:
        if isinstance(name, str):
            res = _delete_bucket_object(bucket, name, subresource=subresource)
        elif isinstance(name, list) and subresource == '':
            res = _delete_bucket_multiple_object(bucket, name, subresource='delete')
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:delete_bucket_object:\n'
                  'Error deleting {0}/{1}?{2}: {3}'.format(bucket, name, subresource, ex))
    return res


def _delete_bucket_object(bucket, objectname, subresource='', **kwargs):
    '''
    Deletes an object from a bucket, or a subresource from an object in a bucket.
    Raises CommandExecutionError on error
    '''
    kwargs = _get_defaults(**kwargs)
    subresource_data = {'': {}, 'tagging': {}}
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_delete_bucket_object:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket,
                                                        path=objectname,
                                                        **kwargs)
    headers, requesturl = _generate_headers_request_url(method='DELETE',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('DELETE',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('modules/s3:_delete_bucket:\n' +
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 DELETE operation failed: {0}'.format(err))
    return True


def list_buckets(region=None):
    '''
    Lists all buckets in the region specified or the region of the EC2 instance
    from where this is called.
    '''
    ret = {}
    try:
        ret = _list_buckets(region=region)
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:list_buckets:\n'
                  '\t\tError listing buckets: {}'.format(ex))
    return ret


def _list_buckets(**kwargs):
    '''
    Returns a dict with the owner 'name' and the 'buckets' list owned.
    Each bucket is represented by a dict containing the 'Name' and the 'CreationDate' keys.
    '''
    kwargs = _get_defaults(**kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(**kwargs)
    headers, requesturl = _generate_headers_request_url(method='GET',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers={},
                                                        params={},
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('GET',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_list_buckets:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 list operation failed: {0}'.format(err))
    if result.content:
        log.debug('salt/modules/s3:_list_buckets:\n'
                  '\t\tRESULT: {}'.format(result.content))
        ret = {'buckets': []}
        list_result = xml.to_dict(ET.fromstring(result.content))
        ret.update({'owner': list_result['Owner']})
        if 'Bucket' in list_result['Buckets']:
            if isinstance(list_result['Buckets']['Bucket'], list):
                for bucket in list_result['Buckets']['Bucket']:
                    ret['buckets'].append(bucket)
            else:
                ret['buckets'].append(list_result['Buckets']['Bucket'])
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
    '''
    ret = None
    kwargs = {}
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
            result = _get_bucket(name,
                                 subresource=subresource,
                                 **kwargs)
            if 'start-after' in kwargs:
                del kwargs['start-after']
            content_tag = list_base_tag[subresource]
            ret.extend(_parse_bucket_contents(result, content_tag))
            while result['IsTruncated'] == 'true' and _set_get_continuation(result, kwargs):
                result = _get_bucket(name,
                                     subresource=subresource,
                                     **kwargs)
                ret.extend(_parse_bucket_contents(result, content_tag))
        except CommandExecutionError as ex:
            log.error('salt/modules/s3:get_bucket:\n'
                      '\t\tError retrieving contents of {0}?{1}: {2}'.format(name,
                                                                             subresource,
                                                                             ex))
    else:
        try:
            result = _get_bucket(name,
                                 subresource=subresource,
                                 **kwargs)
            if subresource == 'tagging':
                ret = _s3_tagging_to_dict(result)
            else:
                ret = result
        except CommandExecutionError as ex:
            log.error('salt/modules/s3:get_bucket:\n'
                      '\t\tError retrieving contents of {0}?{1}: {2}'.format(name,
                                                                             subresource,
                                                                             ex))
    return ret


def _get_bucket(bucket, subresource='', **kwargs):
    '''
    List the contents of a bucket (up to 1000 objects) or get subresources of a bucket.

    CLI Example to list the contents of a bucket:

    .. code-block:: bash
        salt myminion s3.get mybucket

    Amazon currently supports the following subresources:
        accelerate, acl, analytics, cors, inventory, lifecycle, location, logging,
        metrics, notification, versions, policy, replication, requestPayment,
        tagging, versioning, website.

    '''
    kwargs = _get_defaults(**kwargs)
    log.debug('HERBERT: salt/modules/s3:_get_bucket: kwargs: {}'.format(kwargs))
    subresource_data = {'': {'parameters': {'delimiter': False, 'encoding-type': False,
                                            'max-keys': False, 'prefix': False,
                                            'list-type': True, 'continuation-token': False,
                                            'fetch-owner': False, 'start-after': False}},
                        'accelerate': {},
                        'acl': {},
                        'analytics': {'parameters': {'id': True}},
                        'cors': {},
                        'inventory': {'parameters': {'id': True}},
                        'lifecycle': {},
                        'location': {},
                        'logging': {},
                        'metrics': {'parameters': {'id': True}},
                        'notification': {},
                        'versions': {'parameters': {'delimiter': False, 'encoding-type': False,
                                                    'key-marker': False, 'max-keys': False,
                                                    'prefix': False, 'version-id-marker': False}},
                        'policy': {},
                        'replication': {},
                        'requestPayment': {},
                        'tagging': {},
                        'uploads': {'parameters': {'delimiter': False, 'encoding-type': False,
                                                   'max-uploads': False, 'key-marker': False,
                                                   'prefix': False, 'upload-id-marker': False}},
                        'versioning': {},
                        'website': {}}
    if subresource == '':
        kwargs.update({'list-type': '2'})
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_get_bucket:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, **kwargs)
    headers, requesturl = _generate_headers_request_url(method='GET',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('GET',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_get_bucket:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 GET operation failed: {0}'.format(err))
    if result.content:
        ret = xml.to_dict(ET.fromstring(result.content))
    else:
        ret = True
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
    new_kwargs = {'subresource': subresource, 'local_file': local_file,
                  'return_contents': return_contents, 'versionId': version_id}
    ret = None
    if subresource == 'torrent' and (local_file is None or not return_contents):
        log.error('salt/modules/s3:get_bucket_object:\n'
                  '\t\tError retrieving contents of {0}/{1}?{2}: '.format(bucket, name, subresource) +
                  'For subresource torrent, '
                  'either local_file or return_content must be specified.')
        return ret
    if subresource in ['tagging', 'acl']:
        return_contents = True
    try:
        result = _get_bucket_object(bucket, name, **new_kwargs)
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
        log.error('salt/modules/s3:get_bucket_object:\n'
                  '\t\tError retrieving contents of {0}/{1}?{2}: {3}'.format(bucket,
                                                                             name,
                                                                             subresource,
                                                                             ex))
    return ret


def _get_bucket_object(bucket, objectname, subresource='', **kwargs):
    '''
    Gets (subresource of) object at path in bucket.
    '''
    kwargs = _get_defaults(**kwargs)
    request_kwargs = {}
    log.debug('salt/modules/s3:_get_bucket_object:\n'
              '\t\tkwargs: {}'.format(kwargs))
    subresource_data = {'': {'parameters': {'response-content-type': False,
                                            'response-content-language': False,
                                            'response-expires': False,
                                            'response-cache-control': False,
                                            'response-content-disposition': False,
                                            'response-content-encoding': False},
                             'headers': {'Range': False, 'If-Modified-Since': False,
                                         'If-Unmodified-Since': False, 'If-Match': False,
                                         'If-None-Match': False,
                                         'x-amz-server-side-encryption-customer-algorithm': False,
                                         'x-amz-server-side-encryption-customer-key': False,
                                         'x-amz-server-side-encryption-customer-key-MD5': False}},
                        'acl': {'parameters': {'versionId': False}, 'headers': {}},
                        'tagging': {'parameters': {}, 'headers': {}},
                        'torrent': {'parameters': {}, 'headers': {}}}
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_get_bucket_object:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket,
                                                        path=objectname,
                                                        **kwargs)
    headers, requesturl = _generate_headers_request_url(method='GET',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    if subresource != '' and requesturl.endswith('='):
        requesturl = requesturl[:-1]
    if subresource == '':
        request_kwargs['stream'] = True
    result = _do_request('GET',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'],
                         **request_kwargs)
    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_get_bucket_object:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.headers: {}'.format(result.headers))
    if err:
        raise CommandExecutionError('S3 GET operation failed: {}'.format(err))
    return result


def head_bucket(name, region=None):
    '''
    Returns True if the bucket exists and there are enough permissions to access it.
    '''
    ret = {}
    try:
        ret = _head_bucket(name, region=region)
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:head_bucket:\n'
                  '\t\tError during HEAD-request of bucket: {}'.format(ex))
    return ret


def _head_bucket(bucket, **kwargs):
    '''
    Returns True if the bucket exists and there are enough permissions to access it.
    Raises CommandExecutionError if anything goes wrong.
    '''
    kwargs = _get_defaults(**kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, **kwargs)
    headers, requesturl = _generate_headers_request_url(method='HEAD',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers={},
                                                        params={},
                                                        data='',
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('HEAD',
                         requesturl,
                         headers=headers,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_head_bucket:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 HEAD operation failed: {}'.format(err))
    return True


def put_bucket(name, subresource='', **kwargs):
    '''
    Publicly exposed function for putting buckets
    '''
    try:
        ret = _put_bucket(name, subresource=subresource, **kwargs)
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:put_bucket:\n'
                  '\t\tError putting bucket: {}'.format(ex))
        ret = '{}'.format(ex)
    return ret


def _put_bucket(bucket, subresource='', **kwargs):
    '''
    Creates a new S3 bucket, or modifies the subresource configuration.
    See also: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUT.html
    Generates headers as required.
    '''
    kwargs = _get_defaults(**kwargs)
    log.debug('salt/modules/s3:_put_bucket:\n'
              '\t\tkwargs: {}'.format(kwargs))
    subresource_data = {'': {'headers': {'x-amz-acl': False, 'x-amz-grant-read': False,
                                         'x-amz-grant-write': False, 'x-amz-grant-read-acp': False,
                                         'x-amz-grant-write-acp': False, 'x-amz-grant-full-control': False},
                             'parameters': {}, 'body_root': 'CreateBucketConfiguration'},
                        'accelerate': {'headers': {}, 'parameters': {},
                                       'body_root': 'AccelerateConfiguration'},
                        'acl': {'headers': {'x-amz-acl': False, 'x-amz-grant-read': False,
                                            'x-amz-grant-write': False, 'x-amz-grant-read-acp': False,
                                            'x-amz-grant-write-acp': False, 'x-amz-grant-full-control': False},
                                'parameters': {}, 'body_root': 'AccessControlPolicy'},
                        'analytics': {'headers': {}, 'parameters': {'id': True},
                                      'body_root': 'AnalyticsConfiguration'},
                        'cors': {'headers': {'Content-MD5': True}, 'parameters': {},
                                 'body_root': 'CORSConfiguration'},
                        'inventory': {'headers': {}, 'parameters': {'id': True},
                                      'body_root': 'InventoryConfiguration'},
                        'lifecycle': {'headers': {'Content-MD5': True}, 'parameters': {},
                                      'body_root': 'LifecycleConfiguration'},
                        'logging': {'headers': {}, 'parameters': {},
                                    'body_root': 'BucketLoggingStatus'},
                        'metrics': {'headers': {}, 'parameters': {'id': True},
                                    'body_root': 'MetricsConfiguration'},
                        'notification': {'headers': {}, 'parameters': {},
                                         'body_root': 'NotificationConfiguration'},
                        'policy': {'headers': {}, 'parameters': {}, 'body_root': None},
                        'replication': {'headers': {'Content-MD5': True}, 'parameters': {},
                                        'body_root': 'ReplicationConfiguration'},
                        'requestPayment': {'headers': {}, 'parameters': {},
                                           'body_root': 'RequestPaymentConfiguration'},
                        'tagging': {'headers': {'Content-MD5': False}, 'parameters': {},
                                    'body_root': 'Tagging'},
                        'versioning': {'headers': {'x-amz-mfa': False}, 'parameters': {},
                                       'body_root': 'VersioningConfiguration'},
                        'website': {'headers': {}, 'parameters': {},
                                    'body_root': 'WebsiteConfiguration'}}
    if kwargs['region'] is not None and subresource == '' and kwargs.get('data', None) is None:
        kwargs['data'] = {'CreateBucketConfiguration': {'LocationConstraint': kwargs['region']}}

    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_put_bucket:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, **kwargs)
    if subresource == 'policy':
        data = kwargs.get('data', None)
    else:
        data = _generate_subresource_data(subresource,
                                          subresource_data[subresource]['body_root'],
                                          kwargs.get('data', None))
        headers.update({'Content-MD5': base64.b64encode(hashlib.md5(data).digest())})
    log.debug('salt/modules/s3:_put_bucket:\n'
              '\t\tdata: {}'.format(data))
    headers, requesturl = _generate_headers_request_url(method='PUT',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data=data,
                                                        payload_hash=None,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    result = _do_request('PUT',
                         requesturl,
                         headers=headers,
                         data=data,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug('modules/s3:_put_bucket:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 PUT operation failed: {}'.format(err))
    if result.content:
        ret = xml.to_dict(result.content)
    else:
        ret = True
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
    new_kwargs = kwargs.copy()
    if subresource == 'tagging':
        new_kwargs['data'] = _dict_to_s3_tagging(kwargs.get('tags', {})) \
                                if 'tags' in kwargs else kwargs.get('data', None)
    try:
        ret = _put_bucket_object(bucket,
                                 name,
                                 subresource=subresource,
                                 local_file=local_file,
                                 **new_kwargs)
    except CommandExecutionError as ex:
        log.error('salt/modules/s3:put_bucket_object:\n'
                  '\t\tError putting bucket: {}'.format(ex))
    return ret


def _put_bucket_object(bucket, objectname, subresource='', local_file=None, **kwargs):
    '''
    Puts an object in a bucket or puts a configuration in a subresource of an object in a bucket.
    Header values can be passed as kwargs.
    Params can be passed as kwargs.
    '''
    kwargs = _get_defaults(**kwargs)
    log.debug('salt/modules/s3: _put_bucket_object:\n'
              '\t\tkwargs: {}'.format(kwargs))
    subresource_data = {'': {'headers': {'Cache-Control': False, 'Content-Disposition': False,
                                         'Content-Encoding': False, 'Content-Length': False,
                                         'Content-MD5': False, 'Content-Type': False,
                                         'Expect': False, 'Expires': False,
                                         'x-amz-meta-': False, 'x-amz-storage-class': False,
                                         'x-amz-tagging': False, 'x-amz-website-redirect-location': False,
                                         'x-amz-acl': False, 'x-amz-grant-read': False,
                                         'x-amz-grant-write': False, 'x-amz-grant-read-acp': False,
                                         'x-amx-grant-write-acp': False, 'x-amz-grant-full-control': False,
                                         'x-amz-server-side-encryption': False,
                                         'x-amz-amz-server-side-encryption-aws-kms-key-id': False,
                                         'x-amz-server-side-encryption-context': False,
                                         'x-amz-server-side-encryption-customer-algorithm': False,
                                         'x-amz-server-side-encryption-customer-key': False,
                                         'x-amz-server-side-encryption-customer-key-MD5': False},
                             'parameters': {}},
                        'acl': {'headers': {'x-amz-acl': False, 'x-amz-grant-read': False,
                                            'x-amz-grant-write': False, 'x-amz-grant-read-acp': False,
                                            'x-amz-grant-write-acp': False, 'x-amz-grant-full-control': False},
                                'parameters': {},
                                'body_root': 'AccessControlPolicy'},
                        'tagging': {'headers': {'Content-MD5': False},
                                    # Acutally, Content-MD5 is required, but we're calculating it here.
                                    'parameters': {}, 'body_root': 'Tagging'}}
    headers = _check_headers(subresource_data[subresource].get('headers', {}), **kwargs)
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data[subresource].get('parameters', {}), **kwargs))
    log.debug('salt/modules/s3:_put_bucket_object:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    # Unfortunately, requests-lib will likely never support 100-Expects
    # https://github.com/kennethreitz/requests/issues/713
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, path=objectname, **kwargs)
    data = ''
    payload_hash = None
    if subresource == '':
        if local_file is not None:
            payload_hash = salt.utils.get_hash(local_file, form='sha256')
        elif kwargs.get('data', None) is not None:
            data = kwargs['data']
            # Payload hash will be calculated by salt.utils.aws.sig4
        else:
            raise SaltInvocationError('No data or local file given to put.')
    else:
        data = _generate_subresource_data(subresource,
                                          subresource_data[subresource]['body_root'],
                                          kwargs.get('data', None))
        headers.update({'Content-MD5': base64.b64encode(hashlib.md5(data).digest())})
        log.debug('salt/modules/s3:_put_bucket_object:\n'
                  '\t\tdata: {}'.format(data))
    headers, requesturl = _generate_headers_request_url(method='PUT',
                                                        proto=proto,
                                                        endpoint=endpoint,
                                                        uri=uri,
                                                        headers=headers,
                                                        params=params,
                                                        data=data,
                                                        payload_hash=payload_hash,
                                                        region=kwargs['region'],
                                                        role_arn=kwargs['role_arn'],
                                                        key=kwargs['key'],
                                                        keyid=kwargs['keyid'])
    try:
        if subresource == '' and local_file is not None:
            data = salt.utils.fopen(local_file, 'rb')
        result = _do_request('PUT',
                             requesturl,
                             headers=headers,
                             data=data,
                             verify=kwargs['verify_ssl'])
    finally:
        if subresource == '' and local_file is not None:
            data.close()

    err = _generic_result_error_check(result)
    log.debug('salt/modules/s3:_put_bucket_object:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        return err
    if result.content:
        ret = xml.to_dict(result.content)
    else:
        ret = True
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
               'region': ('s3.region', salt.utils.aws.get_region()),
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
    log.debug('HERBERT: salt/modules/s3: _get_defaults: ret: {0}'.format(ret))
    return ret


def _do_request(method, url, **kwargs):
    '''
    Wrapper for requests in order to fix dropping the Authorization-header
    on 307-redirects to different hosts. Which is the case for a redirect
    from:
        https://<bucketname>.s3.amazonaws.com
    to:
        https://<bucketname>.s3-<region>.amazonaws.com
    See also https://github.com/kennethreitz/requests/issues/2949
    '''
    log.debug('salt/modules/s3: _do_request:\n' +
              'method: {}\n'.format(method) +
              'url: {}\n'.format(url) +
              'kwargs: {}'.format(kwargs))
    result = requests.request(method,
                              url,
                              allow_redirects=False,
                              **kwargs)
    if result.status_code in [301, 302, 307, 308]:
        result = requests.request(method,
                                  result.headers['Location'],
                                  allow_redirects=False,
                                  **kwargs)
    return result


def _generic_result_error_check(result):
    '''
    Generic function to extract error-data from result.
    Returns a dict, empty if there was no error.
    If there was an error, and the API response is parsable,
    the dict will contain:
      code, message, request_id, resource
    otherwise only code (with the HTTP statuscode) and
    message (with the full API response) will be present.
    '''
    ret = {}
    if result.status_code >= 400:
        # On error the S3 API response should contain error message
        err_text = result.content or 'Unknown error'
        log.debug('utils/s3:_generic_result_error_check: Response content: {0}'.format(err_text))
        # Try to get err info from response xml
        try:
            err_data = xml.to_dict(ET.fromstring(err_text))
            ret = {key.lower(): value for key, value in six.iteritems(err_data)}
        except (KeyError, ET.ParseError) as err:
            log.debug('utils/s3:_generic_result_error_check: ' +
                      'Failed to parse s3 err response. ' +
                      '{0}: {1}\n'.format(type(err).__name__, err))
            ret.update({'code': 'http-{0}'.format(result.status_code),
                        'message': err_text})
    return ret


def _check_subresources(subresource, allowed_subresources):
    '''
    Checks if the specified subresource is allowed.
    Returns params dict for the subresource or raises SaltInvocationError.
    '''
    if subresource is not None and subresource not in allowed_subresources.keys():
        raise SaltInvocationError('Invalid subresource specified: {0}.\n'.format(subresource) +
                                  'Valid subresources are: {0}'.format(allowed_subresources.keys()))
    params = {subresource: ''} if subresource is not None else {}
    return params


def _check_parameters(possible_params, **kwargs):
    '''
    Check if the possible params are required and supplied.
    Returns a params-dict for all params supplied.
    Raises SaltInvocationError if a required parameter was not supplied or has no value.
    '''
    ret = {}
    for param, required in six.iteritems(possible_params):
        if required and kwargs.get(param, None) is None:
            raise SaltInvocationError('A required parameter {0} '.format(param) +
                                      'was not supplied or was None')
        if param in kwargs:
            ret.update({param: kwargs[param]})
    return ret


def _check_headers(headers, **kwargs):
    '''
    Checks if the required headers are present in kwargs.
    Headers is a dict with the header as key, and its required status as value (bool).
    Returns a dict with the headers and their data from kwargs.
    '''
    ret = {}
    for header, required in six.iteritems(headers):
        if required and kwargs.get(header, None) is None:
            raise SaltInvocationError('A required header {0} '.format(header) +
                                      'was not supplied or was none')
        if header in kwargs:
            ret.update({header: kwargs[header]})
    return ret


def _generate_subresource_data(subresource, subresource_body_root, data):
    '''
    Generates the data to be sent in the body of a PUT request with subresource.
    Returns string with data
    '''
    if subresource_body_root is None or data is None:
        return ''
    if not isinstance(data, dict):
        raise SaltInvocationError('Data passed for subresource is not a dict: {}'.format(data))
    if subresource_body_root not in data:
        raise SaltInvocationError('Data passed for subresource does not have '
                                  'required root element {}'.format(subresource_body_root))
    root_node = ET.Element(subresource_body_root)
    salt.utils.xmlutil.from_dict(root_node, data[subresource_body_root])
    return ET.tostring(root_node)


def _generate_proto_endpoint_uri(service_url='s3.amazonaws.com',
                                 region=None,
                                 bucket='',
                                 path='',
                                 path_style=False,
                                 https_enable=True,
                                 **kwargs):
    '''
    Returns the endpoint to use in the call to S3.
    The story on whether to use virtual-hosted-style or path-style URLs:
    http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
    '''
    log.debug('salt/modules/s3: _generate_proto_endpoint_uri:\n' +
              '\t\tservice_url: {}\n'.format(service_url) +
              '\t\tregion: {}\n'.format(region) +
              '\t\tbucket: {}\n'.format(bucket) +
              '\t\tpath: {}'.format(path))
    endpoint = service_url
    uri = ''
    proto = 'http{}://'.format('s' if https_enable else '')
    if service_url == 's3.amazonaws.com' and region:
        endpoint = 's3-{}.amazonaws.com'.format(region)
    if not bucket:
        return proto, endpoint, '/'
    if path_style:
        uri += '/{}'.format(bucket)
    else:
        endpoint = '{0}.{1}'.format(bucket, endpoint)
    uri += '/{}'.format(path)
    log.debug('salt/modules/s3: _generate_proto_endpoint_uri:\n' +
              'proto: {}\n'.format(proto) +
              'endpoint: {}\n'.format(endpoint) +
              'uri: {}'.format(uri))
    return proto, endpoint, uri


def _generate_headers_request_url(method,
                                  proto,
                                  endpoint,
                                  uri,
                                  headers,
                                  params,
                                  data,
                                  payload_hash,
                                  region,
                                  role_arn,
                                  key,
                                  keyid):
    '''
    Wrapper for getting the signed headers and request_url with all params explicitly required
    '''
    return salt.utils.aws.sig4(
        method,
        endpoint,
        params,
        data=data,
        payload_hash=payload_hash,
        uri=uri,
        prov_dict={'id': keyid, 'key': key},
        role_arn=role_arn,
        region=region,
        product='s3',
        requesturl=proto + endpoint,
        headers=headers
    )


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
    data = input['TagSet']['Tag']
    log.debug('HERBERT: data: {}'.format(data))
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
