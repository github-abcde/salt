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
    not "s3:\\n  keyid: blah".)

    A service_url may also be specified in the configuration::

        s3.service_url: s3.amazonaws.com

    A role_arn may also be specified in the configuration::

        s3.role_arn: arn:aws:iam::111111111111:role/my-role-to-assume

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

    AWS region may be specified in the configuration:

        s3.region: eu-central-1

    Default is us-east-1.

:depends: requests
'''
from __future__ import absolute_import

# Import Python libs
import logging

# Import 3rd-party libs
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Import Salt libs
import salt.utils
from salt.ext import six
import salt.utils.xmlutil as xml
from salt._compat import ElementTree as ET
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Requires requests library.
    '''
    if not HAS_REQUESTS:
        log.error('There was an error: requests is required for s3 access')
    return HAS_REQUESTS


def _delete_bucket(bucket, subresource=None, **kwargs):
    '''
    Delete a bucket, or delete subresources of a bucket.
    Returnvalue: True on success
    Exceptions: SaltInvocationError, CommandExecutionError
    '''
    kwargs = _get_defaults(**kwargs)
    parameters = {'analytics': {'id': {'required': True}},
                  'cors': {},
                  'inventory': {'id': {'required': True}},
                  'lifecycle': {},
                  'metrics': {'id': {'required': True}},
                  'policy': {},
                  'replication': {},
                  'tagging': {},
                  'website': {}}
    params = _check_subresources(subresource, parameters.keys())
    params.update(_check_parameters(parameters[subresource], **kwargs))
    endpoint, uri = _generate_endpoint_uri(bucket=bucket, **kwargs)

    headers, requesturl = _generate_headers_requesturl('PUT', endpoint, uri, headers,
                                                       params, data, prov_dict, role_arn)

    log.debug('modules/s3:delete: S3 Request: {0}'.format(requesturl))
    log.debug('modules/s3:delete: S3 Headers::')
    log.debug('modules/s3:delete: Authorization: {0}'.format(headers['Authorization']))

    result = _do_request(method,
                         request_url,
                         headers=headers,
                         verify=verify_ssl)
    err = _result_error_check(result)
    log.debug('modules/s3:delete: S3 Response Status Code: {0}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 DELETE operation failed: {0}'.format(err))
    elif subresource:
        log.debug('modules/s3:delete: Removed {0} from bucket {1}'.format(subresource, bucket))
    else:
        log.debug('modules/s3:delete: Deleted bucket {0}'.format(bucket))
    return True


def _list_buckets(**kwargs):
    '''
    Returns a list of all buckets owned.
    Each bucket is represented by a dict containing the 'Name' and the 'CreationDate' keys.
    '''
    kwargs = _get_defaults(**kwargs)
    headers, requesturl = _generate_headers_requesturl('GET', service_url, '/', headers,
                                                       params, data, prov_dict, role_arn)
    result = _do_request(method,
                         request_url,
                         headers=headers,
                         verify=verify_ssl)
    err = _result_error_check(result)
    log.debug('utils/s3:list: S3 Response Status Code: {0}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 list operation failed: {0}'.format(err))
    if result.content:
        ret = []
        items = ET.fromstring(result.content)
        for bucket in items['Buckets']:
            ret.append(xml.to_dict(bucket))
    return ret


def _get_bucket(bucket, subresource=None, **kwargs):
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
    possible_params = {'': {'delimiter': False, 'encoding-type': False, 'max-keys': False,
                            'prefix': False, 'list-type': True, 'continuation-token': False,
                            'fetch-owner': False, 'start-after': False},
                       'analytics': {'id': True},
                       'inventory': {'id': True},
                       'metrics': {'id': True},
                       'versions': {'delimiter': False, 'encoding-type': False,
                                    'key-marker': False, 'max-keys': False, 'prefix': False,
                                    'version-id-marker': False}}
    if subresource is None:
        subresource = ''
        kwargs.update({'list-type': '2'})
    params = _check_subresources(subresource, parameters.keys())
    params.update(_check_parameters(parameters.get(subresource, {}), **kwargs))
    endpoint, uri = _generate_endpoint_uri(bucket=bucket, **kwargs)

    headers, requesturl = _generate_headers_requesturl('GET', endpoint, uri, headers,
                                                       params, data, prov_dict, role_arn)
    log.debug('modules/s3:delete: S3 Request: {0}'.format(requesturl))
    log.debug('modules/s3:delete: S3 Headers::')
    log.debug('modules/s3:delete: Authorization: {0}'.format(headers['Authorization']))

    result = _do_request(method,
                         request_url,
                         headers=headers,
                         verify=verify_ssl)
    err = _result_error_check(result)
    log.debug('modules/s3:delete: S3 Response Status Code: {0}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 GET operation failed: {0}'.format(err))
    if result.content:
        ret = xml.to_dict(result.content)
    return ret


def _head_bucket(bucket, **kwargs):
    '''
    Returns True if the bucket exists and there are enough permissions to access it.
    Raises CommandExecutionError if anything goes wrong.
    '''
    kwargs = _get_defaults(**kwargs)
    endpoint, uri = _generate_endpoint_uri(bucket=bucket, **kwargs)

    headers, requesturl = _generate_headers_requesturl('PUT', endpoint, uri, headers,
                                                       params, data, prov_dict, role_arn)
    result = _do_request(method,
                         request_url,
                         headers=headers,
                         verify=verify_ssl)
    err = _result_error_check(result)
    log.debug('modules/s3:delete: S3 Response Status Code: {0}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 GET operation failed: {0}'.format(err))
    return True


def _put_bucket(bucket, subresource=None, **kwargs):
    '''
    Creates a new S3 bucket, or modifies the subresource configuration.
    See also: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUT.html
    '''
    kwargs = _get_defaults(**kwargs)
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
                        'tagging': {'headers': {'Content-MD5': True}, 'parameters': {},
                                    'body_root': 'Tagging'},
                        'versioning': {'headers': {'x-amz-mfa': False}, 'parameters': {},
                                       'body_root': 'VersioningConfiguration'},
                        'website': {'headers': {}, 'parameters': {},
                                    'body_root': 'WebsiteConfiguration'}}
    if subresource is None:
        subresource = ''
    params = _check_subresources(subresource, parameters.keys())
    params.update(_check_parameters(subresource_data[subresource]['parameters'], **kwargs))
    headers = _check_headers(subresource_data[subresource]['headers'], **kwargs)
    endpoint, uri = _generate_endpoint_uri(bucket=bucket, **kwargs)
    if subresource == 'policy':
        data = kwargs['data']
    else:
        data = _generate_subresource_data(subresource,
                                          subresource_data[subresource]['body_root'],
                                          kwargs['data'])
    headers, requesturl = _generate_headers_requesturl('PUT', endpoint, uri, headers,
                                                       params, data, prov_dict, role_arn)

    log.debug('modules/s3:put: S3 Request: {0}'.format(requesturl))
    log.debug('modules/s3:put: S3 Headers: {0}'.format(headers))
    log.debug('modules/s3:put: S3 Params:  {0}'.format(params))

    result = _do_request(method,
                         request_url,
                         headers=headers,
                         verify=verify_ssl)
    err = _result_error_check(result)
    log.debug('modules/s3:put: S3 Response Status Code: {0}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 PUT operation failed: {0}'.format(err))
    if result.content:
        ret = xml.to_dict(result.content)
    return ret


def _get_defaults(**kwargs):
    '''
    Gets defaults from config or provides some from here.
    The following items are supported:
        key, keyid, kms_keyid, region, path_style, role_arn, service_url and verify_ssl.
    Modifies kwargs
    '''
    ret = {}
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
        kwargs[item] = __salt__['config.option'](value) if kwargs.get(item, None) is None else kwargs[item]
    return kwargs


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


def _check_params(possible_params, **kwargs):
    '''
    Check if the possible params are required and supplied.
    Returns a params-dict for all params supplied.
    Raises SaltInvocationError if a required parameter was not supplied or has no value.
    '''
    params = {}
    for param in possible_params:
        if param and kwargs.get(param, None) is None:
            raise SaltInvocationError('A required parameter {1} '.format(param) +
                                      'was not supplied or was None')
        if param in kwargs:
            params.update({param: kwargs[param]})
    return params


def _generate_subresource_data(subresource, subresource_body_root, data):
    '''
    Generates the data to be sent in the body of a PUT request with subresource.
    Returns string with data
    '''
    if subresource_body_root is None:
        return ''
    root_node = ET.Element(subresource_body_root)
    salt.utils.xmlutil.from_dict(root_node, data[root_tag])
    return ET.tostring(root_node, encoding='UTF-8')


def _generate_endpoint_uri(service_url, region=None, bucket='', path='', path_style=False, **kwargs):
    '''
    Returns the endpoint to use in the call to S3.
    The story on whether to use virtual-hosted-style or path-style URLs:
    http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
    '''
    endpoint = service_url
    uri = ''
    if service_url == 's3.amazonaws.com' and region:
        endpoint = 's3-{0}.amazonaws.com'.format(region)
    if not bucket:
        return endpoint, '/'
    if path_style:
        uri += '/{0}'.format(bucket)
    else:
        endpoint = '{0}.{1}'.format(bucket, ret)
    if path:
        uri += '/{0}'.format(path)
    return endpoint, uri


def _generate_headers_request_url(method, endpoint, uri, headers, params, data, prov_dict, role_arn):
    '''
    Wrapper for getting the signed headers and request_url
    '''
    return salt.utils.aws.sig4(
        method,
        endpoint,
        params,
        data=data,
        uri=uri,
        prov_dict={'id': keyid, 'key': key},
        role_arn=role_arn,
        region=region,
        product='s3',
        requesturl='http{0}://{1}'.format('s' if kwargs['https_enable'] else '', endpoint),
        headers=headers
    )


def _delete_bucket_object(bucket, objectname, **kwargs):
    '''
    Deletes an object from a bucket, or a subresource from an object in a bucket.
    Raises CommandExecutionError on error
    '''
    kwargs = _get_defaults(**kwargs)
    parameters = {'tagging': {}}
    params = _check_subresources(subresource, parameters.keys())
    params.update(_check_parameters(parameters[subresource], **kwargs))
    endpoint = _generate_endpoint(bucket=bucket, **kwargs)

    if not requesturl:
        requesturl = (('https' if https_enable else 'http')+'://{0}/').format(endpoint)
    headers, requesturl = salt.utils.aws.sig4(
        'DELETE',
        endpoint,
        params,
        uri='/',
        prov_dict={'id': keyid, 'key': key},
        role_arn=role_arn,
        region=region,
        product='s3',
        requesturl=requesturl,
        headers=headers or {},
    )

    log.debug('modules/s3:delete: S3 Request: {0}'.format(requesturl))
    log.debug('modules/s3:delete: S3 Headers::')
    log.debug('modules/s3:delete: Authorization: {0}'.format(headers['Authorization']))








