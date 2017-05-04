# -*- coding: utf-8 -*-
'''
Connection library for Amazon S3

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
    HAS_REQUESTS = True  # pylint: disable=W0612
except ImportError:
    HAS_REQUESTS = False  # pylint: disable=W0612

# Import Salt libs
import salt.utils
import salt.utils.aws
import salt.utils.xmlutil as xml
from salt.ext import six
from salt._compat import ElementTree as ET
from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)


def delete_bucket(bucket, subresource='', **kwargs):
    '''
    Delete a bucket, or delete subresources of a bucket.
    Returns: True on success
    Exceptions: SaltInvocationError, CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETE.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEAnalyticsConfiguration.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEcors.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEInventoryConfiguration.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETElifecycle.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTDeleteBucketMetricsConfiguration.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEpolicy.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEreplication.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEtagging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETEwebsite.html
    '''
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
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_delete_bucket:\n'
              '\t\tparams: {}'.format(params))
    del params['']
    # Rename configuration_id to id
    if 'configuration_id' in params:
        params['id'] = params.pop('configuration_id')
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
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
    log.debug(__name__ + ':_delete_bucket:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 DELETE operation failed: {0}'.format(err))
    elif subresource:
        log.debug(__name__ + ':_delete_bucket:\n'
                  '\t\tRemoved {0} from bucket {1}'.format(subresource, bucket))
    else:
        log.debug(__name__ + ':_delete_bucket:\n'
                  '\t\tDeleted bucket {0}'.format(bucket))
    return True


def delete_bucket_object(bucket, objectname, subresource='', **kwargs):
    '''
    Deletes an object from a bucket, or a subresource from an object in a bucket.
    Returns: True on success
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETE.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETEtagging.html
    '''
    subresource_data = {'': {'parameters': {'versionid': False}, 'tagging': {}}}
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_delete_bucket_object:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
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
    log.debug(__name__ + ':_delete_bucket:\n' +
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.headers: {}\n'.format(result.headers) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 DELETE operation failed: {0}'.format(err))
    return True


def delete_bucket_multiple_objects(bucket, objects, **kwargs):
    '''
    The Multi-Object Delete operation enables you to delete multiple objects
    from a bucket using a single HTTP request.

    Arguments:
    bucket: The name of the bucket to operate on
    objects: A dict of key-value pairs with object-name:object-version.
             The object-version may be None
    Returns: None if all went well. List of keys with errors for the keys that
             failed to be deleted.
    '''
    params = {'delete':''}
    headers = _check_headers({'x-amz-mfa': False}, **kwargs)
    data = '<Delete><Quiet>true</Quiet>'
    for key, versionid in six.iteritems(objects):
        data += '<Object><Key>{}</Key>'.format(key)
        if versionid is not None:
            data += '<VersionId>{}</VersionId>'.format(versionid)
        data += '</Object>'
    data += '</Delete>'
    headers.update({'Content-MD5': base64.b64encode(hashlib.md5(data).digest())})
    headers.update({'Content-Length': str(len(data))})
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket,
                                                        path='',
                                                        **kwargs)
    headers, requesturl = _generate_headers_request_url(method='POST',
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
    log.debug(__name__ + ':_delete_bucket_multiple_objects:\n' +
              '\t\trequesturl: {}\n'.format(requesturl) +
              '\t\theaders: {}\n'.format(headers) +
              '\t\tdata: {}'.format(data))
    result = _do_request('POST',
                         requesturl,
                         headers=headers,
                         data=data,
                         verify=kwargs['verify_ssl'])
    err = _generic_result_error_check(result)
    log.debug(__name__ + ':_delete_bucket_multiple_objects:\n' +
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 multiple delete operation failed: {}'.format(err))
    return xml.to_dict(ET.fromstring(result.content))['DeleteResult']


def list_buckets(**kwargs):
    '''
    Lists the buckets owned.
    Returns: a dict with the owner 'name' and the 'buckets' list owned.
    Each bucket is represented by a dict containing the 'Name' and the 'CreationDate' keys.
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTServiceGET.html
    '''
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
    log.debug(__name__ + ':_list_buckets:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 list operation failed: {0}'.format(err))
    if result.content:
        log.debug(__name__ + ':_list_buckets:\n'
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


def get_bucket(bucket, subresource='', **kwargs):
    '''
    List the contents of a bucket (up to 1000 objects) or get subresources of a bucket.
    Returns: dict
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/v2-RESTBucketGET.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETaccelerate.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETacl.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETAnalyticsConfig.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETcors.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETlifecycle.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETlocation.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETlogging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETMetricConfiguration.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETnotification.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETVersion.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETpolicy.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETreplication.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTrequestPaymentGET.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETtagging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETversioningStatus.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETwebsite.html
    '''
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
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_get_bucket:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
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
    log.debug(__name__ + ':_get_bucket:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 GET operation failed: {0}'.format(err))
    if result.content:
        ret = xml.to_dict(ET.fromstring(result.content))
    else:
        ret = True
    return ret


def get_bucket_object(bucket, objectname, subresource='', **kwargs):
    '''
    Gets (subresource of) object at path in bucket.
    Returns: request object
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETacl.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtagging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtorrent.html
    '''
    request_kwargs = {}
    log.debug(__name__ + ':_get_bucket_object:\n'
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
    params = _check_subresources(subresource, subresource_data)
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_get_bucket_object:\n'
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
    log.debug(__name__ + ':_get_bucket_object:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.headers: {}'.format(result.headers))
    if result.status_code == 404 and result.headers.get('x-amz-delete-marker', False):
        raise CommandExecutionError('File was deleted')
    if err:
        raise CommandExecutionError('S3 GET operation failed: {}'.format(err))
    return result


def head_bucket(bucket, **kwargs):
    '''
    Checks if a bucket exists and you have permission to access it.
    Returns: True if the bucket exists and there are enough permissions to access it.
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketHEAD.html
    '''
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
    log.debug(__name__ + ':_head_bucket:\n'
              '\t\tS3 Response Status Code: {}'.format(result.status_code))
    if err:
        raise CommandExecutionError('S3 HEAD operation failed: {}'.format(err))
    return True


def put_bucket(bucket, subresource='', **kwargs):
    '''
    Creates a new S3 bucket, or modifies the subresource configuration.
    See also: http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUT.html
    Generates headers as required.
    Returns: dict or boolean depending on whether the PUT-request returns data or not
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUT.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTaccelerate.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTacl.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTAnalyticsConfig.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTcors.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTInventoryConfig.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTnotification.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTpolicy.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTrequestPaymentPUT.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTtagging.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTVersioningStatus.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTwebsite.html
    '''
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
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_put_bucket:\n'
              '\t\tparams: {}'.format(params))
    if subresource == '':
        del params['']
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
    proto, endpoint, uri = _generate_proto_endpoint_uri(bucket=bucket, **kwargs)
    if subresource == 'policy':
        data = kwargs.get('data', None)
    else:
        data = _generate_subresource_data(subresource,
                                          subresource_data.get(subresource, {}).get('body_root', None),
                                          kwargs.get('data', None))
        headers.update({'Content-MD5': base64.b64encode(hashlib.md5(data).digest())})
    log.debug(__name__ + ':_put_bucket:\n'
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
    log.debug(__name__ + ':_put_bucket:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        raise CommandExecutionError('S3 PUT operation failed: {}'.format(err))
    if result.content:
        ret = xml.to_dict(result.content)
    else:
        ret = True
    return ret


def put_bucket_object(bucket, objectname, subresource='', local_file=None, **kwargs):
    '''
    Puts an object in a bucket or puts a configuration in a subresource of an object in a bucket.
    Header values can be passed as kwargs.
    Params can be passed as kwargs.
    Returns: dict or boolean depending on whether the PUT-request returns data or not
    Exceptions: CommandExecutionError
    References:
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectCOPY.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTacl.html
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTtagging.html
    '''
    log.debug(__name__ + ':_put_bucket_object:\n'
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
                                         'x-amz-server-side-encryption-customer-key-MD5': False,
                                         'x-amz-copy-source': False, 'x-amz-metadata-directive': False,
                                         'x-amz-copy-source-if-match': False,
                                         'x-amz-copy-source-if-none-match': False,
                                         'x-amz-copy-source-if-unmodified-since': False,
                                         'x-amz-copy-source-if-modified-since': False,
                                         'x-amz-tagging-directive': False},
                             'parameters': {}},
                        'acl': {'headers': {'x-amz-acl': False, 'x-amz-grant-read': False,
                                            'x-amz-grant-write': False, 'x-amz-grant-read-acp': False,
                                            'x-amz-grant-write-acp': False, 'x-amz-grant-full-control': False},
                                'parameters': {},
                                'body_root': 'AccessControlPolicy'},
                        'tagging': {'headers': {'Content-MD5': False},
                                    # Acutally, Content-MD5 is required, but we're calculating it here.
                                    'parameters': {}, 'body_root': 'Tagging'}}
    headers = _check_headers(subresource_data.get(subresource, {}).get('headers', {}), **kwargs)
    params = _check_subresources(subresource, subresource_data)
    params.update(_check_parameters(subresource_data.get(subresource, {}).get('parameters', {}), **kwargs))
    log.debug(__name__ + ':_put_bucket_object:\n'
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
        log.debug(__name__ + ':_put_bucket_object:\n'
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
    log.debug(__name__ + ':_put_bucket_object:\n'
              '\t\tresult.status_code: {}\n'.format(result.status_code) +
              '\t\tresult.text: {}'.format(result.text))
    if err:
        return err
    if result.content:
        ret = xml.to_dict(result.content)
    else:
        ret = True
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
    log.debug(__name__ + ': _do_request:\n' +
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
        log.debug(__name__ + ':_generic_result_error_check: Response content: {0}'.format(err_text))
        # Try to get err info from response xml
        try:
            err_data = xml.to_dict(ET.fromstring(err_text))
            ret = {key.lower(): value for key, value in six.iteritems(err_data)}
        except (KeyError, ET.ParseError) as err:
            log.debug(__name__ + ':_generic_result_error_check: ' +
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
    log.debug(__name__ + ':_generate_proto_endpoint_uri:\n' +
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
    log.debug(__name__ + ':_generate_proto_endpoint_uri:\n' +
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
        location=region,
        product='s3',
        requesturl=proto + endpoint,
        headers=headers
    )
