# -*- coding: utf-8 -*-
'''
Support for Zabbix
Mostly rewritten for zabbix v3.2 by Herbert Buurman

:configuration: This module is not usable until the zabbix user and zabbix password are specified either in a pillar
    or in the minion's config file. Zabbix url should be also specified.

    For example::

        zabbix:
          user: Admin
          password: mypassword
          url: http://127.0.0.1/zabbix/api_jsonrpc.php

:codeauthor: Jiri Kotlin <jiri.kotlin@ultimum.io>
:codeauthor: Herbert Buurman <herbert.buurman@ogd.nl>
'''
# Import python libs
from __future__ import absolute_import
from __future__ import unicode_literals
import logging
import socket
import json
import copy
import sys
import functools

# Import salt libs
import salt.utils
import salt.exceptions
from salt.ext import six
from salt.ext.six.moves.urllib.error import HTTPError, URLError  # pylint: disable=import-error,no-name-in-module
from salt.ext.six.moves import zip
# from salt.utils.versions import LooseVersion

# Import third party libs
try:
    import zabbix_32_definitions as zabbix
    HAS_ZABBIX = True
except ImportError:
    HAS_ZABBIX = False

log = logging.getLogger(__name__)


def __virtual__():
    if HAS_ZABBIX:
        return 'zabbix'


def __init__(opts):
    # Add _eq, _diff, _valid, _create, _delete, _update functions as partials for _object_eq, _object_diff, ... etc
    # for all CRUD_OBJECTS where these are not already defined
    current_module = sys.modules[__name__]
    gen_func = lambda functype, item, id, **kwargs: \
        getattr(current_module, '_object_{0}'.format(functype))(item,
                                                                zabbix.CRUD_OBJECTS[item]['definition'],
                                                                id,
                                                                **kwargs)
    for functype in ['eq', 'diff', '_valid', 'create', 'delete', 'update', 'present']:
        for itemname in zabbix.CRUD_OBJECTS.keys():
            private = '_' if functype.startswith('_') else ''
            attr = '{0}{1}_{2}'.format(private, itemname, functype[1:] if private else functype)
            if not hasattr(current_module, attr):
                partial = functools.partial(gen_func, functype[1:] if private else functype, itemname)
                setattr(current_module, attr, partial)


def _frontend_url(protocol='http'):
    '''
    Tries to guess the url of zabbix frontend.
    '''
    hostname = socket.gethostname()
    frontend_url = '{}://{}/zabbix/api_jsonrpc.php'.format(protocol, hostname)
    try:
        try:
            response = salt.utils.http.query(frontend_url)
            error = response['error']
        except HTTPError as http_e:
            error = str(http_e)
        if error.find('412: Precondition Failed'):
            return frontend_url
        else:
            raise salt.exceptions.SaltInvocationError(error)
    except (ValueError, KeyError) as ex:
        log.debug(__name__ + ': _frontend_url: An exception was thrown: {0}'.format(ex))
        return False


def _query(method, params, url, auth=None):
    '''
    JSON request to Zabbix API.

    Args:
        method: actual operation to perform via the API
        params: parameters required for specific method
        url: url of zabbix api
        auth: auth token for zabbix api (only for methods with required authentication)

    Returns:
        Response from API with desired data in JSON format.
    '''
    ret = {}
    unauthenticated_methods = ['user.login', 'apiinfo.version']

    header_dict = {'Content-type': 'application/json-rpc'}
    data = {'jsonrpc': '2.0', 'id': 0, 'method': method, 'params': params}

    if method not in unauthenticated_methods:
        data['auth'] = auth

    data = json.dumps(data)
    log.debug(__name__ + ': _query:performing query:\n'
              '\t\turl: {0}\n'.format(url) +
              '\t\tdata: {0}'.format(data))
    try:
        result = salt.utils.http.query(url,
                                       method='POST',
                                       data=data,
                                       header_dict=header_dict,
                                       decode_type='json',
                                       decode=True,
                                       status=True)
        log.debug(__name__ + ': _query:\n'
                  '\t\tZabbix query result: {0}'.format(result))
        if 'error' in result:
            return result
        ret.update({'status': result['status'], 'dict': result['dict']})
    except URLError as ex:
        ret.update({'exception': 'An URLError exception was thrown: {0}'.format(ex)})
    except socket.gaierror as ex:
        ret.update({'exception': 'A socket.gaiaerror exception was thrown: {0}'.format(ex)})
    except HTTPError as ex:
        ret.update({'exception': 'An HTTPException was thrown: {0}'.format(ex)})
    return ret


def _login(**kwargs):
    '''
    Log in to the API and generate the authentication token.

    Args:
        optional kwargs:
                _connection_user: zabbix user (can also be set in opts or pillar, see module's docstring)
                _connection_password: zabbix password (can also be set in opts or pillar, see module's docstring)
                _connection_url: url of zabbix frontend (can also be set in opts or pillar, see module's docstring)

    Returns:
        On success connargs dictionary with auth token and frontend url,
        On failure, returns a dict with error
    '''
    connargs = {}

    def _connarg(name, key=None):
        '''
        Add key to connargs, only if name exists in our kwargs or, as zabbix.<name> in __opts__ or __pillar__

        Evaluate in said order - kwargs, pillar, then opts. To avoid collision with other functions,
        kwargs-based connection arguments are prefixed with '_connection_' (i.e. '_connection_user', etc.).

        Inspired by mysql salt module.
        '''
        prefix = '_connection_'
        # Remove prefix from name if present
        if name.startswith(prefix) and name != prefix:
            name = name[len(prefix):]
        if key is None:
            key = name
        # Get from kwargs
        val = kwargs.get(prefix + name)
        if not val:
            # Get from pillar
            val = __salt__['pillar.get']('zabbix:{}'.format(name))
        if not val:
            # Get from config
            val = __salt__['config.option']('zabbix.{}'.format(name))
        connargs[key] = val

    _connarg('user')
    _connarg('password')
    _connarg('protocol')
    _connarg('url')

    if 'url' not in connargs:
        connargs['url'] = _frontend_url(connargs.get('protocol', 'http'))

    if connargs['user'] and connargs['password'] and connargs['url']:
        params = {'user': connargs['user'], 'password': connargs['password']}
        method = 'user.login'
        zret = _query(method, params, connargs['url'])
        log.debug(__name__ + ': _login:\n\t\tzret: {0}'.format(zret))
        if 'error' in zret:
            raise salt.exceptions.CommandExecutionError('Error connecting to {}: {}'
                                                        ''.format(connarcs['url'], zret['error']))
        auth = zret['dict']['result']
        connargs['auth'] = auth
        connargs.pop('user', None)
        connargs.pop('password', None)
        return connargs
    else:
        raise salt.exceptions.SaltInvocationError('Could not connect to Zabbix')


def _params_filter(function, **kwargs):
    '''
    Filters kwargs based on name of function ('host.get', 'trigger.get', 'hostinterface.create', etc)
    Uses zabbix.FUNCTION_KWARGS to determine which kwargs are returned.
    '''
    keep_keys = []
    if function[-4:] == '.get':
        keep_keys += zabbix.FUNCTION_KWARGS['common.get']
    keep_keys += zabbix.FUNCTION_KWARGS[function]

    filtered_out = [key for key in kwargs if key not in keep_keys]
    log.debug(__name__ + ': _params_filter: Filtered out keys: {0}'.format(filtered_out))
    return {key: kwargs[key] for key in keep_keys if key in kwargs}


def apiinfo_version(**kwargs):
    '''
    Retrieve the version of the Zabbix API.

    Returns:
        On success string with Zabbix API version, False on failure.

    CLI Example:
    .. code-block:: bash

        salt '*' zabbix.apiinfo_version
    '''
    conn_args = _login(**kwargs)

    if conn_args:
        method = 'apiinfo.version'
        params = {}
        ret = _query(method, params, conn_args['url'], conn_args['auth'])
        return ret['result']
    return False


def _generic_response(zret):
    '''
    Sets return-value based on response code from zabbix
    '''
    ret = {'result': False, 'contents': {}}
    if zret['status'] == 200:
        if 'result' in zret['dict']:
            ret['result'] = True
            ret['contents'].update(zret['dict']['result'])
        elif 'error' in zret['dict']:
            ret['result'] = False
            ret['contents'].update(zret['dict']['error'])
        else:
            ret['result'] = False
            ret['contents'].update('Something went wrong. The response from zabbix was: {0}'.format(zret['dict']))
    return ret


def generic_id_list(itemname, **kwargs):
    '''
    Wrapper for calling all .get-functions using the Zabbix API.
    Arguments:
        itemname: name of the item ('host', 'hostinterface', 'item', 'trigger', etc)
    All other kwargs to be used by the zabbix API can be supplied and will be passed along.

    Returns a list of item id's.
    '''
    ret = []
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret = []
    else:
        method = zabbix.CRUD_OBJECTS[itemname].get('read',
                                                   '{}.get'.format(itemname))
        params = _params_filter(method, **kwargs)
        params.update({'output': 'extend'})
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        zabbix_item_idname = zabbix.IDNAMES.get(itemname, [itemname + 'id'])[0]
        if zret['status'] == 200:
            for item in zret['dict']['result']:
                log.debug(__name__ + ':generic_id_list: item: {}'.format(item))
                ret.append(item[zabbix_item_idname])
    return ret


def generic_get_dict(itemname, keyfield, **kwargs):
    '''
    Wrapper for calling all .get-functions using the Zabbix API.
    Arguments:
        itemname: name of the item ('host', 'hostinterface', 'item', 'trigger', etc)
        keyfield: name of the field to be used as key in the returned dict
    All other kwargs to be used by the zabbix API can be supplied and will be passed along.

    Returns a dict with { keyfield: result_from_zabbix }-entries
    '''
    ret = {}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['error'] = conn_args
    else:
        method = zabbix.CRUD_OBJECTS[itemname].get('read',
                                                   '{}.get'.format(itemname))
        params = _params_filter(method, **kwargs)
        params.update({'output': 'extend'})
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        if zret['status'] == 200:
            for item in zret['dict']['result']:
                if item[keyfield] in ret:
                    if not isinstance(ret[item[keyfield]], list):
                        ret[item[keyfield]] = [ret[item[keyfield]]]
                    ret[item[keyfield]].append(item)
                else:
                    ret.update({item[keyfield]: item})
    return ret


def generic_get_list(itemname, **kwargs):
    '''
    Wrapper for calling all .get-functions using the Zabbix API.
    Arguments:
        itemname: name of the item ('host', 'hostinterface', 'item', 'trigger', etc)
    All other args required by the zabbix API can be supplied and will be passed along

    returns a list with result_from_zabbix-entries
    '''
    ret = []
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        raise salt.exceptions.SaltInvocationError(conn_args)
    else:
        method = zabbix.CRUD_OBJECTS[itemname].get('read',
                                                   '{}.get'.format(itemname))
        params = _params_filter(method, **kwargs)
        params.update({'output': 'extend'})
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        if zret['status'] == 200:
            ret = zret['dict']['result']
    return ret


def get_all_templates_dict(ids, **kwargs):
    '''
    Utility function to retrieve the specified templates and all recursive parent templates in one dict.
    Returns a dict:
        <templateid>: { template }
    Returns an empty dict on failure or if no ids were found.
    '''
    if not isinstance(ids, list):
        ids = [ids]
    templates = generic_get_dict(
            'template',
            'templateid',
            selectParentTemplates=['templateid'],
            selectHttpTests=['httptestid'],
            selectItems=['itemid'],
            selectTriggers=['triggerid'],
            selectGraphs=['graphid'],
            selectApplications=['applicationid'],
            selectScreens=['screenid'],
            templateids=ids
    )
    if not templates:
        return {}
    for templateid in templates:
        if 'parentTemplates' in templates[templateid]:
            templates.update(
                    get_all_templates_dict(
                            [aap['templateid'] for aap in templates[templateid]['parentTemplates']]),
                    **kwargs)
    return templates


def _type_value_check(itemname, required, type_req, default, restrict_values, arglist):
    '''
    Performs a presence-check (if itemname is present in arglist or required)
    Performs a type-check
    Performs a value-check (if item value is in restrict_values list) if restrict_values is supplied.
    Returns True if all tests pass, raises exception otherwise
    '''
    # log.debug(__name__ + ': _type_value_check: Entry:\n'
    #           '\t\titemname: {}\n'.format(itemname) +
    #           '\t\trequired: {}\n'.format(required) +
    #           '\t\ttype_req: {}\n'.format(type_req) +
    #           '\t\tdefault: {}\n'.format(default) +
    #           '\t\trestrict_values: {}\n'.format(restrict_values) +
    #           '\t\targlist: {}'.format(arglist))
    if itemname not in arglist:
        if required:
            raise KeyError('{} is required but missing'.format(itemname))
        else:
            item = default
    else:
        item = arglist[itemname]
    if item is not None:
        if type_req == str:
            type_req = six.string_types
        if not isinstance(item, type_req):
            raise TypeError('{} is of the wrong type '.format(itemname) +
                            '({} expected, got {})'.format(type_req, type(item)))
        if restrict_values is not None and item not in restrict_values:
            raise ValueError('{} is has an invalid value {}'.format(itemname, item))
    return True


def _object_create(object_name, object_def, object_id, **kwargs):
    '''
    Wrapper for generic object creation.
    '''
    ret = {'result': False, 'contents': {}}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['error'] = conn_args
    else:
        method = zabbix.CRUD_OBJECTS[object_name].get('create',
                                                      '{}.create'.format(object_name))
        params = _params_filter(method, **kwargs)
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        if zret['status'] == 200:
            if 'result' in zret['dict']:
                ret['result'] = True
                ret['contents'].update(zret['dict']['result'])
            elif 'error' in zret['dict']:
                ret['result'] = False
                ret['contents'].update(zret['dict']['error'])
            else:
                ret['result'] = False
                ret['contents'].update('Something went wrong. The response from zabbix was: {0}'.format(zret['dict']))
    return ret


def _object_delete(object_name, object_def, object_ids, **kwargs):
    '''
    Wrapper for generic object deletion.
    '''
    ret = {'result': False, 'contents': {}}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['error'] = conn_args
    else:
        method = zabbix.CRUD_OBJECTS[object_name].get('delete',
                                                      '{}.delete'.format(object_name))
        ret = _generic_response(_query(method, object_ids, conn_args['url'], conn_args['auth']))
    return ret


def _object_update(object_name, object_def, object_id, **kwargs):
    '''
    Wrapper for generic object updating.
    '''
    ret = {'result': False, 'contents': {}}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['error'] = conn_args
    else:
        method = zabbix.CRUD_OBJECTS[object_name].get('update',
                                                      '{}.update'.format(object_name))
        idname = zabbix.IDNAMES.get(object_name, [object_name + 'id'])[0]
        params = _params_filter(method, **kwargs)
        params.update({idname: object_id})
        ret = _generic_response(_query(method, params, conn_args['url'], conn_args['auth']))
    return ret


def _object_eq(object_name, object_def, object_id, **kwargs):
    '''
    Wrapper for generic object comparison.
    Compares configuration of object with ID=id to the parameters specified in **kwargs.
    Returns True if equal, False otherwise.

    See https://www.zabbix.com/documentation/3.2/manual/api/reference/<object_name>/object for object specs.
    '''
    diff, current_object = _object_diff(object_name, object_def, object_id, **kwargs)
    return len(diff['old']) + len(diff['new']) == 0


def _object_valid(object_name, object_def, object_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid object_def, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/<object_type>/object
    '''
    ret = True
    error = None
    log.debug(__name__ + ': _object_valid:\n\t\tobject_name: {0}\n\t\tkwargs: {1}'.format(object_name, kwargs))
    for key in object_def.keys():
        itemproperty = object_def[key]
        log.debug(__name__ + ': _object_valid: key: {}, type: {}, spec: {}'
                  ''.format(key, type(kwargs.get(key, None)), itemproperty))
        try:
            _type_value_check(key,
                              itemproperty.get('required', False),
                              itemproperty.get('type', str),
                              itemproperty.get('default', None),
                              itemproperty.get('restrict_values', None),
                              kwargs)
        except (KeyError, TypeError, ValueError) as ex:
            return False, '{}'.format(ex)
        log.debug(__name__ + ': _object_valid: type-value-check OK')
        if itemproperty.get('type', None) == dict and key in kwargs:
            log.debug(__name__ + ': _object_valid: examining subdict {}'.format(key))
            ret, error = _object_valid('{}.{}'.format(object_name, key),
                                       object_def[key]['contents'],
                                       object_id,
                                       **kwargs[key])
        elif itemproperty.get('type', None) == list:
            log.debug(__name__ + ': _object_valid: examining sublist {}'.format(key))
            for subitem in kwargs.get(key, []):
                ret, error = _object_valid('{}.{}'.format(object_name, key),
                                           object_def[key]['contents'],
                                           object_id,
                                           **subitem)
                if not ret:
                    break
        if not ret:
            break
    log.debug(__name__ + ': _object_valid: ret: {}'.format(ret))
    return ret, error


def _local_object_diff(object_name, object_def, current_object, **kwargs):
    '''
    Wrapper for generic object comparison between current_object and new_object
    Compares configuration of current_object to the parameters specified in new_object.
    Returns dict with diff in the style: { 'old': { key: value }, 'new': { key: value } }
    '''
    log.debug(__name__ + ': _local_object_diff {}'.format(object_name))
    ret = {'old': {}, 'new': {}}
    for attribute in object_def:
        log.debug(__name__ + ': _local_object_diff({0}): checking attribute {1}'.format(object_name, attribute))
        if attribute in kwargs:
            log.debug(__name__ + ': _local_object_diff: attribute is present in kwargs')
            if object_def[attribute]['type'] in [int, str]:
                if current_object.get(attribute) is None or \
                        object_def[attribute]['type'](current_object.get(attribute)) != kwargs.get(attribute):
                    log.debug(__name__ + ': _local_object_diff: but not equal (given: {0}, current: {1})'.format(
                              kwargs.get(attribute),
                              current_object.get(attribute)))
                    ret['old'].update({attribute: current_object.get(attribute)})
                    ret['new'].update({attribute: object_def[attribute]['type'](kwargs.get(attribute))})
                else:
                    log.debug(__name__ + ': _local_object_diff: and equal')
            elif object_def[attribute]['type'] == list:
                log.debug(__name__ + ': _local_object_diff: Comparing list-subattribute {}'.format(attribute))
                for current_item, new_item in zip(current_object.get(attribute, []),
                                                  kwargs.get(attribute, [])):
                    ret2 = _local_object_diff('{}.{}'.format(object_name, attribute),
                                              object_def[attribute]['contents'],
                                              current_item,
                                              **new_item)
                    if ret2['old']:
                        ret = salt.utils.append_dict_key_value(ret, 'old:{}'.format(attribute), ret2['old'])
                    if ret2['new']:
                        ret = salt.utils.append_dict_key_value(ret, 'new:{}'.format(attribute), ret2['new'])
            elif object_def[attribute]['type'] == dict:
                log.debug(__name__ + ': _local_object_diff: Comparing dict-subattribute {}'.format(attribute))
                ret2 = _local_object_diff('{}.{}'.format(object_name, attribute),
                                          object_def[attribute]['contents'],
                                          current_object.get(attribute, {}),
                                          **kwargs.get(attribute, {}))
                if ret2['old']:
                    ret['old'].update({attribute: ret2['old']})
                if ret2['new']:
                    ret['new'].update({attribute: ret2['new']})
            else:
                raise NotImplementedError('Comparison of type {} is not implemented '
                                          'yet.'.format(object_def[attribute]['type']))
        else:
            log.debug(__name__ + ': _local_object_diff: attribute is not present in kwargs')
            default = object_def[attribute].get('default', None)
            if default in current_object:
                default = current_object[default]
            if default is not None and current_object.get(attribute) != str(default):
                log.debug(__name__ + ':_local_object_diff: default {} does not '
                          'match current value {}'.format(str(default), current_object.get(attribute)))
                ret['old'].update({attribute: current_object.get(attribute)})
                ret['new'].update({attribute: str(default)})
    log.debug(__name__ + ': _local_object_diff:\n\t\tret: {0}'.format(ret))
    return ret


def _object_diff(object_name, object_def, object_id, **kwargs):
    '''
    Wrapper for generic object comparison between object in zabbix and **kwargs.
    Compares configuration of object with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: { 'old': { key: value }, 'new': { key: value } }

    See https://www.zabbix.com/documentation/3.2/manual/api/reference/<object_name>/object for object specs.
    '''
    log.debug(__name__ + ': _object_diff {}, {}'.format(object_name, object_id))
    available_functions = globals().copy()
    available_functions.update(locals())
    f_chk = '_{}_valid'.format(object_name)
    if f_chk not in available_functions:
        raise NotImplementedError('No validation-function has been defined for {}'.format(object_name))
    valid, error = available_functions[f_chk](None, **kwargs)
    if not valid:
        raise ValueError('The specified arguments do not quality as a valid: '
                         '{}: {}'.format(object_name, error))
    idnames = zabbix.IDNAMES.get(object_name, [object_name + 'id'])
    current_object_kwargs = copy.deepcopy(kwargs)
    current_object_kwargs.update({'{}s'.format(idnames[0]): [object_id]})
    if 'filter' in current_object_kwargs:
        del current_object_kwargs['filter']
    current_object = generic_get_dict(object_name, idnames[0],
                                      **current_object_kwargs)
    if not current_object:
        current_object = {}
    else:
        log.warn(__name__ + ': _object_diff: multiple objects {} found by name. '
                 'Comparing with the first.'.format(object_name))
        current_object = current_object[str(object_id)]
    log.trace(__name__ + ': _object_diff:\n' +
              '\t\tCurrent object: {}\n'.format(current_object) +
              '\t\tNew object: {}'.format(kwargs))
    return _local_object_diff(object_name, object_def, current_object, **kwargs), current_object


def _object_present(object_name, object_def, name, **kwargs):
    '''
    Ensures an object with variable itemtype (item=object_name) is present, and configured as specified.
    required_kwargs is a list of attribute names that are required to be present in kwargs.

    Extra option:
    - target_required (boolean): Indicates whether a single valid target is required.
    '''
    ret = {'name': '{}_present'.format(object_name), 'changes': {}, 'result': False, 'comment': ''}
    current_module = sys.modules[__name__]
    log.debug(__name__ + ': generic_present: kwargs: {}'.format(kwargs))
    action = None
    query_filter = {}
    current_object_def = zabbix.CRUD_OBJECTS[object_name]
    if 'name' in current_object_def:
        query_filter = {current_object_def['name']: kwargs.get(current_object_def['name'], name)}
    expand_select = {k: 'extend' for k in current_object_def['select'] if k not in kwargs}
    if kwargs.get('target_required', False):
        # Resolve target_template or target_host
        target = get_target(**kwargs)
        if not target['result']:
            return target
        ret.update({'comment': target['comment']})
        # We can safely add all possible targeting keywords, as all invalid
        # keywords get filtered out before the final call to Zabbix.
        kwargs.update({'hostid': target['hostid']})
        if 'target_template' in kwargs:
            kwargs.update({'templateids': target['hostid']})
        if 'target_host' in kwargs:
            kwargs.update({'hostids': target['hostid']})
    log.debug(__name__ + ': generic_present: kwargs: {}'.format(kwargs))
    for arg in [k for k, v in six.iteritems(object_def)
                if v.get('required', False) and current_object_def.get('name') != k]:
        if arg not in kwargs:
            raise salt.exceptions.SaltInvocationError('A required argument {} was not passed in kwargs'.format(arg))
    if 'name' in current_object_def:
        kwargs[current_object_def['name']] = name
    # Check if item already present (by name)
    list_kwargs = kwargs.copy()
    # Delete 'filter' param if already present in kwargs. This interferes with the next call.
    if 'filter' in list_kwargs.keys():
        del list_kwargs['filter']
    # If a target is specified, add the hostid to the filter of current items.
    if kwargs.get('target_required', False):
        query_filter.update({'hostid': kwargs['hostid']})
    generic_ids = __salt__['zabbix-30.generic_id_list'](itemname=object_name,
                                                        filter=query_filter,
                                                        **list_kwargs)
    if generic_ids:
        diff_kwargs = expand_select.copy()
        diff_kwargs.update(kwargs)
        generic_diff, current_object = __salt__['zabbix-30.{}_diff'.format(object_name)](generic_ids[0],
                                                                                         **diff_kwargs)
        if len(generic_diff['old']) + len(generic_diff['new']) == 0:
            ret['result'] = True
            ret['comment'] = '{} "{}" already exists '.format(object_name, name) + \
                             'as configured and has ID {}'.format(generic_ids)
        else:
            action = 'update'
            # If a parameter is not present in kwargs, but its default value
            # differs from the parameter in current_object, it won't get updated
            # because it's not in kwargs. Fix this now.
            for key, value in six.iteritems(generic_diff.get('new', {})):
                if key not in kwargs:
                    kwargs[key] = value
    else:
        valid, error = getattr(current_module, '_{}_valid'.format(object_name))(None, **kwargs)
        if not valid:
            ret['comment'] = 'The supplied action is not valid: {}'.format(error)
            ret['result'] = False
            return ret
        action = 'create'

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Test mode, nothing changed.'
    elif action is not None:
        if action == 'create':
            zret = __salt__['zabbix-30.{}_create'.format(object_name)](None, **kwargs)
        elif action == 'update':
            zret = __salt__['zabbix-30.{}_update'.format(object_name)](generic_ids[0], **kwargs)
        else:
            raise ValueError('action must be one of "create" or "update", not "{0}"'.format(action))
        log.debug(__name__ + ': generic_present: zret: {}'.format(zret))
        if '{}ids'.format(object_name) in zret['contents']:
            ret['result'] = True
            if generic_ids:
                ret['changes'] = generic_diff
            else:
                ret['changes'] = {'old': '{} not present'.format(object_name),
                                  'new': '{} "{}" with ID "{}"'
                                  ''.format(object_name,
                                            name,
                                            zret['contents']['{}ids'.format(object_name)][0])
                                  }
        elif zret['result'] is False:
            ret['comment'] = zret['contents']
        ret.update(zret)
    return ret


def _action_valid(action_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid action, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/action/object

    Extends upon _object_valid by:
    - Validating operations and recovery_operations if supplied.
    - If an opcommand is specified as an operation, makes sure either opcommand_grp
      or opcommand_hst are supplied.
    - If an opmessage is specified as an operation, the specified mediatypeid is validated.
    - If a filter is specified in an operation with evaltype 3, makes sure a
      formula is supplied.
    '''
    log.debug(__name__ + ': _action_valid:\n'
              '\t\tkwargs: {}'.format(kwargs))
    ret, error = _object_valid('action', zabbix.ACTION_OBJECT, action_id, **kwargs)
    # "operations", "recovery_operations" and "filter" are not present in the
    # Action Object specification, so we validate these here if present.
    for operation_type in ['operations', 'recovery_operations']:
        for operation in kwargs.get(operation_type, []):
            ret, error = _object_valid('action_operation',
                                       zabbix.ACTION_OPERATION_OBJECT,
                                       None,
                                       **operation)
            # log.debug(__name__ + ': _action_valid: _object_valid(action_operation): {}'.format(ret))
            if ret and operation['operationtype'] == 1 and 'opcommand' in operation and not (
                    'opcommand_grp' in operation or 'opcommand_hst' in operation):
                ret = False
                error = 'opcommand specified, but neither opcommand_grp ' + \
                        'nor opcommand_hst have been specified'
            if ret and 'opmessage' in operation:
                opmessage = operation['opmessage']
                # Validate the supplied mediatypeid
                if ret and 'mediatypeid' in opmessage:
                    mediatypeids = generic_get_dict('mediatype',
                                                    'mediatypeid',
                                                    mediatypeids=[opmessage['mediatypeid']])
                    # Mediatypeid 0 == 'All'
                    if not mediatypeids and opmessage['mediatypeid'] != '0':
                        ret = False
                        error = 'mediatypeid {} does not exist.'.format(opmessage['mediatypeid'])
            if ret and 'filter' in operation:
                if operation['filter']['evaltype'] == 3 and 'formula' not in operation['filter']:
                    ret = False
                    error = 'formula is required for filters of type 3 (custom expression)'
            if not ret:
                break
        if not ret:
            break
    return ret, error


def action_diff(action_id, **kwargs):
    '''
    Compares configuration of action with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: { 'old': { key: value }, 'new': { key: value } }

    Extends upon _object_diff by:
    - Diffing action's operations and recovery operationc and filters
    '''
    log.debug(__name__ + ': action_diff: kwargs: {}'.format(kwargs))
    ret, current_object = _object_diff('action', zabbix.ACTION_OBJECT, action_id, **kwargs)
    # "operations", "recovery_operations" and "filter" are not present in the
    # Action Object specification, so we compare these here if present.
    for current_operation, new_operation in zip(current_object.get('operations', []),
                                                kwargs.get('operations', [])):
        ret2 = _local_object_diff('action_operation',
                                  zabbix.ACTION_OPERATION_OBJECT,
                                  current_operation,
                                  **new_operation)
        ret['old'].update(ret2['old'])
        ret['new'].update(ret2['new'])
    for current_operation, new_operation in zip(current_object.get('recoveryOperations', []),
                                                kwargs.get('recovery_operations', [])):
        ret2 = _local_object_diff('action_recoveryoperation',
                                  zabbix.ACTION_OPERATION_OBJECT,
                                  current_operation,
                                  **new_operation)
        ret['old'].update(ret2['old'])
        ret['new'].update(ret2['new'])
    if 'filter' in kwargs.keys():
        # Swap eval_formula returned from zabbix to formula for comparison with user-supplied formula.
        if 'filter' in current_object:
            current_object['filter']['formula'] = current_object['filter']['eval_formula']
        ret2 = _local_object_diff('action_filter',
                                  zabbix.ACTION_FILTER_OBJECT,
                                  current_object.get('filter', {}),
                                  **kwargs.get('filter', {}))
        ret['old'].update(ret2['old'])
        ret['new'].update(ret2['new'])
    return ret, current_object


def action_present(name, **kwargs):
    '''
    Extends _object_present with extra lookups for various IDs that can be specified
    in the action configuration.

    When supplying operations, the following attributes can be supplied with names instead of ids:
    - opcommand_grp[].hostgroup: Name will be looked up and id put in groupid
    - opcommand_hst[].host: Name will be looked up and id put in hostid
    - opmessage_grp[].usergroup: Name will be looked up and id put in usrgrpid
    - opmessage_usr[].user: Name will be looked up as user.alias and id put in userid
    - opmessage.mediatype: Name will be looked up and id put in mediatypeid
    '''
    zabbix_hostgroups = {}
    zabbix_hosts = {}
    zabbix_usergroups = {}
    zabbix_users = {}
    zabbix_mediatypes = {}
    for operation_type in ['operations', 'recovery_operations']:
        for operation in kwargs.get(operation_type, []):
            if 'opmessage' in operation:
                opmessage = operation['opmessage']
                if 'mediatype' in opmessage and 'mediatypeid' not in opmessage:
                    if opmessage['mediatype'].lower() == 'all':
                        opmessage.update({'mediatypeid': '0'})
                    else:
                        opmessage.update({'mediatypeid': _object_id_lookup('mediatype',
                                                                           zabbix_mediatypes,
                                                                           'description',
                                                                           opmessage['mediatype'])})
                    del opmessage['mediatype']
            if 'opcommand_grp' in operation:
                for opcommand_grp in operation['opcommand_grp']:
                    if 'hostgroup' in opcommand_grp:
                        opcommand_grp['groupid'] = _object_id_lookup('hostgroup',
                                                                     zabbix_hostgroups,
                                                                     'name',
                                                                     opcommand_grp['hostgroup'])
                        del opcommand_grp['hostgroup']
            if 'opcommand_hst' in operation:
                for opcommand_hst in operation['opcommand_hst']:
                    if 'host' in opcommand_hst:
                        opcommand_hst['hostid'] = _object_id_lookup('host',
                                                                    zabbix_hosts,
                                                                    'name',
                                                                    opcommand_hst['host'])
                        del opcommand_hst['host']
            if 'opmessage_grp' in operation:
                for opmessage_grp in operation['opmessage_grp']:
                    if 'usergroup' in opmessage_grp:
                        opmessage_grp['usrgrpid'] = _object_id_lookup('usergroup',
                                                                      zabbix_usergroups,
                                                                      'name',
                                                                      opmessage_grp['usergroup'])
                        del opmessage_grp['usergroup']
            if 'opmessage_usr' in operation:
                for opmessage_usr in operation['opmessage_usr']:
                    if 'user' in opmessage_usr:
                        opmessage_usr['userid'] = _object_id_lookup('user',
                                                                    zabbix_users,
                                                                    'alias',
                                                                    opmessage_usr['user'])
                        del opmessage_usr['user']
    return _object_present('action', zabbix.CRUD_OBJECTS['action']['definition'], name, **kwargs)


def _httptest_valid(httptest_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid httptest, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/httptest/object

    Extends upon _object_valid by:
    - validating steps, if supplied
    '''
    log.debug(__name__ + ':_httptest_valid:\n'
              '\t\tkwargs: {}'.format(kwargs))
    ret, error = _object_valid('httptest', zabbix.WEB_SCENARIO_OBJECT, httptest_id, **kwargs)
    # "steps" is not present in the Web Scenario Object specification, so we
    # validate them here if present.
    for step in kwargs.get('steps', []):
        ret, error = _object_valid('httptest_step',
                                   zabbix.SCENARIO_STEP_OBJECT,
                                   None,
                                   **step)
        if not ret:
            break
    return ret, error


def httptest_diff(httptest_id, **kwargs):
    '''
    Compares configuration of httptest with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: { 'old': { key: value }, 'new': { key: value } }

    Extends upon _object_diff by:
    - Diffing httptest's steps
    '''
    log.debug(__name__ + ':httptest_diff: kwargs: {}'.format(kwargs))
    ret, current_object = _object_diff('httptest', zabbix.WEB_SCENARIO_OBJECT, httptest_id, **kwargs)
    # "steps" is not present in the Httptest Object specification, so we compare
    # them here if present.
    for current_operation, new_operation in zip(current_object.get('steps', []),
                                                kwargs.get('steps', [])):
        ret2 = _local_object_diff('httptest_step',
                                  zabbix.SCENARIO_STEP_OBJECT,
                                  current_operation,
                                  **new_operation)
        ret['old'].update(ret2['old'])
        ret['new'].update(ret2['new'])
    return ret, current_object


def item_diff(item_id, **kwargs):
    '''
    Compares configuration of item with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: {'old': {key: value}, 'new': {key: value}}

    Extends upon _object_diff by:
    - Diffing item's applications
    '''
    log.debug(__name__ + ': item_diff: kwargs: {}'.format(kwargs))
    ret, current_object = _object_diff('item', zabbix.ITEM_OBJECT, item_id, **kwargs)
    # "applications" is not present in the Item Object specification, so we
    # compare it here if present.
    current_applications = [app['applicationid'] for app in current_object.get('applications', [])]
    for new_application in kwargs.get('applications', []):
        if new_application not in current_applications:
            if 'applications' not in ret['new']:
                ret['new']['applications'] = []
            ret['new']['applications'].append(new_application)
    for current_application in current_applications:
        if current_application not in kwargs.get('applications', []):
            if 'applications' not in ret['old']:
                ret['old']['applications'] = []
            ret['old']['applications'].append(current_application)
    return ret, current_object


def _trigger_valid(trigger_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid trigger, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/trigger/object

    Extends upon _object_valid by making sure a recovery_expression is supplied
    when recovery_mode 1 is specified.
    '''
    ret, error = _object_valid('trigger', zabbix.TRIGGER_OBJECT, trigger_id, **kwargs)
    if ret and 'recovery_mode' in kwargs and kwargs['recovery_mode'] == 1 and 'recovery_expression' not in kwargs:
        ret = False
        error = 'recovery_mode 1 requires a recovery_expression.'
    return ret, error


def trigger_diff(trigger_id, **kwargs):
    '''
    Compares configuration of trigger with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: {'old': {key: value}, 'new': {key: value}}

    Extends upon _object_diff by:
    - Checking whether the targeted host-or-template in 'hostid' is present in
      the 'hosts'-attribute of the current object.
    '''
    log.debug(__name__ + ': trigger_diff: kwargs: {}'.format(kwargs))
    ret, current_object = _object_diff('trigger', zabbix.TRIGGER_OBJECT, trigger_id, **kwargs)
    # Check if the targeted host-or-template is present in kwargs
    if 'hostid' in kwargs:
        for applied_host in current_object.get('hosts', []):
            # If the same targeted host-or-template is present in applied_host
            if applied_host.get('hostid', '') == kwargs['hostid']:
                # Disregard the difference in hostid in the result of _object_diff
                del ret['old']['hostid']
                del ret['new']['hostid']
    return ret, current_object


def _hostinterface_valid(hostinterface_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid host interface, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/hostinterface/object

    Extends upon _object_valid by making sure the 'ip' and 'dns'-values are
    filled properly with respect to the 'useip' value.
    '''
    ret, error = _object_valid('hostinterface', zabbix.HOST_INTERFACE_OBJECT, hostinterface_id, **kwargs)
    if ret and ((kwargs['useip'] == 0 and 'dns' not in kwargs) or (kwargs['useip'] == 1 and 'ip' not in kwargs)):
        ret = False
        error = 'Either use "useip" or "dns" but not neither or both.'
    return ret, error


def _host_valid(host_id, **kwargs):
    '''
    Checks if the given arguments constitute a valid host, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/host/object
    '''
    return _object_valid('host', zabbix.HOST_OBJECT, host_id, **kwargs)


def host_eq(hostid, **kwargs):
    '''
    Compares configuration of host with ID=id with parameters specified in **kwargs.
    Returns True if equal, False otherwise

    First checks if the given kwargs constitute a valid host, then compares the current_host to
    the kwargs given, and finally compares memberships with:
    - hostgroups
    - interfaces
    - parenttemplates
    '''
    ret = _object_eq('host', zabbix.HOST_OBJECT, hostid, **kwargs)
    frop = {'selectGroups': ['groupid'],
            'selectInterfaces': ['interfaceid'],
            'selectParentTemplates': ['templateid'],
            'hostids': hostid}
    current_host = generic_get_dict('host', 'hostid', **frop)[str(hostid)]
    if ret and 'groups' in current_host:
        log.debug(__name__ + ': host_eq: comparing groups')
        groups = generic_get_dict('hostgroup',
                                  'groupid',
                                  groupids=[group['groupid'] for group in current_host['groups']])
        kwargs_groupids = [str(group['groupid']) for group in kwargs['groups']]
        if len(kwargs_groupids) != len(groups.keys()):
            ret = False
        else:
            mismatching_group_ids = [groupid for groupid in groups if groupid not in kwargs_groupids]
            if mismatching_group_ids:
                ret = False
    if ret and 'interfaces' in current_host:
        log.debug(__name__ + ': host_eq: comparing interfaces')
        interfaces = generic_get_dict('hostinterface',
                                      'interfaceid',
                                      interfaceids=[interface['interfaceid']
                                                    for interface in current_host['interfaces']])
        if not isinstance(kwargs['interfaces'], list):
            target_interfaces = [kwargs['interfaces']]
        if len(interfaces.keys()) != len(target_interfaces):
            log.debug(__name__ + ': host_eq: Interface length differs:\n'
                      '\t\tcurrent: {0}\n\t\tkwargs: {1}'.format(interfaces, target_interfaces))
            ret = False
        else:
            for interfaceid in [interface['interfaceid'] for interface in current_host['interfaces']]:
                kwarg_interface = target_interfaces[0]
                ret &= hostinterface_eq(interfaceid, hostid=str(current_host['hostid']), **kwarg_interface)
    if ret and 'parentTemplates' in current_host:
        log.debug(__name__ + ': host_eq: comparing templates')
        kwargs_templateids = [str(template['templateid']) for template in kwargs['templates']]
        if len(kwargs_templateids) != len(current_host['parentTemplates']):
            log.debug(__name__ + ': host_eq: Template length differs:\n'
                      '\t\tcurrent: {0}\n\t\tkwargs: {1}'.format(current_host['parentTemplates'], kwargs_templateids))
            ret = False
        else:
            mismatching_template_ids = [template['templateid'] for template in current_host['parentTemplates']
                                        if template['templateid'] not in kwargs_templateids]
            if mismatching_template_ids:
                log.debug(__name__ + ': host_eq: Templates mismatch:\n\t\t{0}'.format(mismatching_template_ids))
                ret = False
    log.debug(__name__ + ': host_eq: EXIT: ret: {0}'.format(ret))
    return ret


def host_update(hostid, **kwargs):
    '''
    Update existing hosts.

    Args:
        hostid: ID of the host to update

                visible_name: string with visible name of the host, use 'visible_name' instead of 'name' parameter
                              to not mess with value supplied from Salt sls file.

                all standard host and host.update properties: keyword argument names differ depending on
                your zabbix version, see:

                https://www.zabbix.com/documentation/2.4/manual/api/reference/host/update
                https://www.zabbix.com/documentation/2.4/manual/api/reference/host/object#host

    Returns:
        {'result': bool, 'changes': dingen}

    CLI Example:
    .. code-block:: bash

        salt '*' zabbix.host_update 10084 name='Zabbix server2'
    '''
    ret = {'result': False, 'comment': '', 'changes': {}}
    log.debug(__name__ + ': host_update: kwargs: {0}'.format(kwargs))
    conn_args = _login(**kwargs)
    if conn_args:
        current_host = generic_get_dict('host',
                                        'hostid',
                                        **{'selectInterfaces': 'extend', 'hostids': hostid}
                                        )[str(hostid)]
        if 'interfaces' in kwargs:
            # Calling host.update with a different interface may cause the update to be rejected
            # if the interface is linked to sensor-items. We therefore update the (main) interface first.
            if isinstance(kwargs['interfaces'], list):
                new_interface = [interface for interface in kwargs['interfaces']
                                 if str(interface.get('main')) == '1'][0]
            else:
                new_interface = kwargs['interfaces']
            new_interface.update({'hostid': str(current_host['hostid'])})

            current_interface = [interface for interface in current_host['interfaces']
                                 if str(interface.get('main')) == '1'][0]

            interface_diff, current_interface = hostinterface_diff(current_interface['interfaceid'], **new_interface)
            if len(interface_diff['old']) + len(interface_diff['new']) > 0:
                interface_update_result = hostinterface_update(current_interface['interfaceid'],
                                                               **new_interface)
                if interface_update_result['result']:
                    ret['changes'].update({'interface': interface_diff})
            del kwargs['interfaces']
        method = 'host.update'
        params = _params_filter(method, **kwargs)
        params.update({"hostid": hostid})
        return _generic_response(_query(method, params, conn_args['url'], conn_args['auth']))
    else:
        ret['comment'] = 'Could not connect succesfully: {0}'.format(conn_args)
    return ret


def configuration_export(options=None, **kwargs):
    '''
    Wrapper around zabbix API configuration.export call.
    Returns a dict:
        result: True or False, the success of the API call
        contents: The data returned in the response
    '''
    ret = {'result': False, 'contents': None}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['error'] = conn_args
    else:
        method = 'configuration.export'
        if options is None:
            options = {}
        params = {"format": "json", "options": options}
        return _generic_response(_query(method, params, conn_args['url'], conn_args['auth']))
    return ret


def configuration_import(source, rules=None, **kwargs):
    '''
    Wrapper around zabbix API configuration.import call.
    '''
    conn_args = _login(**kwargs)
    if conn_args:
        method = 'configuration.import'
        if rules is None:
            rules = {}
        params = {"format": "json", "rules": rules, "source": source}
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        return zret['result']
    return False


def get_target(**kwargs):
    '''
    Gets the ID of the target specified in kwargs. This has to be either 'target_template' or 'target_host'.
    Returns a dict:
        result: Result of the operation, True or False
        comment: Comment on what happened
        hostid: The ID retrieved (or None if error or not found)
    '''
    ret = {'result': False, 'comment': '', 'hostid': None}
    targeted = len([x for x in ['hostid', 'target_template', 'target_host'] if x in kwargs])
    if targeted > 1:
        ret['comment'] = 'You must use exactly one of "hostid", "target_template" or "target_host"'
        return ret
    if 'hostid' in kwargs:
        ret['hostid'] = kwargs['hostid']
    if 'target_template' in kwargs:
        resultid = generic_id_list(itemname='template', filter={'host': kwargs['target_template']}, **kwargs)
        if not resultid:
            ret['comment'] = 'Template "{0}" does not exist.'.format(kwargs['target_template'])
        else:
            ret['comment'] = 'targeted template "{0}"'.format(kwargs['target_template'])
            ret['hostid'] = resultid[0]
            ret['result'] = True
    if 'target_host' in kwargs:
        resultid = generic_id_list(itemname='host', filter={'host': kwargs['target_host']}, **kwargs)
        if not resultid:
            ret['comment'] = 'Host "{0}" does not exist.'.format(kwargs['target_host'])
        else:
            ret['comment'] = 'targeted host "{0}"'.format(kwargs['target_host'])
            ret['hostid'] = resultid[0]
            ret['result'] = True
    return ret


def do_query(method, **kwargs):
    '''
    Allows for issuing raw queries to the Zabbix API.

    kwargs should contain a key params pointing to either a dict or a list.

    Returns a dict { result: bool, contents: result_dict }
    where result_dict is the dict with the result received from Zabbix, in case things went ok.
    If there are errors, these are returned in contents instead.
    '''
    ret = {'result': False, 'contents': {}}
    conn_args = _login(**kwargs)
    if 'error' in conn_args:
        ret['contents'].update(conn_args)
    else:
        if isinstance(kwargs['params'], list):
            params = kwargs['params']
        else:
            params = {"format": "json"}
            params.update(kwargs['params'])
            params = _params_filter(method, **kwargs['params'])
        zret = _query(method, params, conn_args['url'], conn_args['auth'])
        if 'error' in zret['dict'].keys():
            ret.update({'contents': zret['dict']['error']})
        else:
            ret['result'] = True
            ret.update({'contents': zret['dict']['result']})
    return ret


def _object_id_lookup(object_name, cache, field_name, field_value):
    '''
    Helper function to perform name-to-id lookups in Zabbix.
    Uses cache-variable to store list of 'object_name'-items for subsequent lookups.

    Parameters:
        object_name: The type of object to do the lookup for
        cache: Dict with results of earlier calls
               If empty dict is supplied, it will be filled with data retrieved from zabbix.
        field_name: The field-name to look for needles
        field_value: The value to find the ID for.
    '''
    if cache is None:
        cache = {}
    cache.update(generic_get_dict(object_name, field_name))
    idfield = zabbix.IDNAMES.get(object_name, object_name + 'id')
    log.debug(__name__ + ':_object_id_lookup:\n'
              '\t\tidfield: {}'.format(idfield))
    return cache[field_value][idfield]


def generic_absent(names, item, **kwargs):
    '''
    Ensures an object with variable itemtype (item) is absent.

    Extra option:
    - target_required (boolean): Indicates if a single valid target is required (or not).
    '''
    ret = {'name': names, 'changes': {}, 'result': False, 'comment': ''}
    query_filter = {}
    if 'name' in zabbix.CRUD_OBJECTS[item]:
        query_filter = {zabbix.CRUD_OBJECTS[item]['name']: names}
    if kwargs.get('target_required', False):
        target = __salt__['zabbix-30.get_target'](**kwargs)
        if not target['result']:
            return ret
        kwargs.update({'hostid': target['hostid']})
    if 'hostid' in kwargs:
        query_filter.update({'hostid': kwargs['hostid']})
    objectids = __salt__['zabbix-30.generic_id_list'](itemname=item,
                                                      filter=query_filter,
                                                      **kwargs)
    if not objectids:
        ret['comment'] = '{} "{}" already absent'.format(item, names)
        ret['result'] = True
        return ret
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Test mode, {} with id(s) {} would have been deleted'.format(item, objectids)
    else:
        zret = __salt__['zabbix-30.{}_delete'.format(item)](objectids, **kwargs)
        if '{0}ids'.format(item) in zret['contents']:
            ret['result'] = True
            ret['changes'] = {'old': '{} with names {} and id(s) {} exists'.format(item, names, objectids),
                              'new': '{}IDs {} removed'.format(item, zret['contents']['{}ids'.format(item)])}
    return ret


def _usermedia_valid(mediaid, **kwargs):
    '''
    Checks if the given arguments constitute a valid usermedia, according to:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/usermedia/object

    This object differs from almost all other objects in that it does not have
    usermedia.create, usermedia.update, usermedia.delete functions.
    usermedia are created using user.addmedia, retrieved using usermedia.get,
    updated using user.updatemedia and deleted using user.deletemedia.
    '''
    return _object_valid('usermedia', zabbix.MEDIA_OBJECT, mediaid, **kwargs)


def usermedia_diff(mediaid, **kwargs):
    '''
    Compares configuration of usermedia with ID=id to the parameters specified in **kwargs.
    Returns dict with diff in the style: {'old': {key: value}, 'new': {key: value}}

    Wrapper for _object_diff.
    '''
    return _object_diff('usermedia', zabbix.MEDIA_OBJECT, mediaid, **kwargs)


def usermedia_present(name, **kwargs):
    '''
    Ensures a usermedia is present.
    Adds a usermedia unless one with the exact same configuration is already
    present for the specified user(s).

    required_kwargs is a list of attribute names that are required to be
    present in kwargs.

    This differs from _object_present in that the required datastruct for
    usermedia should be present in the 'medias' argument.
    Also, a 'users' argument should be present.
    '''
    ret = {'name': 'usermedia_present', 'changes': {}, 'result': False, 'comment': ''}
    log.debug(__name__ + ':usermedia_present: kwargs: {}'.format(kwargs))

    add_media_to_users = [entry['userid'] for entry in kwargs['users']]
    current_medias = generic_get_dict('usermedia', 'mediaid')
    for current_media in current_medias.values():
        # usermedia_eq also does usermedia_valid on its kwargs.
        if usermedia_eq(current_media['mediaid'], **kwargs['medias']):
            if current_media['userid'] in add_media_to_users:
                add_media_to_users.remove(current_media['userid'])

    if not add_media_to_users:
        # No users to add media to remain
        ret['result'] = True
        ret['comment'] = 'Specified media is already present for all specified users.'
        return ret

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Test mode, nothing changed.'
    else:
        zret = __salt__['zabbix-30.usermedia_create'](None, **kwargs)
        log.debug(__name__ + ': usermedia_present: zret: {}'.format(zret))
        if 'mediaids' in zret['contents']:
            ret['result'] = True
            ret['changes'] = {'old': 'usermedia not present',
                              'new': 'usermedia "{}" with ID "{}"'
                              ''.format(name, zret['contents']['mediaids'][0])}
        elif zret['result'] is False:
            ret['comment'] = zret['contents']
        ret.update(zret)
    return ret
