# -*- coding: utf-8 -*-
'''
Management of Zabbix hosts.

:codeauthor: Herbert Buurman <herbert.buurman@ogd.nl>
'''
from __future__ import absolute_import
import logging
log = logging.getLogger(__name__)

__virtualname__ = 'zabbix'


def __virtual__():
    '''
    Only make these states available if Zabbix module is available.
    '''
    requirements = ['zabbix.get_target',
                    'zabbix.application_present',
                    'zabbix.action_present',
                    'zabbix.host_present',
                    'zabbix.httptest_present',
                    'zabbix.item_present',
                    'zabbix.mediatype_present',
                    'zabbix.template_present',
                    'zabbix.trigger_present',
                    'zabbix.generic_absent',
                    'zabbix.generic_get_dict']
    for req in requirements:
        if req not in __salt__:
            return False, 'Requisite {} not found'.format(req)
    return __virtualname__


def application_present(name, **kwargs):
    '''
    Checks if an application is present and configured with the same parameters as given.
    Creates the application if it is not present, updates the application if it is different.

    Required parameters:
    - name: Name of the application

    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to add this application to
    - target_template: Name of the template to add this application to
    - target_host: Name of the host to add this application to
    '''
    new_kwargs = {'target_required': True}
    new_kwargs.update(kwargs)
    return __salt__['zabbix.application_present'](name, **new_kwargs)


def application_absent(name, names=None, **kwargs):
    '''
    Ensures an application is absent from a given template or host.
    Can also be called with an array of names to remove multiple applications.
    When using 'names', the value of 'name' gets discarded.

    Required parameters (pick one):
    - name: Name of the application to be made absent.
    - names: List of names of the applications to be made absent.

    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to remove this application from
    - target_template: Name of the template to remove this application from
    - target_host: Name of the host to remove this application from
    '''
    new_kwargs = {'target_required': True}
    new_kwargs.update(kwargs)
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'application', **new_kwargs)


def action_present(name, esc_period, eventsource, **kwargs):
    '''
    Checks if an action is present and configured with the same parameters as given.
    Creates the action if it is not present, updates the action if it is different.

    Required parameters:
    - name: Name of the action
    - esc_period: Default operation step duration. Must be greater than 60 (seconds).
    - eventsource: Type of events that the action will handle.

    Optional parameters include all writable properties in action.create or
    action.update. See:
    https://www.zabbix.com/documentation/3.2/manual/api/reference/action/create
    https://www.zabbix.com/documentation/3.2/manual/api/reference/action/update
    '''
    new_kwargs = {'esc_period': esc_period, 'eventsource': eventsource}
    new_kwargs.update(kwargs)
    return __salt__['zabbix.action_present'](name, **new_kwargs)


def action_absent(name, names=None, **kwargs):
    '''
    Ensures an action is absent.
    Can also be called with an array of names to remove multiple actions.
    When using 'names', the value of 'name' gets discarded.

    Required parameters (pick one):
    - name: Name of the application to be made absent.
    - names: List of names of the applications to be made absent.
    '''
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'action', **kwargs)


def host_present(name, groups, interfaces, **kwargs):
    '''
    Checks if a host is present and configured with the same parameters as given.
    Creates the host if it is not present, updates the host if it is different.

    Required parameters:
    - name: Name of the host to create or update
    - groups: Name or list of names of the hostgroup(s) to link the host to.
    - interfaces: Interface dict or list of dicts with interface specifications.
    Optional parameters:
    - templates: Name or list of names of the template(s) to link the host to.

    Other optional paramaters include everything Zabbix allows you to use in
    either host.create or host.update.
    See https://www.zabbix.com/documentation/3.2/manual/api/reference/host/create
    and https://www.zabbix.com/documentation/3.2/manual/api/reference/host/update
    '''
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not isinstance(groups, list):
        groups = [groups]
    if not isinstance(interfaces, list):
        interfaces = [interfaces]
    zabbix_groups = __salt__['zabbix.generic_get_dict']('hostgroup', 'name')
    zabbix_templates = __salt__['zabbix.generic_get_dict']('template', 'host')
    # Fix for the issue where 'ip' and 'dns' both need to be present in interface,
    # even though only one gets used.
    for interface in interfaces:
        for item in ['ip', 'dns']:
            if item not in interface:
                interface[item] = ''
    new_kwargs = {'groups': [], 'interfaces': interfaces}
    # Translate group names to groupIDs
    for group in groups:
        if group not in zabbix_groups:
            ret['comment'] = 'Group {} does not exist'.format(group)
            return ret
        new_kwargs['groups'].append({'groupid': zabbix_groups[group]['groupid']})
    if 'templates' in kwargs.keys():
        if not isinstance(kwargs['templates'], list):
            kwargs['templates'] = [kwargs['templates']]
        new_kwargs['templates'] = []
        # Translate template names to templateIDs
        for template in kwargs['templates']:
            if template not in zabbix_templates:
                ret['comment'] = 'Template {} does not exist'.format(template)
                return ret
            new_kwargs['templates'].append({'templateid': zabbix_templates[template]['templateid']})
        del kwargs['templates']
    new_kwargs.update(kwargs)
    return __salt__['zabbix.host_present'](name, **new_kwargs)


def host_absent(name, names=None, **kwargs):
    '''
    Ensures a host (by name) is absent.
    Can also be called with an array of names to remove multiple hosts.
    When using 'names', the value of 'name' gets discarded.

    If you want to remove a host from a template, update the host to have no
    links to templates instead.
    '''
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'host', **kwargs)


def httptest_present(name, steps, **kwargs):
    '''
    Checks if an httptest (webtest) is present, if not, creates it.

    Required parameters:
    - name: Name of webtest.
    - steps: List of steps of the webtest, for a specification of a step, see
      https://www.zabbix.com/documentation/3.2/manual/api/reference/httptest/object#scenario_step

    Extra parameters:
    - hostid: ID of host (or template) to add this httptest to
    - target_template: Name of the template to add this httptest to
    - target_host: Name of the host to add this httptest to

    Optional parameters:
    - application: Name of the application to link this httptest to. Will be looked
                   up and passed on as applicationid. Application will need to
                   be present at the same host or template you want this httptest
                   to be linked to.

    Other optional paramaters include everything Zabbix allows you to use in
    either httptest.create or httptest.update.
    See https://www.zabbix.com/documentation/3.2/manual/api/reference/httptest/create
    and https://www.zabbix.com/documentation/3.2/manual/api/reference/httptest/update
    '''
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    new_kwargs = {'steps': steps, 'target_required': True}
    new_kwargs.update(kwargs)
    target = __salt__['zabbix.get_target'](**kwargs)
    if not target['result']:
        return target
    if 'application' in kwargs:
        # Get the applicationID with the same target as this httptest
        del new_kwargs['application']
        application_lookup = __salt__['zabbix.generic_get_dict'](itemname='application',
                                                                 keyfield='name',
                                                                 **kwargs).get(kwargs['application'], [])
        if isinstance(application_lookup, dict):
            application_lookup = [application_lookup]
        application_ids = [app['applicationid']
                           for app in application_lookup
                           if app['hostid'] == target['hostid']]
        if application_ids:
            new_kwargs['applicationid'] = application_ids[0]
        else:
            ret['comment'] = 'The linked application {} does not exist'.format(kwargs['application'])
            return ret
    return __salt__['zabbix.httptest_present'](name, **new_kwargs)


def httptest_absent(name, names=None, **kwargs):
    '''
    Ensures an httptest is absent.

    Required parameters (pick one):
    - name: Name of the httptest to be made absent.
    - names: List of names of the httptest to be made absent.

    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to remove this httptest from.
    - target_template: Name of the template to remove this httptest from.
    - target_host: Name of the host to remove this httptest from.
    '''
    new_kwargs = {'target_required': True}
    new_kwargs.update(kwargs)
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'httptest', **new_kwargs)


def item_present(name, delay, key_, item_type, value_type, **kwargs):
    '''
    Checks if an item is present, if not, creates it.

    For the full list of properties, see https://www.zabbix.com/documentation/3.2/manual/api/reference/item/object).
    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to add this item to.
    - target_template: Name of the template to add this item to.
    - target_host: Name of the host to add this item to.

    Optional parameters:
    - applications: List of strings with application names to link this item to.
                    Names will be looked up for you. Application will need to be
                    present at the same host or template you want this item to be linked to.
    '''
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    new_kwargs = {'delay': delay,
                  'key_': key_,
                  'type': item_type,
                  'value_type': value_type,
                  'target_required': True}
    new_kwargs.update(kwargs.copy())
    # The default of 365 does not apply to items of type 'log' (which do not have a trend)
    if value_type == 2 and 'trends' not in kwargs:
        new_kwargs.update({'trends': 0})
    target = __salt__['zabbix.get_target'](**kwargs)
    if not target['result']:
        ret['comment'] = 'The target was not supplied or could not be found'
        return ret
    if 'target_host' in kwargs:
        # Zabbix now also wants an interfaceid.
        # Fetch the main interfaceid unless one is specified in kwargs
        if 'interfaceid' not in kwargs:
            interfaceids = __salt__['zabbix.generic_id_list']('hostinterface', hostids=target['hostid'])
            if interfaceids:
                new_kwargs['interfaceid'] = interfaceids[0]
            else:
                ret['comment'] = 'No interfaces found for target: {}'.format(target)
                return ret
    if 'applications' in kwargs:
        wanted_applications = kwargs['applications']
        if not isinstance(wanted_applications, list):
            wanted_applications = [wanted_applications]
        # Get the applicationID with the same target as this item
        application_lookup = __salt__['zabbix.generic_get_dict'](itemname='application',
                                                                 keyfield='name',
                                                                 **kwargs)
        application_ids = []
        for application in wanted_applications:
            if application not in application_lookup:
                ret['comment'] = 'Application with name "{}" not found.'.format(application) + \
                                 ' Note that this is case-sensitive.'
                return ret
            current_applications = application_lookup.get(application)
            if isinstance(current_applications, dict):
                current_applications = [current_applications]
            application_ids.extend([app['applicationid']
                                    for app in current_applications
                                    if app['hostid'] == target['hostid']])
        if application_ids:
            new_kwargs['applications'] = application_ids
        else:
            ret['comment'] = 'No linked applications by name(s) {} exist.'.format(kwargs['applications'])
            return ret
    return __salt__['zabbix.item_present'](name, **new_kwargs)


def item_absent(name, names=None, **kwargs):
    '''
    Ensures an item is absent.
    Can also be called with an array of names to remove multiple media types.
    However, the items must all have the same target (host or template).
    When using 'names', the value of 'name' gets discarded.

    Required parameters (pick one):
    - name: Name of the item to be made absent.
    - names: List of names of the item to be made absent.

    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to remove this item from.
    - target_template: Name of the template to remove this item from.
    - target_host: Name of the host to remove this item from.
    '''
    new_kwargs = {'target_required': True}
    new_kwargs.update(kwargs)
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'item', **new_kwargs)


def mediatype_present(name, mediatype_type, **kwargs):
    '''
    Checks if a mediatype is present and configured with the same parameters as given.
    Creates the mediatype if it is not present, updates the mediatype if it is different.
    '''
    new_kwargs = {'description': name, 'type': mediatype_type}
    new_kwargs.update(kwargs)
    return __salt__['zabbix.mediatype_present'](name, **new_kwargs)


def mediatype_absent(name, names=None, **kwargs):
    '''
    Ensures a media type (by name) is absent.
    Can also be called with an array of names to remove multiple media types.
    When using 'names', the value of 'name' gets discarded.

    Required parameters (pick one):
    - name: Name of the item to be made absent.
    - names: List of names of the item to be made absent.
    '''
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'mediatype', **kwargs)


def template_present(name, groups='Templates', description='', visible_name=None, **kwargs):
    '''
    Checks if a template is present, if not, creates it.

    Required parameters:
    - name: Technical name of the template

    Optional parameters:
    - groups: Name or list of names of hostgroups to add this template to. (Default: Templates)
    - description: Decription of the template
    - visible_name: Visible name of the host (Default: host property value)
    '''
    new_kwargs = {'description': description, 'visible_name': visible_name}
    new_kwargs.update(kwargs)
    if not isinstance(groups, list):
        groups = [groups]
    if groups:
        # Get the applicationID with the same target as this item
        hostgroup_lookup = __salt__['zabbix.generic_get_dict'](itemname='hostgroup',
                                                                  keyfield='name',
                                                                  **kwargs)
        hostgroup_ids = []
        for hostgroup in groups:
            current_hostgroups = hostgroup_lookup.get(hostgroup)
            if isinstance(current_hostgroups, dict):
                current_hostgroups = [current_hostgroups]
            hostgroup_ids.extend([hg['groupid']
                                  for hg in current_hostgroups])
        if hostgroup_ids:
            new_kwargs['groups'] = {'groupid': groupid for groupid in hostgroup_ids}
        else:
            return {'name': name,
                    'changes': {},
                    'result': False,
                    'comment': 'No hostgroup name(s) {} exist.'.format(groups)}
    return __salt__['zabbix.template_present'](name, **new_kwargs)


def template_absent(name, names=None, **kwargs):
    '''
    Ensures one or more templates are absent.

    Required parameters (pick one):
    - name: Name of the template to be made absent.
    - names: List of names of the templates to be made absent.
    '''
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'template', **kwargs)


def trigger_present(name, expression, **kwargs):
    '''
    Checks if a trigger is present, if not, creates it.

    For the full list of properties, see https://www.zabbix.com/documentation/3.2/manual/api/reference/trigger/object).
    Required parameters:
    - name: Name of the trigger
    - expression: Expanded trigger expression.

    Extra parameters (exactly one required):
    - hostid: ID of host (or template) to add this httptest to
    - target_template: Name of the template to add this httptest to
    - target_host: Name of the host to add this httptest to
    '''
    new_kwargs = {'expression': expression, 'expandDescription': None, 'target_required': True}
    new_kwargs.update(kwargs)
    return __salt__['zabbix.trigger_present'](name, **new_kwargs)


def trigger_absent(name, names=None, **kwargs):
    '''
    Ensures a trigger is absent.
    Can also be called with an array of names to remove multiple triggers.
    When using 'names', the value of 'name' gets discarded.

    Extra parameters:
    - hostid: ID of host (or template) to add this httptest to
    - target_template: Name of the template to add this httptest to
    - target_host: Name of the host to add this httptest to
    '''
    new_kwargs = {'target_required': True}
    new_kwargs.update(kwargs)
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'trigger', **new_kwargs)


def screen_present(name, **kwargs):
    '''
    Checks if a screen is present as configured, if not, creates or updates it.

    Required parameters:
    - name: Name of the screen

    For the full list of properties, see https://www.zabbix.com/documentation/3.2/manual/api/reference/screen/object
    '''
    return __salt__['zabbix.screen_present'](name, **kwargs)


def screen_absent(name, names=None, **kwargs):
    '''
    Ensures a screen is absent.
    Can also be called with an array of names to remove multiple screens.
    When using 'names', the value of 'name' gets discarded.
    '''
    if names is None:
        names = [name]
    return __salt__['zabbix.generic_absent'](names, 'screen', **kwargs)


def usermedia_present(name, users, mediatype, sendto, **kwargs):
    '''
    Ensures a usermedia is present and linked to the specified user.
    Multiple usernames may be specified in a list.

    Parameters:
    - name: Not used
    - users: Username or list of usernames
    - mediatype: Description of mediatype
    - sendto: Target of the media (email address, channel, Phone no.)

    Extra parameters:
    - active: enabled (0) or disabled (1). Default: 0
    - period: Range-specification of day-of-week + hour-of-day this media is
              allowed to be used. Default: '1-7,00:00-24:00'
    - severity: Trigger severities to send notifications about. This is a binary
                representation of the list:
                - Not classified
                - Information
                - Warning
                - Average
                - High
                - Disaster
                Default: 63 (111111) (all severities)
    '''
    ret = {'name': name, 'changes': {}, 'result': False, 'comment': ''}
    if not isinstance(users, list):
        users = [users]
    new_kwargs = {'medias': {'sendto': sendto,
                             'active': kwargs.get('active', 0),
                             'period': kwargs.get('period', '1-7,00:00-24:00'),
                             'severity': kwargs.get('severity', 63)},
                  'users': []}
    # Translate usernames to userids
    zabbix_users = __salt__['zabbix.generic_get_dict']('user', 'alias')
    for user in users:
        if user not in zabbix_users:
            ret['comment'] = 'User {} does not exist'.format(user)
            return ret
        new_kwargs['users'].append({'userid': zabbix_users[user]['userid']})
    # Translate mediatype to mediatypeid
    zabbix_mediatypes = __salt__['zabbix.generic_get_dict']('mediatype', 'description')
    if mediatype.lower() == 'all':
        new_kwargs['medias']['mediatypeid'] = 0
    elif mediatype not in zabbix_mediatypes:
        ret['comment'] = 'Mediatype {} does not exist'.format(mediatype)
        return ret
    new_kwargs['medias']['mediatypeid'] = int(zabbix_mediatypes[mediatype]['mediatypeid'])
    return __salt__['zabbix.usermedia_present'](name, **new_kwargs)


def usermedia_absent(name, mediaids, **kwargs):
    '''
    Ensures a screen is absent.

    Parameters:
    - name: not used
    - mediaids: List of usermedia-ids to delete.
    '''
    new_kwargs = kwargs.copy()
    # mediaids will eventually be passed on to usermedia.get and act as a filter
    new_kwargs['mediaids'] = mediaids
    return __salt__['zabbix.generic_absent'](name, 'usermedia', **new_kwargs)
