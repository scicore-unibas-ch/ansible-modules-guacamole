#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token, guacamole_get_connections
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: guacamole_user_group

short_description: Administer guacamole user-groups using the rest API.

version_added: "2.9"

description:
    - "Manage guacamole user-groups and assign connection permissions."

options:
    base_url:
        description:
            - Url to access the guacamole API
        required: true
        aliases: ['url']
        type: str

    auth_username:
        description:
            - Guacamole admin user to login to the API
        required: true
        type: str

    auth_password:
        description:
            - Guacamole admin user password to login to the API
        required: true
        type: str

    validate_certs:
        description:
            - Validate ssl certs?
        default: true
        type: bool

    permissions:
        description:
            - A dictionary that maps user-group names to connections.
        type: dict
        elements: str

    state:
        description:
            - Create, delete or sync the user-group.
            - `sync` will make guacamole match the permissions dict, so it will add and remove.
        default: 'present'
        type: str
        choices:
            - present
            - absent
            - sync

author:
    - Pablo Escobar Lopez (@pescobar)
    - Garrett Bischof (@gwbischof)
    - Robert Schaffer (@RobertSchaffer1)
'''

EXAMPLES = '''

- name: Create a new user-group "users1" with permissions for connections: "c1' and "c2"
  scicore.guacamole.guacamole_users_group:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    permissions: "{{ {'users1' : ['c1', 'c2']} }}"
    state: present

- name: Remove user-group "users1".
  scicore.guacamole.guacamole_users_group:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    permissions: "{{ {'users1' : []} }}"
    state: absent

- name: Remove connection "c1" from user-group "users1".
  scicore.guacamole.guacamole_users_group:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    permissions: "{{ {'users1' : ['c1']} }}"
    state: absent

- name: Sync user-groups and permissions. This will create groups and permissions defined
    in the permissions dict, and delete anything not defined in the permissions.
  scicore.guacamole.guacamole_users_group:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    permissions: "{{ {'users1' : ['c1', 'c2']} }}"
    state: sync
'''

RETURN = '''
message:
    description: Some extra info about what the module did
    type: str
    returned: always
'''

URL_LIST_GROUPS = "{url}/api/session/data/{datasource}/userGroups?token={token}"
URL_ADD_GROUP = URL_LIST_GROUPS
URL_DELETE_GROUP = "{url}/api/session/data/{datasource}/userGroups/{group_name}?token={token}"
URL_GET_GROUP_PERMISSIONS = "{url}/api/session/data/{datasource}/userGroups/{group_name}/permissions?token={token}"
URL_UPDATE_CONNECTIONS_IN_GROUP = URL_GET_GROUP_PERMISSIONS


def guacamole_get_users_groups(base_url, validate_certs, datasource, auth_token):
    """
    Returns a dict of dicts.
    Each dict provides the name and state (enabled/disabled) for each group of users
    """

    url_list_users_groups = URL_LIST_GROUPS.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        users_groups = json.load(open_url(url_list_users_groups, method='GET',
                                          validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain users groups from %s: %s'
            % (url_list_users_groups, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain users groups from %s: %s'
                             % (url_list_users_groups, str(e)))

    return users_groups


def guacamole_add_group(base_url, validate_certs, datasource, auth_token, group_name):
    """
    Add a group of users
    """

    url_add_group = URL_ADD_GROUP.format(
        url=base_url, datasource=datasource, token=auth_token)

    payload = {
        "identifier": group_name,
        "attributes": {
            "disabled": ""
        }
    }

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_add_group, method='POST', validate_certs=validate_certs, headers=headers,
                 data=json.dumps(payload))
    except Exception as e:
        # if the group exists we get a http code 400
        if e.code == 400:
            pass
            #  raise GuacamoleError('Group %s already exists.' % group_name)
        else:
            raise GuacamoleError('Could not add a users group. Error msg: %s' % str(e))


def guacamole_delete_group(base_url, validate_certs, datasource, auth_token, group_name):
    """
    Delete a group of users
    """

    url_delete_group = URL_DELETE_GROUP.format(
        url=base_url, datasource=datasource, token=auth_token, group_name=group_name)

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_delete_group, method='DELETE', validate_certs=validate_certs, headers=headers)
    except Exception as e:
        raise GuacamoleError(f'Could not delete user group {group_name}. Error msg: {e}')


def guacamole_get_users_group_permissions(base_url, validate_certs, datasource, auth_token, group_name):
    """
    Returns a dict of dicts.
    Each dict provides the details for one of the users groups defined in guacamole
    """

    url_get_users_group_permissions = URL_GET_GROUP_PERMISSIONS.format(
        url=base_url, datasource=datasource, token=auth_token, group_name=group_name)

    try:
        group_permissions = json.load(open_url(url_get_users_group_permissions, method='GET',
                                               validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain group permissions from %s: %s'
            % (url_get_users_group_permissions, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain group permissions from %s: %s'
                             % (url_get_users_group_permissions, str(e)))

    return group_permissions


def guacamole_update_connections_in_group(base_url, validate_certs, datasource, auth_token, group_name, connection_id, action):
    """
    Add or remove a connection to a group.
    Action must be "add" or "remove"
    """

    if action not in ['add', 'remove']:
        raise GuacamoleError("action must be 'add' or 'remove'")

    url_update_connections_in_group = URL_UPDATE_CONNECTIONS_IN_GROUP.format(
        url=base_url, datasource=datasource, token=auth_token, group_name=group_name)

    payload = [{
        "op": action,
        "path": '/connectionPermissions/%s' % connection_id,
        "value": 'READ'
    }]

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_connections_in_group, method='PATCH', validate_certs=validate_certs, headers=headers,
                 data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update connections for group %s in url %s. Error msg: %s'
                             % (group_name, url_update_connections_in_group, str(e)))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True),
        permissions=dict(type='dict', default={}),
        state=dict(type='str', choices=['absent', 'present', 'sync'], default='present')
    )

    result = dict(changed=False, msg='', users_group_info={})

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Obtain access token, initialize API
    try:
        guacamole_token = guacamole_get_token(
            base_url=module.params.get('base_url'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            validate_certs=module.params.get('validate_certs'),
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # Get the list of existing user-groups.
    try:
        groups_before = guacamole_get_users_groups(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    permissions = module.params.get('permissions')

    # Get the list of the existing connections.
    try:
        guacamole_existing_connections = guacamole_get_connections(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            group='ROOT',
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # Add user-groups and assign permisions for connections to the user-groups.
    if module.params.get('state') in {'present', 'sync'}:
        for group_name, connections in permissions.items():

            # Add the user-group if it does not exist.
            if group_name not in groups_before:
                try:
                    guacamole_add_group(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        group_name=group_name,
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))

                result['changed'] = True

            # Get the list of connections for the user-group.
            try:
                existing_group_connection_ids = set(guacamole_get_users_group_permissions(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    group_name=group_name
                )['connectionPermissions'].keys())
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            group_connection_ids = {connection['identifier'] for connection
                                    in guacamole_existing_connections if connection['name']
                                    in set(connections)} - existing_group_connection_ids

            # Add connection permissions to the user-group.
            for connection_id in group_connection_ids:
                try:
                    guacamole_update_connections_in_group(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        group_name=group_name,
                        connection_id=connection_id,
                        action='add',
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))

    # Remove user-groups and connection permisions.
    if module.params.get('state') in {'absent', 'sync'}:

        # Determine which user-groups should be deleted.
        if module.params.get('state') == 'absent':
            remove_groups = {group for group, connections in permissions.items()
                             if not connections}
        else:
            remove_groups = set(groups_before) - set(permissions.keys())

        # Remove user-groups.
        for remove_group in remove_groups:
            try:
                guacamole_delete_group(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    group_name=remove_group,
                )
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            result['changed'] = True

        # Remove connection permissions from user-groups.
        for group_name, connections in permissions.items():

            connection_ids = {connection['identifier'] for connection
                              in guacamole_existing_connections if
                              connection['name'] in set(connections)}

            # Determine which connections should be removed from group permissions.
            if module.params.get('state') == 'absent':
                remove_connection_ids = connection_ids
            else:
                remove_connection_ids = set(guacamole_get_users_group_permissions(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    group_name=group_name
                )['connectionPermissions'].keys()) - connection_ids

            # Remove connection permissions.
            for remove_connection_id in remove_connection_ids:
                try:
                    guacamole_update_connections_in_group(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        group_name=group_name,
                        connection_id=remove_connection_id,
                        action='remove',
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
