#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token, guacamole_get_connections, guacamole_get_connections_group_id
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: guacamole_connections_group

short_description: Administer guacamole connections groups using the rest API

version_added: "2.9"

description:
    - "Add or remove guacamole connections groups."

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

    group_name:
        description:
            - Group name to create
        required: true
        type: str

    parent_group:
        description:
            - Parent group in case this is a sub-group
        default: 'ROOT'
        aliases: ['parentIdentifier']
        type: str

    group_type:
        description:
            - Choose the group type
        default: 'ORGANIZATIONAL'
        type: str
        choices:
            - "ORGANIZATIONAL"
            - "BALANCING"

    max_connections:
        description:
            - Max connections in this group
        type: int

    max_connections_per_user:
        description:
            - Max connections per user in this group
        type: int

    enable_session_affinity:
        description:
            - Enable session affinity for this group
        type: bool

    state:
        description:
            - Create or delete the connections group?
        default: 'present'
        type: str
        choices:
            - present
            - absent

author:
    - Pablo Escobar Lopez (@pescobar)
'''

EXAMPLES = '''

- name: Create a new group "group_3"
  scicore.guacamole.guacamole_connections_group:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    group_name: group_3

'''

RETURN = '''
connections_group_info:
    description: Information about the created or updated connections group
    type: dict
    returned: always
message:
    description: Some extra info about what the module did
    type: str
    returned: always
'''

URL_LIST_CONNECTIONS_GROUPS = "{url}/api/session/data/{datasource}/connectionGroups/?token={token}"
URL_ADD_CONNECTIONS_GROUP = URL_LIST_CONNECTIONS_GROUPS
URL_UPDATE_CONNECTIONS_GROUP = "{url}/api/session/data/{datasource}/connectionGroups/{conn_numeric_id}?token={token}"
URL_DELETE_CONNECTIONS_GROUP = URL_UPDATE_CONNECTIONS_GROUP


def guacamole_get_connections_groups(base_url, validate_certs, datasource, auth_token):
    """
    Returns a dict of dicts.
    Each dict provides the details for one of the connections groups defined in guacamole
    """

    url_list_connections_groups = URL_LIST_CONNECTIONS_GROUPS.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        connections_groups = json.load(open_url(url_list_connections_groups, method='GET',
                                                validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain connections groups from %s: %s'
            % (url_list_connections_groups, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain connections groups from %s: %s'
                             % (url_connection_details, str(e)))

    return connections_groups


def guacamole_populate_connections_group_payload(module_params):
    """
    Populate the json that we send to the guaccamole API to create new connection group
    """

    payload = {
        "parentIdentifier": module_params['parent_group'],
        "name": module_params['group_name'],
        "type": module_params['group_type'],
        "attributes": {
            "max-connections": module_params['max_connections'],
            "max-connections-per-user": module_params['max_connections_per_user'],
            "enable-session-affinity": module_params['enable_session_affinity'],
        }
    }

    return payload


def guacamole_add_connections_group(base_url, validate_certs, datasource, auth_token, payload):
    """
    Add a new connections group to the guacamole server.
    """

    url_add_connections_group = URL_ADD_CONNECTIONS_GROUP.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_add_connections_group, method='POST', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not add a new connections group in %s: %s'
                             % (url_add_connection, str(e)))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True),
        group_name=dict(type='str', required=True),
        parent_group=dict(type='str', default='ROOT'),
        group_type=dict(type='str', choices=['ORGANIZATIONAL', 'BALANCING'], default='ORGANIZATIONAL'),
        max_connections=dict(type='int'),
        max_connections_per_user=dict(type='int'),
        enable_session_affinity=dict(type='bool'),
        state=dict(type='str', choices=['absent', 'present'], default='present')
    )

    result = dict(changed=False, msg='', diff={}, connections_group_info={})

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

    # get the group numeric ID if parent_group is not ROOT
    if module.params.get('parent_group') != "ROOT":
        try:
            module.params['parent_group'] = guacamole_get_connections_group_id(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                group=module.params.get('parent_group'),
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

    # Get existing guacamole connections groups before doing anything else
    try:
        guacamole_connections_groups_before = guacamole_get_connections_groups(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))


    payload = guacamole_populate_connections_group_payload(module.params)

    guacamole_add_connections_group(
        base_url=module.params.get('base_url'),
        validate_certs=module.params.get('validate_certs'),
        datasource=guacamole_token['dataSource'],
        auth_token=guacamole_token['authToken'],
        payload=payload
    )

    # # First check if the connection already exists
    # # If the connection exists we get the connection_id
    # guacamole_connection_exists = False
    # for connection in guacamole_connections_before:
    #     if 'name' in connection:
    #         if connection['name'] == module.params.get('connection_name'):
    #             guacamole_connection_exists = True
    #             connection_id = connection['identifier']
    #             break

    # # module arg state=present so we have to create a new connecion
    # # or update a connection if it already exists
    # if module.params.get('state') == 'present':

    #     # populate the payload(json) with the connection info that we
    #     # will send to the API
    #     payload = guacamole_populate_connection_payload(module.params)

    #     # the connection already exists so we update it
    #     if guacamole_connection_exists:

    #         try:
    #             # query what's the current config for this connection so
    #             # we can check later if it has changed
    #             connection_config_before_update = guacamole_get_connection_details(
    #                 base_url=module.params.get('base_url'),
    #                 validate_certs=module.params.get('validate_certs'),
    #                 datasource=guacamole_token['dataSource'],
    #                 auth_token=guacamole_token['authToken'],
    #                 connection_id=connection_id,
    #             )
    #         except GuacamoleError as e:
    #             module.fail_json(msg=str(e))

    #         try:
    #             # apply the config upddate to the connection
    #             guacamole_update_connection(
    #                 base_url=module.params.get('base_url'),
    #                 validate_certs=module.params.get('validate_certs'),
    #                 datasource=guacamole_token['dataSource'],
    #                 auth_token=guacamole_token['authToken'],
    #                 connection_id=connection_id,
    #                 payload=payload
    #             )
    #         except GuacamoleError as e:
    #             module.fail_json(msg=str(e))

    #         try:
    #             # query what's the config for this connection again to
    #             # verify if it has changed
    #             connection_config_after_update = guacamole_get_connection_details(
    #                 base_url=module.params.get('base_url'),
    #                 validate_certs=module.params.get('validate_certs'),
    #                 datasource=guacamole_token['dataSource'],
    #                 auth_token=guacamole_token['authToken'],
    #                 connection_id=connection_id,
    #             )
    #         except GuacamoleError as e:
    #             module.fail_json(msg=str(e))

    #         if connection_config_before_update != connection_config_after_update:
    #             # if the connection config has changed we report it
    #             result['changed'] = True
    #             result['msg'] = 'Connection config has been updated'
    #         else:
    #             # if the connection config hasn't changed we just report a msg
    #             result['msg'] = 'Connection config not changed'

    #     else:
    #         # We couldn't find a connection with the provided name so we add it
    #         try:
    #             guacamole_add_connection(
    #                 base_url=module.params.get('base_url'),
    #                 validate_certs=module.params.get('validate_certs'),
    #                 datasource=guacamole_token['dataSource'],
    #                 auth_token=guacamole_token['authToken'],
    #                 payload=payload
    #             )

    #             result['msg'] = "Connection added: " + module.params.get('connection_name')

    #         except GuacamoleError as e:
    #             module.fail_json(msg=str(e))

    # # module arg state=absent so we have to delete the connection
    # if module.params.get('state') == 'absent':

    #     if guacamole_connection_exists:

    #         try:
    #             guacamole_delete_connection(
    #                 base_url=module.params.get('base_url'),
    #                 validate_certs=module.params.get('validate_certs'),
    #                 datasource=guacamole_token['dataSource'],
    #                 auth_token=guacamole_token['authToken'],
    #                 connection_id=connection_id,
    #             )

    #             result['msg'] = "Connection deleted: " + module.params.get('connection_name')

    #         except GuacamoleError as e:
    #             module.fail_json(msg=str(e))

    #     else:
    #         # the connection doesn't exists so we don't call delete_connection() and just return a msg
    #         result['msg'] = "There is no guacamole connection named " + module.params.get('connection_name')

    # # Get guacamole connections after
    # try:
    #     guacamole_connections_after = guacamole_get_connections(
    #         base_url=module.params.get('base_url'),
    #         validate_certs=module.params.get('validate_certs'),
    #         datasource=guacamole_token['dataSource'],
    #         group=module.params.get('group_name'),
    #         auth_token=guacamole_token['authToken'],
    #     )
    # except GuacamoleError as e:
    #     module.fail_json(msg=str(e))

    # if guacamole_connections_before != guacamole_connections_after:
    #     result['changed'] = True

    # for connection in guacamole_connections_after:
    #     if 'name' in connection:
    #         if connection['name'] == module.params.get('connection_name'):
    #             result['connection_info'] = connection

    module.exit_json(**result)


if __name__ == '__main__':
    main()
