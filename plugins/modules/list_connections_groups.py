#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token, guacamole_get_connections_group_id, guacamole_get_connections_groups_tree
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: list_connections_groups

short_description: Query existing connections_groups in a guacamole server

version_added: "2.9"

description:
    - "Query existing connections groups in a guacamole server"

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

    group_name:
        description:
            - Group name (parentIdentifier) to query
        default: 'ROOT'
        aliases: ['parentIdentifier']
        type: str

    validate_certs:
        description:
            - Validate ssl certs?
        default: true
        type: bool

author:
    - Pablo Escobar Lopez (@pescobar)
    - Robert Schaffer (@RobertSchaffer1)
'''

EXAMPLES = '''

- name: Query existing connections groups
  scicore.guacamole.list_connections_groups:
    base_url: http://localhost:8080/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
  register: _guacamole_connections_groups

'''

RETURN = '''
connections_groups_list:
    description: Information about the existing connections groups in a guacamole server
    type: list of dicts
    returned: always

connections_groups_dict:
    description: Information about the existing connections groups in a guacamole server
    type: dict
    returned: always
'''


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True,
                           no_log=True),
        group_name=dict(type='str', aliases=['parentIdentifier'], default='ROOT'),
        validate_certs=dict(type='bool', default=True),
    )

    result = dict(msg='', connections_groups_list=[], connections_groups_dict={})

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

    if module.params.get('group_name') != "ROOT":
        try:
            module.params['group_name'] = guacamole_get_connections_group_id(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                group=module.params.get('group_name'),
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

    try:
        guacamole_connections_tree = guacamole_get_connections_groups_tree(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            group=module.params.get('group_name'),
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    if guacamole_connections_tree:
        connections_groups = []
        def fetch_connections_groups(nested_group):
            if 'childConnections' in nested_group.keys() or 'childConnectionGroups' in nested_group.keys():
                connections_groups.append({k: v for k, v in nested_group.items()
                                           if k not in ['childConnections', 'childConnectionGroups']})
            if 'childConnectionGroups' in nested_group.keys():
                for child in nested_group['childConnectionGroups']:
                    fetch_connections_groups(child)

        fetch_connections_groups(guacamole_connections_tree)

        # return connections in dict format
        result['connections_groups_list'] = connections_groups

        # return connections in dict format
        for connection_group in connections_groups:
            result['connections_groups_dict'][connection_group['name']] = connection_group

    module.exit_json(**result)


if __name__ == '__main__':
    main()
