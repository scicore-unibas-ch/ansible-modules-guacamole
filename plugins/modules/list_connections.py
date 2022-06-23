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
module: list_connections

short_description: Query existing connections in a guacamole server

version_added: "2.9"

description:
    - "Query existing connections in a guacamole server"

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
'''

EXAMPLES = '''

- name: Query existing connections
  scicore.guacamole.list_connections:
    base_url: http://localhost:8080/guacamole
    auth_username: guacadmin
    auth_password: guacadmin

'''

RETURN = '''
connections_list:
    description: Information about the existing connections in a guacamole server
    type: list of dicts
    returned: always

connections_dict:
    description: Information about the existing connections in a guacamole server
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

    result = dict(msg='', connections_list=[], connections_dict={})

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

    # get the group numeric ID if we are NOT querying the default connections group (ROOT)
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
        guacamole_connections = guacamole_get_connections(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            group=module.params.get('group_name'),
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    if guacamole_connections:

        # return connections in list format
        result['connections_list'] = guacamole_connections

        # return connections in dict format
        for connection in guacamole_connections:
            result['connections_dict'][connection['name']] = connection

    module.exit_json(**result)


if __name__ == '__main__':
    main()
