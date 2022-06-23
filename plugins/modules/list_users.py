#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token, guacamole_get_users
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: list_users

short_description: Query existing users in a guacamole server

version_added: "2.9"

description:
    - "Query existing users in a guacamole server"

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

author:
    - Pablo Escobar Lopez (@pescobar)
'''

EXAMPLES = '''

- name: Query existing users
  scicore.guacamole.list_users:
    base_url: http://localhost:8080/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
  register: _guacamole_users

'''

RETURN = '''
users_list:
    description: Information about the existing users in a guacamole server
    type: list
    returned: always

users_dict:
    description: Information about the existing users in a guacamole server
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
        validate_certs=dict(type='bool', default=True),
    )

    result = dict(msg='', users_list=[], users_dict={})

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

    try:
        guacamole_users = guacamole_get_users(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # we return the user details in dict and list formats so you
    # can use whatever is more convenient for your needs
    result['users_dict'] = guacamole_users

    for key,value in guacamole_users.items():
       result['users_list'].append(value)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
