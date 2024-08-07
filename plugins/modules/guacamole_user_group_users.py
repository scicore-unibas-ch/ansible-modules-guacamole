#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: guacamole_user_group_users

short_description: Administer guacamole user-group users using the rest API

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

    users:
        description:
            - Dictionary that maps user-groups to a list of users.
        type: dict
        elements: str

    state:
        description:
            - Create, delete or sync the user-group members.
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

- name: Assign user 'u1'  to user group 'users1'
  scicore.guacamole.guacamole_user_group_users:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    users:
      "{{ { 'users1': ['u1'] } }}"
    state: present

- name: Remove user 'u1'  from user group 'users1'
  scicore.guacamole.guacamole_user_group_users:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    users:
      "{{ { 'users1': ['u1'] } }}"
    state: absent


- name: Assign user 'u1' to user group 'users1', and remove any other users from 'users1'.
  scicore.guacamole.guacamole_user_group_users:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    users:
      "{{ { 'users1': ['u1'] } }}"
    state: sync

'''

RETURN = '''
message:
    description: Some extra info about what the module did
    type: str
    returned: always
'''

URL_GET_GROUP_MEMBERS = "{url}/api/session/data/{datasource}/userGroups/{group_name}/memberUsers?token={token}"
URL_UPDATE_USERS_IN_GROUP = URL_GET_GROUP_MEMBERS


def guacamole_get_user_group_users(base_url, validate_certs, datasource, auth_token, group_name):
    """
    Returns a dict of dicts.
    Each dict provides the details for one of the users groups defined in guacamole
    """

    url_get_users_group_permissions = URL_GET_GROUP_MEMBERS.format(
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


def guacamole_update_users_in_group(base_url, validate_certs, datasource, auth_token, group_name, user, action):
    """
    Add or remove a user to a group.
    Action must be "add" or "remove"
    """

    if action not in ['add', 'remove']:
        raise GuacamoleError("action must be 'add' or 'remove'")

    url_update_users_in_group = URL_UPDATE_USERS_IN_GROUP.format(
        url=base_url, datasource=datasource, token=auth_token, group_name=group_name)

    payload = [{
        "op": action,
        "path": '/',
        "value": user,
    }]

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_users_in_group, method='PATCH', validate_certs=validate_certs, headers=headers,
                 data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update users for group %s in url %s. Error msg: %s'
                             % (group_name, url_update_users_in_group, str(e)))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True),
        users=dict(type='dict', default={}),
        state=dict(type='str', choices=['absent', 'present', 'sync'], default='present')
    )

    result = dict(changed=False, msg='')

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

    users = module.params.get('users')

    # Add users to user-group.
    if module.params.get('state') in {'present', 'sync'}:
        for group_name, usernames in users.items():

            # Check the existing users for the user group.
            try:
                existing_users = set(guacamole_get_user_group_users(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    group_name=group_name
                ))
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            # Find which users need to be added.
            new_users = set(usernames) - existing_users

            # Add new users to user-group.
            for new_user in new_users:
                try:
                    guacamole_update_users_in_group(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        group_name=group_name,
                        user=new_user,
                        action='add',
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))

                result['changed'] = True

    # Remove users from user group.
    if module.params.get('state') in {'absent', 'sync'}:

        for group_name, usernames in users.items():

            # Find which users need to be removed.
            existing_users = set(guacamole_get_user_group_users(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                auth_token=guacamole_token['authToken'],
                group_name=group_name
            ))
            if module.params.get('state') == 'absent':
                remove_users = set(usernames) & existing_users
            else:
                remove_users = existing_users - set(usernames)

            # Remove users.
            for remove_user in remove_users:
                try:
                    guacamole_update_users_in_group(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        group_name=group_name,
                        user=remove_user,
                        action='remove',
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))

                result['changed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()
