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
module: guacamole_user

short_description: Administer guacamole users using the rest API

version_added: "2.9"

description:
    - "Create or delete a guacamole user"

options:
    base_url:
        description:
            - Url to access the guacamole API
        required: true
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

    username:
        description:
            - Name of the new user to create
        required: true
        type: str

    password:
        description:
            - Password for the new user
        type: str

    allowed_connections:
        description:
            - List of connections where this user can connect
        type: list
        elements: str

    state:
        description:
            - Create or delete the user?
        default: 'present'
        type: str
        choices:
            - present
            - absent

    disabled:
        description:
            - Disable the account?
        type: bool

    expired:
        description:
            - Is this account expired?
        type: bool

    allow_access_after:
        description:
            - Hour to allow access. Format --:--
        type: str

    do_not_allow_access_after:
        description:
            - Hour to disallow access. Format --:--
        type: str

    enable_account_after:
        description:
            - Date to enable the account in format "YYYY-MM-DD" e.g. "2020-10-23"
        type: str

    disable_account_after:
        description:
            - Date to disable the account in format "YYYY-MM-DD" e.g. "2020-10-23"
        type: str

    timezone:
        description:
            - User timezone
        type: str

    full_name:
        description:
            - Full name of the user
        type: str

    email:
        description:
            - Email of the user
        type: str

    organization:
        description:
            - Organization of the user
        type: str

    organizational_role:
        description:
            - Role of the user in his/her organization
        type: str

author:
    - Pablo Escobar Lopez (@pescobar)
'''

EXAMPLES = '''

- name: Create a new guacamole user
  scicore.guacamole.guacamole_user:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    username: test_user_3
    password: user_pass
    allowed_connections:
      - connection_1
      - connection_2
    full_name: John Foo
    email: john@email.com
    organization: company_bar

- name: Delete a guacamole user
  scicore.guacamole.guacamole_user:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    username: test_user_3
    state: absent

- name: Update password guacadmin user
  scicore.guacamole.guacamole_user:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    username: guacadmin
    password: newpassword
'''

RETURN = '''
user_info:
    description: Information about the created or updated user
    type: dict
    returned: always
message:
    description: Message about what the module did
    type: str
    returned: always
'''


URL_LIST_USERS = "{url}/api/session/data/{datasource}/users?token={token}"
URL_ADD_USER = URL_LIST_USERS
URL_UPDATE_USER = "{url}/api/session/data/{datasource}/users/{username}?token={token}"
URL_DELETE_USER = URL_UPDATE_USER
URL_GET_USER_PERMISSIONS = "{url}/api/session/data/{datasource}/users/{username}/permissions?token={token}"
URL_UPDATE_USER_PERMISSIONS = URL_GET_USER_PERMISSIONS
URL_UPDATE_PASSWORD_CURRENT_USER = "{url}/api/session/data/{datasource}/users/{username}/password?token={token}"


def guacamole_get_users(base_url, validate_certs, datasource, auth_token):
    """
    Returns a dict with all the users registered in the guacamole server
    """

    url_list_users = URL_LIST_USERS.format(url=base_url, datasource=datasource, token=auth_token)

    try:
        guacamole_users = json.load(open_url(url_list_users, method='GET', validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of users from %s: %s'
            % (url_list_users, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole users from %s: %s'
                             % (url_list_users, str(e)))

    return guacamole_users


def guacamole_populate_user_payload(module_params):
    """
    Populate the json that we send to the guaccamole API to create new user
    or update existing ones
    """

    payload = {
        "username": module_params['username'],
        "password": module_params['password'],
        "attributes": {
            "disabled": module_params['disabled'],
            "expired": module_params['expired'],
            "access-window-start": module_params['allow_access_after'],
            "access-window-end": module_params['do_not_allow_access_after'],
            "valid-from": module_params['enable_account_after'],
            "valid-until": module_params['disable_account_after'],
            "timezone": "",
            "guac-full-name": module_params['full_name'],
            "guac-email-address": module_params['email'],
            "guac-organization": module_params['organization'],
            "guac-organizational-role": module_params['organizational_role']
        }
    }

    return payload


def guacamole_add_user(base_url, validate_certs, datasource, auth_token, payload):
    """
    Add a new user account to the guacamole server doing a POST of the payload to the API
    """

    url_add_user = URL_ADD_USER.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_add_user, method='POST', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not add a new user in %s: %s'
                             % (url_add_user, str(e)))


def guacamole_update_user(base_url, validate_certs, datasource, username, auth_token, payload):
    """
    Update existing user in the guacamole server doing a PUT of the payload to the API
    """

    url_update_user = URL_UPDATE_USER.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_user, method='PUT', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update user in %s: %s'
                             % (url_update_user, str(e)))


def guacamole_delete_user(base_url, validate_certs, datasource, username, auth_token):
    """
    Delete existing user in the guacamole server.
    """

    url_delete_user = URL_DELETE_USER.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    try:
        open_url(url_delete_user, method='DELETE', validate_certs=validate_certs)
    except Exception as e:
        raise GuacamoleError('Could not delete user in %s: %s'
                             % (url_delete_user, str(e)))


def guacamole_get_user_permissions(base_url, validate_certs, datasource, username, auth_token):
    """
    Return a dict with detailed current permissions for a user
    """

    url_get_user_permissions = URL_GET_USER_PERMISSIONS.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    try:
        user_permissions = json.load(open_url(url_get_user_permissions, method='GET', validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain user permissions from %s: %s'
            % (url_get_user_permissions, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain user permissions from %s: %s'
                             % (url_get_user_permissions, str(e)))

    return user_permissions


def guacamole_update_user_permissions_for_connection(base_url, validate_certs, datasource, username,
                                      connection_id, operation, auth_token):
    """
    Update permissions for existing user in a specific connection
    """

    url_update_user_permissions = URL_UPDATE_USER_PERMISSIONS.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    payload = [{
        'op': operation,
        'path': '/connectionPermissions/' + str(connection_id),
        'value': 'READ'
    }]

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_user_permissions, method='PATCH', validate_certs=validate_certs, headers=headers,
                 data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update permissions in %s: %s'
                             % (url_update_user_permissions, str(e)))


def guacamole_update_user_permissions_for_group(base_url, validate_certs, datasource, username,
                                      group_id, operation, auth_token):
    """
    Update permissions for existing user in a specific group of connections
    When granting access to a connection which is located in a group of connections we need
    to grant access to the parent group too
    """

    url_update_user_permissions = URL_UPDATE_USER_PERMISSIONS.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    payload = [{
        'op': operation,
        'path': '/connectionGroupPermissions/' + str(group_id),
        'value': 'READ'
    }]

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_user_permissions, method='PATCH', validate_certs=validate_certs, headers=headers,
                 data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update permissions in %s: %s'
                             % (url_update_user_permissions, str(e)))


def guacamole_update_password_current_user(base_url, validate_certs, datasource, username,
                                           current_password, new_password, auth_token):
    """
    Update just the password for the user we use to connect to the api
    We usually do this for the default admin user "guacadmin"
    http://mail-archives.apache.org/mod_mbox/guacamole-dev/202006.mbox/%3CCALKeL-PbLS8qodWEL3yHWWCir87Xqq0z9pVcbp3S-yjwEpYVTw%40mail.gmail.com%3E
    """

    url_update_password_current_user = URL_UPDATE_PASSWORD_CURRENT_USER.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    payload = {
        'oldPassword': current_password,
        'newPassword': new_password
    }

    try:
        headers = {'Content-Type': 'application/json'}
        open_url(url_update_password_current_user, method='PUT', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
    except Exception as e:
        raise GuacamoleError('Could not update user in %s: %s'
                             % (url_update_password_current_user, str(e)))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True,
                           no_log=True),
        validate_certs=dict(type='bool', default=True),
        username=dict(type='str', aliases=['name'], required=True),
        password=dict(type='str', no_log=True),
        allowed_connections=dict(type='list', default=[]),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
        full_name=dict(type='str', Default=None),
        email=dict(type='str', Default=None),
        organization=dict(type='str', Default=None),
        organizational_role=dict(type='str', Default=None),
        disabled=dict(type='bool', default=None),
        expired=dict(type='str', default=None),
        allow_access_after=dict(type='str', default=None),
        do_not_allow_access_after=dict(type='str', default=None),
        enable_account_after=dict(type='str', default=''),
        disable_account_after=dict(type='str', default=''),
        timezone=dict(type='str', default=''),
    )

    result = dict(changed=False, msg='', diff={},
                  connection_info={})

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

    # if we are updating the same user which we use to connect to the api we need to use a different
    # api endpoing to update the password. This is usually done for default admin user "guacadmin"
    # http://mail-archives.apache.org/mod_mbox/guacamole-dev/202006.mbox/%3CCALKeL-PbLS8qodWEL3yHWWCir87Xqq0z9pVcbp3S-yjwEpYVTw%40mail.gmail.com%3E
    # After updating the password for guacadmin user we just exit because last guacamole version (1.2.0)
    # doesn't allow to update anything else for the guacadmin account
    if module.params.get('auth_username') == module.params.get('username'):

        try:
            guacamole_update_password_current_user(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                username=module.params.get('username'),
                current_password=module.params.get('auth_password'),
                new_password=module.params.get('password'),
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

        if module.params.get('auth_password') != module.params.get('password'):
            result['msg'] = "Password updated for user %s" % module.params.get('username')
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    # Get existing guacamole users before doing anything else
    try:
        guacamole_users_before = guacamole_get_users(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # check if the user already exists in guacamole
    guacamole_user_exists = False
    for username, userinfo in guacamole_users_before.items():
        if username == module.params.get('username'):
            guacamole_user_exists = True
            break

    if guacamole_user_exists:
        # Query the current permissions for this user so we can later check if they changed
        try:
            user_permissions_before = guacamole_get_user_permissions(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                username=module.params.get('username'),
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

    # module arg state=present so we must create or update a user in guacamole
    if module.params.get('state') == 'present':

        # populate the payload with the user info to send to the API
        payload = guacamole_populate_user_payload(module.params)

        # if the user already exists in guacamole we update it
        if guacamole_user_exists:
            try:
                guacamole_update_user(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    username=module.params.get('username'),
                    payload=payload
                )

            except GuacamoleError as e:
                module.fail_json(msg=str(e))

        # if the user doesn't exist in guacamole we create it
        else:
            try:
                guacamole_add_user(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    payload=payload
                )

            except GuacamoleError as e:
                module.fail_json(msg=str(e))

        # now that the user has been created or updated we apply the permissions
        # so he/she can access the required connections

        # Query the existing connections to check which ones the user is allowed to use
        try:
            guacamole_connections = guacamole_get_connections(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                group='ROOT',
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))


        # if var "allowed connections" is not an empty list we grant the required access
        if module.params['allowed_connections']:

            for connection in guacamole_connections:

                # if the connection is in the top group (ROOT) we only need to grant access to the connection
                if connection['parentIdentifier'] == 'ROOT':
                    # if the connection is in the list of allowed connections for this user we grant access.
                    if connection['name'] in module.params.get('allowed_connections'):
                        try:
                            guacamole_update_user_permissions_for_connection(
                                base_url=module.params.get('base_url'),
                                validate_certs=module.params.get('validate_certs'),
                                datasource=guacamole_token['dataSource'],
                                auth_token=guacamole_token['authToken'],
                                username=module.params.get('username'),
                                connection_id=connection['identifier'],
                                operation='add'
                            )
                        except GuacamoleError as e:
                            module.fail_json(msg=str(e))

                # if the connection is in a sub-group we need to grant access to the connection and the group
                if connection['parentIdentifier'] != 'ROOT':
                    if connection['name'] in module.params.get('allowed_connections'):

                        try:
                            guacamole_update_user_permissions_for_group(
                                base_url=module.params.get('base_url'),
                                validate_certs=module.params.get('validate_certs'),
                                datasource=guacamole_token['dataSource'],
                                auth_token=guacamole_token['authToken'],
                                username=module.params.get('username'),
                                group_id=connection['parentIdentifier'],
                                operation='add'
                            )
                        except GuacamoleError as e:
                            module.fail_json(msg=str(e))

                        try:
                            guacamole_update_user_permissions_for_connection(
                                base_url=module.params.get('base_url'),
                                validate_certs=module.params.get('validate_certs'),
                                datasource=guacamole_token['dataSource'],
                                auth_token=guacamole_token['authToken'],
                                username=module.params.get('username'),
                                connection_id=connection['identifier'],
                                operation='add'
                            )
                        except GuacamoleError as e:
                            module.fail_json(msg=str(e))

        # loop again over all the connections to remove access to those connections
        # not explicitely defined for the user. This is always executed
        for connection in guacamole_connections:
            if connection['name'] not in module.params.get('allowed_connections'):
                try:
                    guacamole_update_user_permissions_for_connection(
                        base_url=module.params.get('base_url'),
                        validate_certs=module.params.get('validate_certs'),
                        datasource=guacamole_token['dataSource'],
                        auth_token=guacamole_token['authToken'],
                        username=module.params.get('username'),
                        connection_id=connection['identifier'],
                        operation='remove'
                    )
                except GuacamoleError as e:
                    module.fail_json(msg=str(e))


    # module arg state=absent so we must delete a user from guacamole
    if module.params.get('state') == 'absent':

        # if the user already exists in guacamole we delete it
        if guacamole_user_exists:

            try:
                guacamole_delete_user(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    username=module.params.get('username'),
                )

                result['msg'] = "User deleted: " + module.params.get('username')

                # after deleting the user we set "guacamole_user_exists = False"
                # to skip checking if the permissions for this user changed
                guacamole_user_exists = False

            except GuacamoleError as e:
                module.fail_json(msg=str(e))

        # if the user doesn't exist in guacamole we just inform about it
        else:
            result['msg'] = "Nothing deleted. No guacamole username " + module.params.get('username')

    if guacamole_user_exists:
        # Query the permissions for this user again so check if they changed
        try:
            user_permissions_after = guacamole_get_user_permissions(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                username=module.params.get('username'),
                auth_token=guacamole_token['authToken'],
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

        if user_permissions_before != user_permissions_after:
            result['changed'] = True

    # Get existing guacamole users after the module execution to check if something changed
    try:
        guacamole_users_after = guacamole_get_users(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    if guacamole_users_before != guacamole_users_after:
        result['changed'] = True

    for username, userinfo in guacamole_users_after.items():
        if username == module.params.get('username'):
            result['user_info'] = userinfo
            break

    module.exit_json(**result)


if __name__ == '__main__':
    main()
