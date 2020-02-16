#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, guacamole_get_token
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: guacamole_connection

short_description: Administer guacamole connections using the rest API

version_added: "2.9"

description:
    - "Create or delete guacamole connections. You can create rdp, vnc, ssh or telnet connections"

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

    connection_name:
        description:
            - Name of the new connection to create
        required: true
        type: str

    parentIdentifier:
        description:
            - Parent indentifier where to create the connection
        default: 'ROOT'
        type: str

    protocol:
        description:
            - Protocol to use for the new connection
        required: true
        type: str
        choices:
            - rdp
            - vnc
            - ssh
            - telnet

    hostname:
        description:
            - Hostname or ip of the server to connect
        required: true
        type: str

    port:
        description:
            - Port to connect
        required: true
        type: int

    username:
        description:
            - Username for the connection
        required: true
        type: str

    password:
        description:
            - Password for the connection
        required: true
        type: str

    state:
        description:
            - Create or delete the connection?
        default: 'present'
        type: str
        choices:
            - present
            - absent

    max_connections:
        description:
            - Max simultaneos connections allowed for this connection
        required: true
        type: int

    sftp_enable:
        description:
            - Should we enable sftp transfers for this connection?
        type: bool

    sftp_port:
        description:
            - Port to use for sftp
        type: int

    sftp_server_alive_interval:
        description:
            - sftp keep alive interval
        type: int

     sftp_hostname:
        description:
            - Hostname or ip for sftp
        type: str

     sftp_username:
        description:
            - Username for sftp
        type: str

     sftp_password:
        description:
            - Password for sftp
        type: str

     sftp_private_key:
        description:
            - Private key for sftp authentication
        type: str

     sftp_private_key_password:
        description:
            - Password for the sftp private key used for authentication
        type: str

     sftp_root_directory:
        description:
            - File browser root directory
        type: str

     sftp_default_upload_directory:
        description:
            - File browser default upload directory
        type: str


author:
    - Pablo Escobar Lopez (@pescobar)
'''

EXAMPLES = '''

- name: Create a new rdp connection
  scicore.guacamole.guacamole_connection:
    base_url: http://localhost/guacamole
    validate_certs: false
    auth_username: guacadmin
    auth_password: guacadmin
    connection_name: test_name_3
    protocol: rdp
    parentIdentifier: ROOT
    hostname: 192.168.33.44
    port: 3389
    username: rdp_user
    password: rdp_pass
    state: present

- name: Create a new vnc connection with sftp enabled
  scicore.guacamole.guacamole_connection:
    base_url: http://localhost/guacamole
    validate_certs: false
    auth_username: guacadmin
    auth_password: guacadmin
    connection_name: test_vnc
    protocol: vnc
    parentIdentifier: ROOT
    hostname: 192.168.33.44
    port: 5900
    username: rdp_user
    password: rdp_pass
    state: present
    sftp_enable: true
    sftp_port: 22
    sftp_hostname: 192.168.11.11
    sftp_server_alive_interval: 10
    sftp_username: sftp_user
    sftp_password: adsfadfasfdasf

'''

RETURN = '''
connection_info:
    description: Information about the created or updated connection
    type: dict
    returned: always
message:
    description: Some extra info about what the module did
    type: str
    returned: always
'''


URL_LIST_USERS = "{url}/api/session/data/{datasource}/users?token={token}"
URL_ADD_USER = URL_LIST_USERS
URL_UPDATE_USER = "{url}/api/session/data/postgresql/users/{username}?token={token}"
URL_DELETE_USER = URL_UPDATE_USER


def guacamole_get_users(base_url, validate_certs, datasource, auth_token):
    """
    Return all the users registered in the guacamole server
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
            "expired": "",
            "access-window-start": "",
            "access-window-end": "",
            "valid-from": "",
            "valid-until": "",
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
    Add a new user account to the guacamole server.
    """

    url_add_user = URL_ADD_USER.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        r = open_url(url_add_user, method='POST', validate_certs=validate_certs,
                     headers=headers, data=json.dumps(payload))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to add user from %s: %s'
            % (url_add_user, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not add a new user in %s: %s'
                             % (url_add_user, str(e)))

def guacamole_update_user(base_url, validate_certs, datasource, username, auth_token, payload):
    """
    Update existing user in the guacamole server.
    """

    url_update_user = URL_UPDATE_USER.format(
        url=base_url, datasource=datasource, username=username, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        r = open_url(url_update_user, method='PUT', validate_certs=validate_certs,
                     headers=headers, data=json.dumps(payload))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to update user from %s: %s'
            % (url_update_user, str(e)))
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
        r = open_url(url_delete_user, method='DELETE', validate_certs=validate_certs)
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to delete user from %s: %s'
            % (url_delete_user, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not delete user in %s: %s'
                             % (url_delete_user, str(e)))


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
        password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
        disabled=dict(type='bool', default=None),
        expired=dict(type='str', default=None),
        access_window_start=dict(type='str', default=None),
        access_window_end=dict(type='str', default=None),
        valid_from=dict(type='str', default=''),
        valid_until=dict(type='str', default=''),
        timezone=dict(type='str', default=''),
        full_name=dict(type='str', default=''),
        email=dict(type='str', default=''),
        organization=dict(type='str', default=''),
        organizational_role=dict(type='str', default=''),
    )

    result = dict(changed=False, msg='', diff={},
                  connection_info={})

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
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
    # if the user exists we define "guacamole_user = existing_username"
    for user in guacamole_users_before.items():
        guacamole_user = None
        if user[1]['username'] == module.params.get('username'):
            guacamole_user = user[1]['username']

    # module arg state=present so we must create or update a user in guacamole
    if module.params.get('state') == 'present':

        # populate the payload to send to the API
        payload = guacamole_populate_user_payload(module.params)

        # if the user already exists in guacamole we update it
        if guacamole_user:
            try:
                guacamole_update_user(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    username=guacamole_user,
                    payload=payload
                )

            except GuacamoleError as e:
                module.fail_json(msg=str(e))
            pass

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

    # Get existing guacamole users after
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

    module.exit_json(**result)


if __name__ == '__main__':
    main()
