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


URL_LIST_CONNECTIONS = "{url}/api/session/data/{datasource}/connectionGroups/\
{parent_identifier}/tree?token={token}"
URL_ADD_CONNECTION = "{url}/api/session/data/{datasource}/connections?token={token}"
URL_UPDATE_CONNECTION = "{url}/api/session/data/{datasource}/connections/{connection_id}?token={token}"
URL_DELETE_CONNECTION = URL_UPDATE_CONNECTION
URL_CONNECTION_DETAILS = "{url}/api/session/data/{datasource}/connections/{connection_id}/parameters?token={token}"


def guacamole_get_connections(base_url, validate_certs, datasource, parent_identifier, auth_token):
    """
    Return a list of dicts with all the connections registered in the guacamole server
    for the provided parent_identifier
    """

    url_list_connections = URL_LIST_CONNECTIONS.format(
        url=base_url, datasource=datasource, parent_identifier=parent_identifier, token=auth_token)

    try:
        parent_identifier_connections = json.load(open_url(url_list_connections, method='GET',
                               validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of connections from %s: %s'
            % (url_list_connections, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole connections from %s: %s'
                             % (url_list_connections, str(e)))

    return parent_identifier_connections['childConnections']

def guacamole_get_connection_details(base_url, validate_certs, datasource, connection_id, auth_token):
    """
    Get detailed connection parameters for a single connection.
    This function requires a connection id and provides more information than function guacamole_get_connections()
    """

    url_connection_details = URL_CONNECTION_DETAILS.format(
        url=base_url, datasource=datasource, connection_id=connection_id, token=auth_token)

    try:
        r = json.load(open_url(url_connection_details, method='GET',
                               validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain connection details from %s: %s'
            % (url_connection_details, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain connection details from %s: %s'
                             % (url_connection_details, str(e)))

    return {
        'guacamole_connection_details': r,
    }

def guacamole_populate_connection_payload(module_params):
    """
    Populate the json that we send to the guaccamole API to create new connection
    or update existing ones
    """

    payload = {
        "parentIdentifier": module_params['parentIdentifier'],
        "name": module_params['connection_name'],
        "protocol": module_params['protocol'],
        "parameters": {
            "hostname": module_params['hostname'],
            "port": module_params['port'],
            "username": module_params['username'],
            "password": module_params['password'],
            "enable-sftp": module_params['sftp_enable'],
            "sftp-port": module_params['sftp_port'],
            "sftp-server-alive-interval": module_params['sftp_server_alive_interval'],
            "sftp-hostname": module_params['sftp_hostname'],
            "sftp-username": module_params['sftp_username'],
            "sftp-password": module_params['sftp_password'],
            "sftp-private-key": module_params['sftp_private_key'],
            "passphrase": module_params['sftp_private_key_password'],
            "sftp-root-directory": module_params['sftp_root_directory'],
            "sftp-directory": module_params['sftp_default_upload_directory']
        },
        "attributes": {
            "guacd-encryption": "",
            "failover-only": "",
            "weight": "",
            "max-connections": module_params['max_connections'],
            "guacd-hostname": "",
            "guacd-port": "",
            "max-connections-per-user": ""
        }
    }

    return payload

def guacamole_add_connection(base_url, validate_certs, datasource, auth_token, payload):
    """
    Add a new connection to the guacamole server. ]
    Connection can be RDP, VNC, SSH or TELNET
    """

    url_add_connection = URL_ADD_CONNECTION.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        r = open_url(url_add_connection, method='POST', validate_certs=validate_certs,
                     headers=headers, data=json.dumps(payload))
    except HTTPError as e:
        # guacamole api returns http error code 400 if connection
        # with the same name already exists
        if e.code == 400:
            pass
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to add connection from %s: %s'
            % (url_add_connection, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not add a new connection in %s: %s'
                             % (url_add_connection, str(e)))


def guacamole_update_connection(base_url, validate_certs, datasource, connection_id, auth_token, payload):
    """
    Update an existing guacamole connection
    """

    url_update_connection = URL_UPDATE_CONNECTION.format(
        url=base_url, datasource=datasource, connection_id=connection_id, token=auth_token)

    try:
        headers = {'Content-Type': 'application/json'}
        r = open_url(url_update_connection, method='PUT', validate_certs=validate_certs,
                     headers=headers, data=json.dumps(payload))
    except HTTPError as e:
        # guacamole api returns http error code 400 if connection
        # with the same name already exists
        if e.code == 400:
            pass
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to update connection from %s: %s'
            % (url_update_connection, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not add a new connection in %s: %s'
                             % (url_update_connection, str(e)))


def guacamole_delete_connection(base_url, validate_certs, datasource, connection_id, auth_token):
    """
    Delete an existing guacamole connection.
    API doesn't return any json
    """

    url_delete_connection = URL_DELETE_CONNECTION.format(
        url=base_url, datasource=datasource, connection_id=connection_id, token=auth_token)

    #  print(url_delete_connection)
    try:
        open_url(url_delete_connection, method='DELETE', validate_certs=validate_certs)
    except Exception as e:
        raise GuacamoleError('Could not delete guacamole connection from %s: %s'
                             % (url_delete_connection, str(e)))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True,
                           no_log=True),
        validate_certs=dict(type='bool', default=True),
        parentIdentifier=dict(type='str', default='ROOT'),
        connection_name=dict(type='str', aliases=['name'], required=True),
        protocol=dict(type='str', choices=['rdp', 'vnc', 'ssh', 'telnet']),
        hostname=dict(type='str', required=True),
        port=dict(type='int', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
        max_connections=dict(type='int', default=1),
        sftp_enable=dict(type='bool', default=False),
        sftp_port=dict(type='int', required=False),
        sftp_server_alive_interval=dict(type='int', required=False),
        sftp_hostname=dict(type='str', required=False),
        sftp_username=dict(type='str', required=False),
        sftp_password=dict(type='str', required=False, no_log=True),
        sftp_private_key=dict(type='str', required=False),
        sftp_private_key_password=dict(type='str', required=False, no_log=True),
        sftp_root_directory=dict(type='str', required=False),
        sftp_default_upload_directory=dict(type='str', required=False)
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

    # Get guacamole connections before doing anything else
    try:
        guacamole_connections_before = guacamole_get_connections(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            parent_identifier='ROOT',
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # first check if the connection already exists and fetch its id
    guacamole_connection_exists = False
    for connection in guacamole_connections_before:
        if connection['name'] == module.params.get('connection_name'):
            guacamole_connection_exists = True
            connection_id = connection['identifier']
            break

    if module.params.get('state') == 'present':

        payload = guacamole_populate_connection_payload(module.params)

        if guacamole_connection_exists:

            try:
                connection_config_before_update = guacamole_get_connection_details(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    connection_id=connection_id,
                )
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            try:
                guacamole_update_connection(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    connection_id=connection_id,
                    payload=payload
                )
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            try:
                connection_config_after_update = guacamole_get_connection_details(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    connection_id=connection_id,
                )
            except GuacamoleError as e:
                module.fail_json(msg=str(e))

            if connection_config_before_update != connection_config_after_update:
                result['changed'] = True
                result['msg'] = 'Connection config has been updated'
            else:
                result['msg'] = 'Connection config not changed'

        else:
            # We couldn't find a connection with the provided name so we add it
            try:
                guacamole_add_connection(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    payload=payload
                )

                result['msg'] = "Connection added: " + module.params.get('connection_name')

            except GuacamoleError as e:
                module.fail_json(msg=str(e))


    if module.params.get('state') == 'absent':

        if guacamole_connection_exists:

            try:
                guacamole_delete_connection(
                    base_url=module.params.get('base_url'),
                    validate_certs=module.params.get('validate_certs'),
                    datasource=guacamole_token['dataSource'],
                    auth_token=guacamole_token['authToken'],
                    connection_id=connection_id,
                )

                result['msg'] = "Connection deleted: " + module.params.get('connection_name')

            except GuacamoleError as e:
                module.fail_json(msg=str(e))

        else:
            # the connection doesn't exists so we don't call delete_connection() and just return a msg
            result['msg'] = "There is no guacamole connection named " + module.params.get('connection_name')


    # Get guacamole connections after
    try:
        guacamole_connections_after = guacamole_get_connections(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            parent_identifier='ROOT',
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    if guacamole_connections_before != guacamole_connections_after:
        result['changed'] = True

    for connection in guacamole_connections_after:
        if connection['name'] == module.params.get('connection_name'):
            result['connection_info'] = connection

    module.exit_json(**result)


if __name__ == '__main__':
    main()
