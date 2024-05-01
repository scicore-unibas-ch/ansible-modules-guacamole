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
module: guacamole_connection

short_description: Administer guacamole connections using the rest API

version_added: "2.9"

description:
    - "Add or remove guacamole connections. You can create rdp, vnc, ssh or telnet connections"

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

    connection_name:
        description:
            - Name of the new connection to create
        required: true
        aliases: ['name']
        type: str

    group_name:
        description:
            - Group name (parentIdentifier) where to create the connection
        default: 'ROOT'
        aliases: ['parentIdentifier']
        type: str

    guacd_hostname:
        description:
            - Hostname or ip of the guacd to connect
        type: str

    guacd_port:
        description:
            - Port to connect on guacd
        type: int

    guacd_encryption:
        description:
            - Connect with SSL / TLS or None (unencrypted)
        type: str
        choices:
            - ssl
            - ""
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
        type: str

    port:
        description:
            - Port to connect
        type: int

    username:
        description:
            - Username for the connection
        type: str

    password:
        description:
            - Password for the connection
        type: str

    rdp_color_depth:
        description:
            - Color depth in bits
        type: int
        choices:
            - 8
            - 16
            - 24
            - 32

    rdp_domain:
        description:
            - Domain for the connection

    rdp_enable_drive:
        description:
            - Enable network drive mapping
        type: bool

    rdp_drive_name:
        description:
            - Network drive name
        type: str

    rdp_drive_path:
        description:
            - Path to network drive
        type: str

    rdp_enable_full_window_drag:
        description:
            - Display whole windows when they are being dragged
        type: bool

    rdp_ignore_server_certs:
        description:
            - Ignore rdp server certs
        type: bool

    rdp_security:
        description:
            - The security mode to use for the RDP connection
        type: str
        choices:
            - any
            - nla
            - nla-ext
            - tls
            - rdp

    rdp_server_layout:
        description:
            - Keyboard layout
        type: str
        choices:
            - en-us-qwerty
            - en-gb-qwerty
            - de-ch-qwertz
            - de-de-qwertz
            - fr-be-azerty
            - fr-fr-azerty
            - fr-ch-qwertz
            - hu-hu-qwertz
            - it-it-qwerty
            - ja-jp-qwerty
            - pt-br-qwerty
            - es-es-qwerty
            - es-latam-qwerty
            - sv-se-qwerty
            - tr-tr-qwerty
            - failsafe

    rdp_width:
        description:
            - Display width
        type: int

    rdp_height:
        description:
            - Display height
        type: int

    ssh_passphrase:
        description:
            - Passphrase for the SSH private key
        type: str

    ssh_private_key:
        description:
            - Private key for the SSH connection
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
            - Max simultaneous connections allowed for this connection
        type: int

    max_connections_per_user:
        description:
            - Max simultaneous connections allowed per guacamole user for this connection
        type: int

    recording_path:
        description:
            - recording path for connection
        type: str

    recording_include_keys:
        description:
            - include keyboard events for connection
        type: bool

    recording_name:
        description:
            - recording name for connection
        type: str

    sftp_enable:
        description:
            - Should we enable sftp transfers for this connection?
        type: bool

    read_only:
        description:
            - True if connection should be read-only.
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

    sftp_passphrase:
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

    cursor:
        description:
            - Cursor type, choose between remote or local
        type: str


author:
    - Pablo Escobar Lopez (@pescobar)
'''

EXAMPLES = '''

- name: Create a new rdp connection
  scicore.guacamole.guacamole_connection:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    connection_name: test_name_3
    protocol: rdp
    hostname: 192.168.33.44
    port: 3389
    username: rdp_user
    password: rdp_pass

- name: Create a new vnc connection with sftp enabled
  scicore.guacamole.guacamole_connection:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    connection_name: test_vnc
    protocol: vnc
    hostname: 192.168.33.44
    port: 5900
    username: vnc_user
    password: vnc_pass
    sftp_enable: true
    read_only: false
    sftp_port: 22
    sftp_hostname: 192.168.11.11
    sftp_server_alive_interval: 10
    sftp_username: sftp_user
    sftp_password: adsfadfasfdasf

- name: Delete a connection
  scicore.guacamole.guacamole_connection:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    connection_name: test_CC
    state: absent

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


URL_ADD_CONNECTION = "{url}/api/session/data/{datasource}/connections?token={token}"
URL_UPDATE_CONNECTION = "{url}/api/session/data/{datasource}/connections/{connection_id}?token={token}"
URL_DELETE_CONNECTION = URL_UPDATE_CONNECTION
URL_CONNECTION_DETAILS = "{url}/api/session/data/{datasource}/connections/{connection_id}/parameters?token={token}"


def guacamole_get_connection_details(base_url, validate_certs, datasource, connection_id, auth_token):
    """
    Return a dict with detailed connection parameters for a single connection.
    This function requires a connection id and provides more information than function guacamole_get_connections()
    """

    url_connection_details = URL_CONNECTION_DETAILS.format(
        url=base_url, datasource=datasource, connection_id=connection_id, token=auth_token)

    try:
        connection_details = json.load(open_url(url_connection_details, method='GET',
                                                validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain connection details from %s: %s'
            % (url_connection_details, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain connection details from %s: %s'
                             % (url_connection_details, str(e)))

    return connection_details


def guacamole_add_parameter(payload, module_params, parameters, protocol=None):
    for parameter in parameters:
        if protocol is None:
            ansible_parameter = parameter
        else:
            ansible_parameter = "{}_{}".format(protocol, parameter)
        api_parameter = parameter.replace("_", "-")
        if module_params.get(ansible_parameter):
            payload["parameters"][api_parameter] = module_params[ansible_parameter]


def guacamole_populate_connection_payload(module_params):
    """
    Populate the json that we send to the guaccamole API to create new connection
    or update existing ones
    """

    payload = {
        "parentIdentifier": module_params['group_name'],
        "name": module_params['connection_name'],
        "protocol": module_params['protocol'],
        "parameters": {
            "enable-sftp": module_params['sftp_enable'],
            "sftp-directory": module_params['sftp_default_upload_directory'],
            "read-only": module_params['read_only']
        },
        "attributes": {
            "guacd-encryption": module_params['guacd_encryption'],
            "failover-only": "",
            "weight": "",
            "max-connections": module_params['max_connections'],
            "guacd-hostname": module_params['guacd_hostname'],
            "guacd-port": module_params['guacd_port'],
            "max-connections-per-user": module_params['max_connections_per_user']
        }
    }

    parameters = (
        "hostname",
        "port",
        "username",
        "password",
        "recording_path",
        "recording_include_keys",
        "recording_name",
        "sftp_port",
        "sftp_server_alive_interval",
        "sftp_hostname",
        "sftp_username",
        "sftp_passphrase",
        "sftp_password",
        "sftp_private_key",
        "sftp_root_directory",
        "disable_copy",
        "disable_paste",
        "cursor",
        "read_only"
    )
    guacamole_add_parameter(payload, module_params, parameters)

    if module_params['protocol'] == 'rdp':
        parameters = (
            "color_depth",
            "domain",
            "enable_drive",
            "drive_name",
            "drive_path",
            "enable_full_window_drag",
            "security",
            "server_layout",
            "width",
            "height"
        )
        guacamole_add_parameter(payload, module_params, parameters, "rdp")
        if module_params.get('rdp_ignore_server_certs'):
            payload['parameters']['ignore-cert'] = module_params['rdp_ignore_server_certs']
    elif module_params["protocol"] == "ssh":
        parameters = ("private_key", "passphrase")
        guacamole_add_parameter(payload, module_params, parameters, "ssh")

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
        open_url(url_add_connection, method='POST', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
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
        open_url(url_update_connection, method='PUT', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
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
        group_name=dict(type='str', aliases=['parentIdentifier'], default='ROOT'),
        connection_name=dict(type='str', aliases=['name'], required=True),
        protocol=dict(type='str', choices=['rdp', 'vnc', 'ssh', 'telnet']),
        hostname=dict(type='str'),
        port=dict(type='int'),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        rdp_color_depth=dict(type='int', choices=(8, 16, 24, 32)),
        rdp_domain=dict(type='str'),
        rdp_enable_drive=dict(type='bool', default=False),
        rdp_drive_name=dict(type='str'),
        rdp_drive_path=dict(type='str'),
        rdp_enable_full_window_drag=dict(type='bool', default=True),
        rdp_ignore_server_certs=dict(type='bool', required=False),
        rdp_security=dict(type='str', choices=['any', 'nla', 'nla-ext', 'tls', 'rdp'], required=False),
        rdp_server_layout=dict(
            type='str',
            choices=(
                'en-us-qwerty',
                'en-gb-qwerty',
                'de-ch-qwertz',
                'de-de-qwertz',
                'fr-be-azerty',
                'fr-fr-azerty',
                'fr-ch-qwertz',
                'hu-hu-qwertz',
                'it-it-qwerty',
                'ja-jp-qwerty',
                'pt-br-qwerty',
                'es-es-qwerty',
                'es-latam-qwerty',
                'sv-se-qwerty',
                'tr-tr-qwerty',
                'failsafe',
            )
        ),
        rdp_width=dict(type='int'),
        rdp_height=dict(type='int'),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
        max_connections=dict(type='int', required=False),
        max_connections_per_user=dict(type='int'),
        recording_path=dict(type='str', required=False),
        recording_include_keys=dict(type='bool', required=False),
        recording_name=dict(type='str', required=False),
        sftp_enable=dict(type='bool', default=False),
        sftp_port=dict(type='int', required=False),
        sftp_server_alive_interval=dict(type='int', required=False),
        sftp_hostname=dict(type='str', required=False),
        sftp_username=dict(type='str', required=False),
        sftp_password=dict(type='str', required=False, no_log=True),
        sftp_passphrase=dict(type='str', required=False, no_log=True),
        sftp_private_key=dict(type='str', required=False, no_log=True),
        sftp_root_directory=dict(type='str', required=False),
        sftp_default_upload_directory=dict(type='str', required=False),
        ssh_passphrase=dict(type='str', no_log=True),
        ssh_private_key=dict(type='str', no_log=True),
        disable_copy=dict(type='bool', default=False),
        disable_paste=dict(type='bool', default=False),
        cursor=dict(type='str', required=False),
        guacd_hostname=dict(type='str', required=False),
        guacd_port=dict(type='int', required=False),
        guacd_encryption=dict(type='str', required=False),
        read_only=dict(type='bool', default=False),
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

    # get the group numeric ID if we are NOT adding the connection
    # to the default connections group (ROOT)
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

    # Get existing guacamole connections before doing anything else
    try:
        guacamole_connections_before = guacamole_get_connections(
            base_url=module.params.get('base_url'),
            validate_certs=module.params.get('validate_certs'),
            datasource=guacamole_token['dataSource'],
            group=module.params.get('group_name'),
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    # First check if the connection already exists
    # If the connection exists we get the connection_id
    guacamole_connection_exists = False
    for connection in guacamole_connections_before:
        if 'name' in connection:
            if connection['name'] == module.params.get('connection_name'):
                guacamole_connection_exists = True
                connection_id = connection['identifier']
                break

    # module arg state=present so we have to create a new connecion
    # or update a connection if it already exists
    if module.params.get('state') == 'present':

        # populate the payload(json) with the connection info that we
        # will send to the API
        payload = guacamole_populate_connection_payload(module.params)

        # the connection already exists so we update it
        if guacamole_connection_exists:

            try:
                # query what's the current config for this connection so
                # we can check later if it has changed
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
                # apply the config upddate to the connection
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
                # query what's the config for this connection again to
                # verify if it has changed
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
                # if the connection config has changed we report it
                result['changed'] = True
                result['msg'] = 'Connection config has been updated'
            else:
                # if the connection config hasn't changed we just report a msg
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

    # module arg state=absent so we have to delete the connection
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
            group=module.params.get('group_name'),
            auth_token=guacamole_token['authToken'],
        )
    except GuacamoleError as e:
        module.fail_json(msg=str(e))

    if guacamole_connections_before != guacamole_connections_after:
        result['changed'] = True

    for connection in guacamole_connections_after:
        if 'name' in connection:
            if connection['name'] == module.params.get('connection_name'):
                result['connection_info'] = connection
                break

    module.exit_json(**result)


if __name__ == '__main__':
    main()
