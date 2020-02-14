#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: my_test

short_description: This is my test module

version_added: "2.4"

description:
    - "This is my longer description explaining my test module"

options:
    name:
        description:
            - This is the message to send to the test module
        required: true
    new:
        description:
            - Control to demo if the result of this module is changed or not
        required: false

extends_documentation_fragment:
    - azure

author:
    - Your Name (@yourhandle)
'''

EXAMPLES = '''
# Pass in a message
- name: Test with a message
  my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_test:
    name: fail me
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The output message that the test module generates
    type: str
    returned: always
'''

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.urllib.parse import urlencode


URL_TOKEN = "{url}/api/tokens"
URL_LIST_CONNECTIONS = "{url}/api/session/data/{datasource}/connectionGroups/\
{parent_identifier}/tree?token={token}"
URL_ADD_CONNECTION = "{url}/api/session/data/{datasource}/connections?token={token}"


class GuacamoleError(Exception):
    pass


def guacamole_get_token(base_url, validate_certs, auth_username, auth_password):

    url_token = URL_TOKEN.format(url=base_url)
    payload = {
        'username': auth_username,
        'password': auth_password
    }
    try:
        r = json.load(open_url(url_token, method='POST',
                               validate_certs=validate_certs,
                               data=urlencode(payload)))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain access token from %s: %s'
            % (url_token, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain access token from %s: %s'
                             % (url_token, str(e)))
    try:
        return {
            'authToken': r['authToken'],
            'dataSource': r['dataSource'],
        }
    except KeyError:
        raise GuacamoleError(
            'Could not obtain access token from %s' % url_token)


def guacamole_get_connections(base_url, validate_certs, datasource, parent_identifier, auth_token):

    url_list_connections = URL_LIST_CONNECTIONS.format(
        url=base_url, datasource=datasource, parent_identifier=parent_identifier, token=auth_token)

    try:
        r = json.load(open_url(url_list_connections, method='GET',
                               validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of connections from %s: %s'
            % (url_list_connections, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole connections from %s: %s'
                             % (url_list_connections, str(e)))

    return {
        'guacamole_connections': r,
    }


def guacamole_add_connection(base_url, validate_certs, datasource, auth_token, module_params):

    #  print('##################################')
    #  print(module_params['base_url'])
    #  print(module_params.get.hostname)
    #  realm = module.params.get('base_url')

    url_add_connection = URL_ADD_CONNECTION.format(
        url=base_url, datasource=datasource, token=auth_token)

    #  payload = {
    #      'username': 'user1',
    #      'password': 'password1',
    #      'attributes': {
    #          'disabled': '',
    #          'expired': '',
    #          'guac-full-name': 'user_full_name',
    #          'guac-email-address': 'email@mail.com',
    #          'guac-organization': 'scicore',
    #          'guac-organizational-role': 'sysadmin'
    #          }
    #  }
    payload = {
        "parentIdentifier": module_params['parentIdentifier'],
        "name": module_params['connection_name'],
        "protocol": module_params['protocol'],
        "parameters": {
            "hostname": module_params['hostname'],
            "port": module_params['port'],
            "username": module_params['username'],
            "password": module_params['password']
        },
        "attributes": {
            "max-connections": ""
        }
    }

    # print(json.loads(payload))
    #  print(json.dumps(payload))
    #  print(guacamole_add_connection)

    try:
        headers = {'Content-Type': 'application/json'}
        r = open_url(url_add_connection, method='POST', validate_certs=validate_certs,
                 headers=headers, data=json.dumps(payload))
        #  print(r)
    #except urllib_error.HTTPError as e:
        #  print('bbbbbbbbbbbbbbb')
        #  print(r)
    except HTTPError as e:
        # guacamole api returns http error code 400 if connection
        # with the same name already exists
        if e.code == 400:
            return 0
            #  print('We got a 400')
            #  result['changed'] = False
    except Exception as e:
        raise GuacamoleError('Could not add a new connection in %s: %s'
                             % (url_add_connection, str(e)))


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
        max_connections=dict(type='int', default=1),
        state=dict(type='str', choices=['absent', 'present'], default='present')
    )

    result = dict(changed=False, msg='', diff={},
                  proposed={}, existing={}, end_state={})

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    #  print(module.params)

    #  if module.check_mode:
    #      module.exit_json(**result)

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

    #  print(guacamole_connections)


    if module.params.get('state') == 'present':

        #  print(module.params.get('base_url'))
        # Add connection
        try:
            add_connection = guacamole_add_connection(
                base_url=module.params.get('base_url'),
                validate_certs=module.params.get('validate_certs'),
                datasource=guacamole_token['dataSource'],
                auth_token=guacamole_token['authToken'],
                module_params=module.params,
            )
        except GuacamoleError as e:
            module.fail_json(msg=str(e))

        #  print(add_connection.__class__)
        #  print(add_connection)

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

    #  print connection_header
    #  run_module()
    #  result['msg'] = "lalala"
    module.exit_json(**result)


if __name__ == '__main__':
    main()
