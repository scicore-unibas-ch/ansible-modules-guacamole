#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Contributor to the scicore.guacamole collection, Kenneth KOFFI (@theko2fi)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.errors import AnsibleParserError
from ansible.module_utils.parsing.convert_bool import boolean
import os
from ansible_collections.scicore.guacamole.plugins.module_utils import guacamole
from ansible_collections.scicore.guacamole.plugins.modules.guacamole_connection import guacamole_get_connection_details


DOCUMENTATION = r'''
    name: scicore.guacamole.guacamole_inventory
    author: Kenneth KOFFI (@theko2fi)
    short_description: Ansible dynamic inventory plugin for Apache Guacamole
    version_added: "2.10.8"
    extends_documentation_fragment:
        - constructed
    description:
        - Get all your connections details from Apache Guacamole API and parse them to ansible as inventory.
        - Uses an YAML configuration file ending with either I(guacamole.yml) or I(guacamole.yaml) to set parameter values.
    options:
        plugin:
            description: Token that ensures this is a source file for the 'guacamole_inventory' plugin.
            type: string
            required: true
            choices: [ scicore.guacamole.guacamole_inventory ]
        base_url:
            description:
              - URL of the Apache Guacamole instance.
              - It is recommended to use HTTPS so that the username/password are not transferred over the network unencrypted.
            required: true
            type: string
        auth_username:
            description: the username to authenticate against the Apache Guacamole API
            type: string
            default: guacadmin
            env:
              - name: GUACAMOLE_USER
        auth_password:
            description: the password to authenticate against the Apache Guacamole API
            type: string
            default: guacadmin
            env:
              - name: GUACAMOLE_PASSWORD
        selected_connection_groups:
            description:
              - A list of connection group names to search for connections.
              - “ROOT” will include all connections on the Guacamole instance.
            type: list
            elements: str
            default: ["ROOT"]
        validate_certs:
            description:
                - Validate ssl certs ?
            default: true
            type: bool
    notes:
        - This plugin only treat ssh connections.
        - VNC and RDP hosts won't be listed by this plugin.
        - Ansible and ssh protocol doesn't support ssh key as string variable.
        - For hosts using private-key, they will use I(~/.ssh/id_rsa) as default key file.
'''


EXAMPLES = '''
# sample 'myhosts.guacamole.yaml' file
# required for all guacamole_inventory inventory plugin configs
plugin: scicore.guacamole.guacamole_inventory

# places a host in the named group if the associated condition evaluates to true
groups:
  # since this will be true for every host, every host sourced from this inventory plugin config will be in the
  # group 'all_the_hosts'
  all_the_hosts: true
  # if the connection's "name" variable contains "webserver", it will be placed in the 'web_hosts' group
  web_hosts: "'webserver' in name"

# adds variables to each host found by this inventory plugin, whose values are the result of the associated expression
compose:
  my_host_var:
  # A statically-valued expression has to be both single and double-quoted, or use escaped quotes, since the outer
  # layer of quotes will be consumed by YAML. Without the second set of quotes, it interprets 'staticvalue' as a
  # variable instead of a string literal.
  some_statically_valued_var: "'staticvalue'"
  # In this case, the variable we_come_from_guacamole with value 'yes' will be added to all host listed by this plugin.
  we_come_from_guacamole: "'yes'"
  # overrides the default ansible_ssh_private_key_file value with a custom path.
  ansible_ssh_private_key_file: /path/to/my/secondkey/id_rsa
 
# places hosts in dynamically-created groups based on a variable value.
keyed_groups:
# places each connection which uses the same username in a group named 'username_(username value)'
- prefix: username
  key: username
# places each host in a group named 'ssh_port_(port number)', depending on the connection port number
- prefix: ssh_port
  key: port

# fetches connections from an explicit list of connection groups instead of default all (- 'ROOT')
selected_connection_groups:
- databases_servers
- apache_servers
'''

class InventoryModule(BaseInventoryPlugin, Constructable):

    NAME = 'scicore.guacamole.guacamole_inventory'

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('guacamole.yaml', 'guacamole.yml')):
                valid = True
        return valid
    
    def parse(self, inventory, loader, path, cache=True):

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # this method will parse 'common format' inventory sources and
        # update any options declared in DOCUMENTATION as needed
        config = self._read_config_data(path)

        # if NOT using _read_config_data you should call set_options directly,
        # to process any defined configuration for this plugin,
        # if you don't define any options you can skip
        #self.set_options()

        self.guacamole_url=self.get_option('base_url')
        self.guacamole_user=self.get_option('auth_username')
        self.guacamole_password=self.get_option('auth_password')
        self.validate_certs = self.get_option('validate_certs')

        guacamole_token = guacamole.guacamole_get_token(self.guacamole_url, self.validate_certs, self.guacamole_user, self.guacamole_password)

        guacamole_connections = list()
        selected_connection_groups = self.get_option('selected_connection_groups')

        # we only fetch connections from the selected connections groups 
        for connection_group_name in selected_connection_groups:

            if connection_group_name != 'ROOT':
            
                selected_connection_group_id = guacamole.guacamole_get_connections_group_id(
                    self.guacamole_url,
                    self.validate_certs,
                    datasource=guacamole_token['dataSource'],
                    group=connection_group_name,
                    auth_token=guacamole_token['authToken']
                )
            else:
                selected_connection_group_id = 'ROOT'
            
            guacamole_connections.extend(guacamole.guacamole_get_connections(
                self.guacamole_url,
                self.validate_certs,
                datasource=guacamole_token['dataSource'],
                group=selected_connection_group_id,
                auth_token=guacamole_token['authToken']
                )
            )

        
        for connection in guacamole_connections:
            
            # We treat only ssh connections
            if connection.get('protocol') == "ssh":
                try:
                    connection_detail = guacamole_get_connection_details(
                        base_url=self.guacamole_url,
                        validate_certs=self.validate_certs,
                        datasource=guacamole_token['dataSource'],
                        connection_id=connection['identifier'],
                        auth_token=guacamole_token['authToken']
                    )

                    self.inventory.add_host(connection.get('name'))
                    self.inventory.set_variable(connection.get('name'), 'ansible_host', connection_detail['hostname'])
                    self.inventory.set_variable(connection.get('name'), 'ansible_user', connection_detail['username'])

                    # we try to get private-key if a password isn't defined in the connection detail
                    # If the private-key is also missing, we raise an error 
                    try:
                        self.inventory.set_variable(connection.get('name'), 'ansible_password', connection_detail['password'])
                    except KeyError:
                        # if the connection detail contains a private-key, we point ansible_ssh_private_key_file to ~/.ssh/id_rsa file
                        # the ssh protocol doesn't support private-key as string, it requires to be a file
                        if connection_detail.get('private-key') is not None:
                            home_directory = os.path.expanduser('~')
                            self.inventory.set_variable(connection.get('name'), 'ansible_ssh_private_key_file', os.path.join(home_directory, ".ssh", "id_rsa"))
                        else:
                            raise AnsibleParserError('A password or private-key is missing for connection: {}'.format(connection.get('name') ))

                    self.inventory.set_variable(connection.get('name'), 'ansible_port', connection_detail.get('port', "22"))
                    
                    strict = self.get_option('strict')

                    # Add variables created by the user's Jinja2 expressions to the host
                    self._set_composite_vars(self.get_option('compose'), dict(), connection.get('name'), strict=True)

                    connection.update(connection_detail)

                    # The following two methods combine the provided variables dictionary with the latest host variables
                    # Using these methods after _set_composite_vars() allows groups to be created with the composed variables
                    self._add_host_to_composed_groups(self.get_option('groups'), connection, connection.get('name'), strict=strict)
                    self._add_host_to_keyed_groups(self.get_option('keyed_groups'), connection, connection.get('name'), strict=strict)

                except KeyError as kerr:
                    raise AnsibleParserError('A key is missing: {}'.format(str(kerr)))
                except Exception as e:
                    raise AnsibleParserError('An error occured: {}'.format(str(e)))