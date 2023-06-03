# scicore.guacamole.guacamole_inventory – Apache Guacamole dynamic inventory plugin

What would you say about getting all your connections details from Apache Guacamole and passing them to Ansible as inventory ? It would be amazing, right ? 

Guess what, You are in the right place. It's all about this plugin.

> **Note**
>This inventory plugin is part of the scicore.guacamole collection (version 0.0.19).
>
>To install it, use: `ansible-galaxy collection install scicore.guacamole`.
>
>To use it in a playbook, specify: `scicore.guacamole.guacamole_inventory`.
> In Apache Guacamole world, **connection** is the word used for a server. In Ansible world, it's **host**. So all over this documentation, **connection** and **host** mean the same thing.
>

## Synopsis

- Get connection details from Apache Guacamole API and pass them to ansible as inventory.
- Uses an YAML configuration file ending with either `guacamole.yml` or `guacamole.yaml` to set parameter values.

## Requirements

The below requirements are needed on the local controller node that executes this inventory.

- python >= 2.7
- The host that executes this module must have the scicore.guacamole collection installed via galaxy

## Parameters
```yaml
    plugin:
        description: Token that ensures this is a source file for the 'guacamole_inventory' plugin.
        type: string
        required: true
        choices: [ scicore.guacamole.guacamole_inventory ]
    base_url:
        description:
          - URL of the Apache Guacamole instance.
          - It is recommended to use HTTPS so that the username/password are not
            transferred over the network unencrypted.
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
          - 'ROOT' will include all connections from Guacamole instance.
        type: list
        elements: str
        default: ["ROOT"]
    validate_certs:
        description:
            - Validate ssl certs?
        default: true
        type: bool
```
## Examples

```yaml
# sample 'myhosts.guacamole.yaml'
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
```

> **Warning**:
> This plugin handles ssh connections only.
> VNC and RDP hosts won't be listed by this plugin.
> Ansible and ssh protocol don't support ssh key as string variable.
> For hosts using private-key, they will use `~/.ssh/id_rsa` as default key file.
