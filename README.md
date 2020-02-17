# Ansible Collection - scicore.guacamole

Ansible modules to create connections and users using the API

## Installation

Download the ansible collection to the root folder of your playbook:

```
$> cd /path/to/playbook/root/folder

$> ansible-galaxy collection install -p ./collections/ scicore.guacamole
```

Now you can use the modules `guacamole_connection` and `guacamole_user`. Adapt the examples below to your needs.


## Example playbook:

```


- name: Add a guacamole connection and user
  hosts: localhost

  tasks:

    - name: Add a new RDP connection
      scicore.guacamole.guacamole_connection:
        base_url: http://localhost/guacamole
        validate_certs: false
        auth_username: guacadmin
        auth_password: guacadmin
        connection_name: test_connection
        protocol: rdp
        hostname: 192.168.33.43
        port: 3389
        username: rdp_user
        password: rdp_pass
      register: _connection_info
  
    - debug:
        var: _connection_info

    - name: Add a new guacamole user 
      scicore.guacamole.guacamole_user:
        base_url: http://localhost/guacamole
        validate_certs: false
        auth_username: guacadmin
        auth_password: guacadmin
        username: play_user_2
        password: aaaaaaaa
        state: present
        full_name: "John"
        email: "aaaaa@hotmail.com"
        organization: "scicore"
        disabled: false
        allowed_connections:
          - test_connection
      register: _user_info
  
    - debug:
        var: _user_info
      
```
