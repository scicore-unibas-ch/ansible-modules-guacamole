# Ansible Collection - scicore.guacamole

Documentation for the collection.


Example playbook:

```

- name: test my new module
  hosts: localhost

  tasks:
  - name: run the new module
    scicore.guacamole.guacamole_connections:
      base_url: http://localhost/guacamole
      validate_certs: false
      auth_username: guacadmin
      auth_password: guacadmin
      connection_name: test_name_1
      protocol: rdp
      parentIdentifier: ROOT
      hostname: 192.168.33.44
      port: 3389
      username: rdp_user
      password: rdp_pass
      max_connections: 1
      state: absent
    register: _info

  - debug:
      var: _info
      
```
