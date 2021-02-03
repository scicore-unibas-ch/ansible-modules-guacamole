#!/usr/bin/python
# -*- coding: utf-8 -*-

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
module: guacamole_usergroup

short_description: Administer guacamole user groups using the rest API

version_added: "2.9"

description:
    - "Add or remove guacamole user groups."
    - "Check mode and diff mode are supported."
    - "You can create/delete groups and add/remove members and permissions."
    - "The other Guacamole API functionality is not yet implemented."

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

    group_name:
        description:
            - Name of usergroup to crud
        required: true
        type: str

    permissions:
        description:
            - List of guacamole system permissions for this group
        type: list
        elements: str

#    connections:
#        description:
#            - List of connections in this group (not yet implemented)
#        type: list
#        elements: str

    users:
        description:
            - List of members in this group
        type: list
        elements: str

    state:
        description:
            - Create or delete the user group
        default: 'present'
        type: str
        choices:
            - present
            - absent

author:
    - Pablo Escobar Lopez (@pescobar)
    - Philipp Berndt (@pberndt)
'''

EXAMPLES = '''

- name: Create a new group "lab_3"
  scicore.guacamole.guacamole_usergroup:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    group_name: lab_3
    permissions:
      - CREATE_CONNECTION
      - CREATE_SHARING_PROFILE
    users:
      - john
      - laura

- name: Delete user group "developers"
  scicore.guacamole.guacamole_usergroup:
    base_url: http://localhost/guacamole
    auth_username: guacadmin
    auth_password: guacadmin
    group_name: developers
    state: absent
'''

RETURN = '''
usergroup_info:
    description: Information about the created or updated group
    type: dict
    returned: always
message:
    description: Some extra info about what the module did
    type: str
    returned: always
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.scicore.guacamole.plugins.module_utils.guacamole import GuacamoleError, \
    guacamole_get_token, guacamole_get_connections, guacamole_get_connections_group_id

import json

URL_USERGROUPS = "{url}/api/session/data/{datasource}/userGroups?token={token}"
URL_USERGROUP = "{url}/api/session/data/{datasource}/userGroups/{group_name}?token={token}"
URL_USERGROUP_PERMISSIONS = "{url}/api/session/data/{datasource}/userGroups/{group_name}/permissions?token={token}"
URL_USERGROUP_MEMBERS = "{url}/api/session/data/{datasource}/userGroups/{group_name}/memberUsers?token={token}"

GUACAMOLE_USERGROUP_ARG_SPEC = {
    'base_url': {'type': 'str', 'aliases': ['url'], 'required': True},
    'auth_username': {'type': 'str', 'required': True},
    'auth_password': {'type': 'str', 'required': True, 'no_log': True},
    'validate_certs': {'type': 'bool', 'default': True},
    'group_name': {'type': 'str', 'required': True},
    'users': {'type': 'list'},
    'permissions': {'type': 'list'},
    # 'connections': {'type': 'list'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent']
    }
}


class GuacamoleUserGroupModule(AnsibleModule):
    def __init__(self):
        AnsibleModule.__init__(self,
                               argument_spec=GUACAMOLE_USERGROUP_ARG_SPEC,
                               supports_check_mode=True
                               )

        self.base_url = self.params.get('base_url')
        self.auth_username = self.params.get('auth_username')
        self.auth_password = self.params.get('auth_password')
        self.validate_certs = self.params.get('validate_certs')
        self.result = dict(changed=False, msg='', usergroup_info={})

    def execute_module(self):
        state = self.params.get('state')
        group_name = self.params.get('group_name')

        # Log in
        guacamole_token = guacamole_get_token(
            base_url=self.base_url,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            validate_certs=self.validate_certs
        )
        self.datasource = guacamole_token['dataSource']
        self.auth_token = guacamole_token['authToken']

        # Get status quo of usergroup
        self.group_before = self.guacamole_get_usergroup(group_name)

        if self.params.get('state') == 'present':
            self.create_or_update_usergroup(group_name, self.group_before)
        elif self.params.get('state') == 'absent':
            if self.group_before:
                if not self.check_mode:
                    self.guacamole_delete_usergroup(group_name)
                self.result['changed'] = True

        return self.result

    def create_or_update_usergroup(self, group_name, group_before):
        # If the group doesn't exists, we add it
        if not group_before:
            if not self.check_mode:
                self.guacamole_add_usergroup(group_name)
            self.result['changed'] = True

        group_after = {
            "identifier": group_name,
            "attributes": {
                "disabled": None
            }
        }

        # Update usergroup members
        if group_before:
            current_members = set(self.guacamole_get_usergroup_members(group_name))
            group_before['users'] = sorted(current_members)
        else:
            current_members = set()

        nominal_members = set(self.params.get('users'))
        group_after["users"] = sorted(nominal_members)
        additions = [{'op': 'add', 'path': '/', 'value': username} for username in
                     nominal_members - current_members]
        removals = [{'op': 'remove', 'path': '/', 'value': username} for username in
                    current_members - nominal_members]
        actions = additions + removals
        if actions:
            if not self.check_mode:
                self.guacamole_update_usergroup_members(group_name, actions)
            self.result['changed'] = True

        # Guacamole permissions API allows us to perform many
        # permission related changes in one go. Get the current state first.
        if group_before:
            current_permissions = self.guacamole_get_usergroup_permissions(group_name)
            group_before['permissions'] = current_permissions
        else:
            current_permissions = {
                'activeConnectionPermissions': {},
                'connectionGroupPermissions': {},
                'connectionPermissions': {},
                'sharingProfilePermissions': {},
                'systemPermissions': {},
                'userGroupPermissions': {},
                'userPermissions': {}
            }
        permission_actions = []
        group_after["permissions"] = dict(current_permissions)

        # Update permissions (a.k.a. Guacamole systemPermissions)
        actual_sysperms = set(current_permissions['systemPermissions'])
        nominal_sysperms = set(self.params.get('permissions'))
        group_after["permissions"]["systemPermissions"] = sorted(nominal_sysperms)
        additions = [{'op': 'add', 'path': '/systemPermissions', 'value': perm} for perm in
                     nominal_sysperms - actual_sysperms]
        permission_actions.extend(additions)
        removals = [{'op': 'remove', 'path': '/systemPermissions', 'value': perm} for perm in
                    actual_sysperms - nominal_sysperms]
        permission_actions.extend(removals)

        # TODO: Add connectionPermissions here
        # TODO: Add connectionGroupPermissions here
        # TODO: Add sharingProfilePermissions here
        # TODO: Add activeConnectionPermissions here
        # TODO: Add userPermissions here
        # TODO: Add userGroupPermissions here

        # Send all permission changes to Guacamole
        if permission_actions:
            if not self.check_mode:
                self.guacamole_update_usergroup_permissions(group_name, permission_actions)
            self.result['changed'] = True

        if self._diff:
            self.result['diff'] = {
                'before': group_before,
                'after': group_after
            }
        self.result['usergroup_info'] = group_after
        return self.result

    # GUACAMOLE API Methods
    # TODO: All guacamole API functions/methods should be refactored into a GuacamoleClient class and
    #       be separated from Ansible specific code. I left the guacamole_ prefix there,
    #       so they are easier to spot, but have already replaced
    #       the base_url, validate_certs, datasource, auth_token args by member variables.

    # Not used
    def guacamole_get_usergroups(self):
        """
        Returns a dict of dicts.
        Each dict provides the name and state (enabled/disabled) for each usergroup
        """
        url_list_user_groups = URL_USERGROUPS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token)

        try:
            user_groups = json.load(open_url(url_list_user_groups, method='GET',
                                             validate_certs=self.validate_certs))
        except ValueError as e:
            raise GuacamoleError(
                'API returned invalid JSON when trying to obtain usergroups from %s: %s'
                % (url_list_user_groups, str(e)))
        except Exception as e:
            raise GuacamoleError('Could not obtain usergroups from %s: %s'
                                 % (url_list_user_groups, str(e)))
        return user_groups

    def guacamole_get_usergroup(self, group_name):
        """
        Returns a dict.
        The dict provides the name and state (enabled/disabled) for the usergroup
        """
        url_get_user_group = URL_USERGROUP.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            user_group = json.load(open_url(url_get_user_group, method='GET',
                                            validate_certs=self.validate_certs))
        except ValueError as e:
            raise GuacamoleError(
                'API returned invalid JSON when trying to obtain usergroups from %s: %s'
                % (url_list_user_groups, str(e)))
        except Exception as e:
            if e.code == 404:
                return None
            raise GuacamoleError('Could not obtain usergroups from %s: %s'
                                 % (url_list_user_groups, str(e)))
        return user_group

    def guacamole_add_usergroup(self, group_name):
        """
        Add a user group
        """
        url_add_group = URL_USERGROUPS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token)

        payload = {
            "identifier": group_name,
            "attributes": {
                "disabled": ""
            }
        }

        try:
            headers = {'Content-Type': 'application/json'}
            open_url(url_add_group, method='POST', validate_certs=self.validate_certs, headers=headers,
                     data=json.dumps(payload))
        except Exception as e:
            # if the group exists we get a http code 400
            if e.code == 400:
                pass
                #  raise GuacamoleError('Group %s already exists.' % group_name)
            else:
                raise GuacamoleError('Could not add usergroup. Error msg: %s' % str(e))

    def guacamole_delete_usergroup(self, group_name):
        """
        Delete a user group
        """
        url_delete_group = URL_USERGROUP.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            headers = {'Content-Type': 'application/json'}
            open_url(url_delete_group, method='DELETE', validate_certs=self.validate_certs, headers=headers)
        except Exception as e:
            raise GuacamoleError('Could not delete usergroup. Error msg: %s' % str(e))

    def guacamole_get_usergroup_members(self, group_name):
        """
        Returns a dict of arrays
        with the keys being the permission categories defined in guacamole
        """
        url_get_usergroup_members = URL_USERGROUP_MEMBERS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            group_members = json.load(open_url(url_get_usergroup_members, method='GET',
                                               validate_certs=self.validate_certs))
        except ValueError as e:
            raise GuacamoleError(
                'API returned invalid JSON when trying to obtain group members from %s: %s'
                % (url_get_usergroup_members, str(e)))
        except Exception as e:
            raise GuacamoleError('Could not obtain usergroup members from %s: %s'
                                 % (url_get_usergroup_members, str(e)))
        return group_members

    def guacamole_update_usergroup_members(self, group_name, actions):
        """
        Add and/or remove a users to/from a usergroup.
        """
        url_update_usergroup_members = URL_USERGROUP_MEMBERS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            headers = {'Content-Type': 'application/json'}
            open_url(url_update_usergroup_members, method='PATCH', validate_certs=self.validate_certs, headers=headers,
                     data=json.dumps(actions))
        except Exception as e:
            raise GuacamoleError('Could not update usergroup members for group %s in url %s. Error msg: %s'
                                 % (group_name, url_update_usergroup_members, str(e)))

    def guacamole_get_usergroup_permissions(self, group_name):
        """
        Returns a dict of arrays
        with the keys being the permission categories defined in guacamole
        """
        url_get_user_group_permissions = URL_USERGROUP_PERMISSIONS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            group_permissions = json.load(open_url(url_get_user_group_permissions, method='GET',
                                                   validate_certs=self.validate_certs))
        except ValueError as e:
            raise GuacamoleError(
                'API returned invalid JSON when trying to obtain usergroup permissions from %s: %s'
                % (url_get_user_group_permissions, str(e)))
        except Exception as e:
            raise GuacamoleError('Could not obtain usergroup permissions from %s: %s'
                                 % (url_get_user_group_permissions, str(e)))
        # Sorting is just for diff mode
        sorted_permissions = {k: sorted(group_permissions[k]) for k in sorted(group_permissions)}
        return sorted_permissions

    def guacamole_update_usergroup_permissions(self, group_name, actions):
        """
        Update permissions for a usergroup.
        Actions must be a list of "add" or "remove" records, see API
        """
        url_update_usergroup_permissions = URL_USERGROUP_PERMISSIONS.format(
            url=self.base_url, datasource=self.datasource, token=self.auth_token, group_name=group_name)

        try:
            headers = {'Content-Type': 'application/json'}
            open_url(url_update_usergroup_permissions, method='PATCH', validate_certs=self.validate_certs,
                     headers=headers,
                     data=json.dumps(actions))
        except Exception as e:
            raise GuacamoleError('Could not update usergroup permissions for group %s in url %s. Error msg: %s'
                                 % (group_name, url_update_usergroup_permissions, str(e)))


def main():
    try:
        module = GuacamoleUserGroupModule()
        result = module.execute_module()
        module.exit_json(**result)
    except GuacamoleError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
