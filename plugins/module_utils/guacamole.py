#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError


URL_TOKEN = "{url}/api/tokens"
URL_LIST_USERS = "{url}/api/session/data/{datasource}/users?token={token}"
URL_LIST_CONNECTIONS = "{url}/api/session/data/{datasource}/connectionGroups/\
{parent_identifier}/tree?token={token}"
URL_ADD_CONNECTION = "{url}/api/session/data/{datasource}/connections?token={token}"


class GuacamoleError(Exception):
    pass


def guacamole_argument_spec():
    """
    Returns argument_spec of options common to guacamole_*-modules

    :return: argument_spec dict
    """

    return dict(
        base_url=dict(type='str', aliases=['url'], required=True),
        auth_username=dict(type='str', aliases=['username'], required=True),
        auth_password=dict(type='str', aliases=['password'], required=True,
                            no_log=True),
        validate_certs=dict(type='bool', default=True)
    )


def guacamole_get_token(base_url, validate_certs, auth_username, auth_password):
    token_url = 'http://localhost/guacamole/api/tokens'
    print('token_url')
    payload = {
        'username': auth_username,
        'password': auth_password
    }
    try:
        r = json.load(open_url(token_url, method='POST',
                               validate_certs=validate_certs,
                               data=urlencode(payload)))
        print(r)
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain access token from %s: %s'
            % (token_url, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain access token from %s: %s'
                             % (token_url, str(e)))

    try:
        return {
            'authToken': r['authToken'],
            'dataSource': r['dataSource'],
            'Content-Type': 'application/json'
        }
    except KeyError:
        raise GuacamoleError(
            'Could not obtain access token from %s' % token_url)
