#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import urlencode


class GuacamoleError(Exception):
    pass


def guacamole_get_token(base_url, validate_certs, auth_username, auth_password):

    url_token = base_url + "/api/tokens"
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
