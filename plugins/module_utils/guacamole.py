#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import urlencode

URL_GET_TOKEN = "{url}/api/tokens"
URL_LIST_CONNECTIONS = "{url}/api/session/data/{datasource}/connectionGroups/\
{parent_identifier}/tree?token={token}"


class GuacamoleError(Exception):
    pass


def guacamole_get_token(base_url, validate_certs, auth_username, auth_password):
    """
    Retun a dict with a token to authenticate with the API and a datasource.
    DataSource can be "postgresql" or "mysql" depending on how guacamole is configured.

    Example of what this function returns:
    {
        'authToken': 'AAAAABBBBBCCCCCDDDDD",
        'dataSource': 'postgresql'
    }
    """

    url_get_token = URL_GET_TOKEN.format(url=base_url)

    payload = {
        'username': auth_username,
        'password': auth_password
    }

    try:
        token = json.load(open_url(url_get_token, method='POST',
                                   validate_certs=validate_certs,
                                   data=urlencode(payload)))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain access token from %s: %s'
            % (url_get_token, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain access token from %s: %s'
                             % (url_get_token, str(e)))
    try:
        return {
            'authToken': token['authToken'],
            'dataSource': token['dataSource'],
        }
    except KeyError:
        raise GuacamoleError(
            'Could not obtain access token from %s' % url_get_token)


def guacamole_get_connections(base_url, validate_certs, datasource, parent_identifier, auth_token):
    """
    Return a list of dicts with all the connections registered in the guacamole server
    for the provided parent_identifier. Default parent_identifier is ROOT
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

    if 'childConnections' in parent_identifier_connections:
        return parent_identifier_connections['childConnections']
    else:
        return [{}]
