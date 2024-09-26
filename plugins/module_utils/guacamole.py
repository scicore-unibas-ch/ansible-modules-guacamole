#!/usr/bin/python

# Copyright: (c) 2020, Pablo Escobar <pablo.escobarlopez@unibas.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import urlencode

URL_GET_TOKEN = "{url}/api/tokens"
URL_LIST_CONNECTIONS = "{url}/api/session/data/{datasource}/connectionGroups/\
{group}/tree?token={token}"
URL_LIST_CONNECTIONS_GROUPS = "{url}/api/session/data/{datasource}/connectionGroups/?token={token}"
URL_LIST_USERS = "{url}/api/session/data/{datasource}/users?token={token}"


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


def guacamole_get_connections(base_url, validate_certs, datasource, group, auth_token):
    """
    Return a list of dicts with all the connections registered in the guacamole server
    for the provided connections group and its sub-groups. Default connections group is ROOT
    """

    url_list_connections = URL_LIST_CONNECTIONS.format(
        url=base_url, datasource=datasource, group=group, token=auth_token)

    try:
        connections_group = json.load(open_url(url_list_connections, method='GET',
                                                           validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of connections from %s: %s'
            % (url_list_connections, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole connections from %s: %s'
                             % (url_list_connections, str(e)))


    all_connections = []
    def fetch_child_connections(a_connections_group, depth=0):
        for connection in a_connections_group:
            all_connections.extend(connection.get('childConnections',[]))
            if connection.get('childConnectionGroups') is not None:
                fetch_child_connections(connection.get('childConnectionGroups'), depth = depth + 1)
        if depth == 0:
            return

    fetch_child_connections([connections_group])

    return all_connections


def guacamole_get_connections_group_id(base_url, validate_certs, datasource, group, auth_token):
    """
    Get the group numeric id from the group name.
    When working with a group different of the default one (ROOT) we have to map the group name
    to its numeric identifier because the API expects a group numeric id, not a group name
    """

    # if the group name is an integer we assume it's the group numeric id hardcoded by the user
    # quick&dirty hack for https://github.com/scicore-unibas-ch/ansible-modules-guacamole/issues/27
    if isinstance(group, int):
        return group

    url_list_connections_groups = URL_LIST_CONNECTIONS_GROUPS.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        connections_groups = json.load(open_url(url_list_connections_groups, method='GET',
                                                           validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of connections groups from %s: %s'
            % (url_list_connections_groups, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole connections groups from %s: %s'
                             % (url_list_connections_groups, str(e)))

    # find the numeric id for the group name
    for group_id, group_info in connections_groups.items():
        if group_info['name'] == group:
            group_numeric_id = group_info['identifier']

    try:
        group_numeric_id
    except NameError:
        raise GuacamoleError(
            'Could not find the numeric id for connections group %s. Does the group exists?' % (group))
    else:
        return group_numeric_id


def guacamole_get_connections_groups(base_url, validate_certs, datasource, auth_token):
    """
    Returns a dict of dicts.
    Each dict provides the details for one of the connections groups defined in guacamole
    """

    url_list_connections_groups = URL_LIST_CONNECTIONS_GROUPS.format(
        url=base_url, datasource=datasource, token=auth_token)

    try:
        connections_groups = json.load(open_url(url_list_connections_groups, method='GET',
                                                validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain connections groups from %s: %s'
            % (url_list_connections_groups, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain connections groups from %s: %s'
                             % (url_list_connections_groups, str(e)))

    return connections_groups


def guacamole_get_users(base_url, validate_certs, datasource, auth_token):
    """
    Returns a dict with all the users registered in the guacamole server
    """

    url_list_users = URL_LIST_USERS.format(url=base_url, datasource=datasource, token=auth_token)

    try:
        guacamole_users = json.load(open_url(url_list_users, method='GET', validate_certs=validate_certs))
    except ValueError as e:
        raise GuacamoleError(
            'API returned invalid JSON when trying to obtain list of users from %s: %s'
            % (url_list_users, str(e)))
    except Exception as e:
        raise GuacamoleError('Could not obtain list of guacamole users from %s: %s'
                             % (url_list_users, str(e)))

    return guacamole_users
