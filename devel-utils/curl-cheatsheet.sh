#!/bin/bash

guacamole_url="http://localhost:8080/guacamole"
guacamole_user="guacadmin"
guacamole_password="guacadmin"
#echo ${guacamole_url}

token_json=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=${guacamole_user}&password=${guacamole_password}" ${guacamole_url}/api/tokens)

guacamole_token=$(echo $token_json | jq -r '.authToken')
echo $guacamole_token
guacamole_datasource=$(echo $token_json | jq -r '.dataSource')
echo $guacamole_datasource

guacamole_connections_urls="${guacamole_url}/api/session/data/${guacamole_datasource}/connectionGroups/ROOT/tree?token=${guacamole_token}"
curl -s $guacamole_connections_urls | jq -C .

guacamole_connections_groups_url="${guacamole_url}/api/session/data/${guacamole_datasource}/connectionGroups/?token=${guacamole_token}"
curl -s $guacamole_connections_groups_url | jq -C .

guacamole_users_url="${guacamole_url}/api/session/data/${guacamole_datasource}/users?token=${guacamole_token}"
curl -s $guacamole_users_url | jq -C .
