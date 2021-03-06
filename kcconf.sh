#!/bin/bash

# ================================================================================
# Request Access Token
# ================================================================================
KC_URI_BASE="http://keycloak:8080/auth"
KC_REALM="master"

KC_CONN_RETRY=1
KC_CONN_RETRY_MAX=255
while [[ "$(curl -D - -s -o /dev/null "${KC_URI_BASE}/" | head -n1 | sed -e 's/[^a-zA-Z0-9\-\ ]*//g' | awk '{print $2}')" != "200" ]] ; do
  if [[ $KC_CONN_RETRY -gt $KC_CONN_RETRY_MAX ]] ; then
    exit 1
  fi

  echo "Wait to retry connection to Keycloak (sleep: ${KC_CONN_RETRY}s)"
  sleep $KC_CONN_RETRY

  KC_CONN_RETRY=$(expr $KC_CONN_RETRY + $KC_CONN_RETRY)
done

KC_ACCESS_TOKEN=$(curl -XPOST -s \
  -d "client_id=admin-cli" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=admin1234" \
  "${KC_URI_BASE}/realms/${KC_REALM}/protocol/openid-connect/token" \
| jq -r ".access_token")

echo "
================================================================================
Requested Access Token
================================================================================
POST ${KC_URI_BASE}/realms/${KC_REALM}/protocol/openid-connect/token
- client_id=admin-cli
- grant_type=password
- username=admin
- password=admin1234
"

# ================================================================================
# Configure SMTP
#
# [Realm Settings] > [Email] tab
#   1. Input `mailhog` to [Host]
#   2. Input `1025` to [Port]
#   3. Input `postmaster@localhost` to [From]
#   4. Click [Save] button
# ================================================================================
curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}" \
  -d '{
    "smtpServer" : {
      "host" : "mailhog",
      "port" : "1025",
      "from" : "postmaster@localhost"
    }
  }'

echo "
================================================================================
Configured SMTP
================================================================================
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}
{
  smtpServer : {
    host : mailhog,
    port : 1025,
    from : postmaster@localhost
  }
}
"

# ================================================================================
# Configure Authentication Flow (Browser)
#
# [Authentication] > [Flows] tab
#   1. Chose `Browser` in dropdown
#   2. Click [Copy] button
#   3. Input `browserWithNewBrowserVerify` to [New Name]
#   4. Chose `BrowserWithNewBrowserVerify` in dropdown
#   5. Click [Actions] > [Add execution] in `BrowserWithNewBrowserVerify Forms` row
#   6. Chose `Verify New Browser` in dropdown on  [Provider] section
#   7. Click [Save] button
#   8. Chose [REQUIRED] in `Verify New Browser` row
# ================================================================================
KC_AUTHN_FLOW_ALIAS="browser"
KC_AUTHN_FLOW_ALIAS_NEW="browserWithNewBrowserVerify"

curl -s -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS}/copy" \
  -d "{
    \"newName\" : \"${KC_AUTHN_FLOW_ALIAS_NEW}\"
  }"

# Add execution to flow
KC_AUTHN_FLOW_EXEC_ID=$(curl -D - -s -o /dev/null -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}%20forms/executions/execution" \
  -d '{
    "provider" : "verify-new-browser-authenticator"
  }' \
| grep -E '^Location:' | sed -e 's/Location:.*\///g' | sed -e 's/[^a-zA-Z0-9\-]*//g')

# Update execution requirement to REQUIRED
KC_AUTHN_FLOW_ID=$(curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}/executions" \
  -d "{
    \"id\" : \"${KC_AUTHN_FLOW_EXEC_ID}\",
    \"requirement\":\"REQUIRED\"
  }" \
| jq -r '.id')

echo "
================================================================================
Configured Authentication Flow (Browser)
================================================================================
POST ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS}/copy
{
  newName : ${KC_AUTHN_FLOW_ALIAS_NEW}
}
POST ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}%20forms/executions/execution
{
  provider : verify-new-browser-authenticator
}
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}/executions
{
  id : ${KC_AUTHN_FLOW_EXEC_ID},
  requirement : REQUIRED
}
"

# ================================================================================
# Configure Authentication Flow to Client (account-console)
#
# [Clients] > `account-console` link in [Lookup] tab > [Authentication Flow Overrides] in [Settings] tab
#   1. Chose `browserWithNewBrowserVerify` in dropdown on [Browser Flow] section
#   2. Click [Save] button
# ================================================================================
KC_CLIENT_ID=$(curl -s -XGET \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/clients" \
| jq -r '.[] | select(.clientId == "account-console") | .id')

curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/clients/${KC_CLIENT_ID}" \
  -d "{
    \"authenticationFlowBindingOverrides\" : {
      \"browser\" : \"${KC_AUTHN_FLOW_ID}\"
    }
  }"

echo "
================================================================================
Configured Authentication Flow to Client (account-console)
================================================================================
GET ${KC_URI_BASE}/admin/realms/${KC_REALM}/clients
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}/clients/${KC_CLIENT_ID}
{
  authenticationFlowBindingOverrides : {
    browser : ${KC_AUTHN_FLOW_ID}
  }
}
"

# ================================================================================
# Configure Authentication Flow (Registration)
#
# [Authentication] > [Flows] tab
#   1. Chose `Registration` in dropdown
#   2. Click [Copy] button
#   3. Input `registrationWithNewBrowser` to [New Name]
#   4. Chose `RegistrationWithNewBrowser` in dropdown
#   5. Click [Actions] > [Add execution] in `RegistrationWithNewBrowser Registration Form` row
#   6. Chose `New Browser` in dropdown on  [Provider] section
#   7. Click [Save] button
#   8. Chose [REQUIRED] in `New Browser` row
# ================================================================================
KC_AUTHN_FLOW_ALIAS="registration"
KC_AUTHN_FLOW_ALIAS_NEW="registrationWithNewBrowser"

curl -s -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS}/copy" \
  -d "{
    \"newName\" : \"${KC_AUTHN_FLOW_ALIAS_NEW}\"
  }"

# Add execution to flow
KC_AUTHN_FLOW_EXEC_ID=$(curl -D - -s -o /dev/null -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}%20registration%20form/executions/execution" \
  -d '{
    "provider" : "registration-new-browser-action"
  }' \
| grep -E '^Location:' | sed -e 's/Location:.*\///g' | sed -e 's/[^a-zA-Z0-9\-]*//g')

# Update execution requirement to REQUIRED
KC_AUTHN_FLOW_ID=$(curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}/executions" \
  -d "{
    \"id\" : \"${KC_AUTHN_FLOW_EXEC_ID}\",
    \"requirement\":\"REQUIRED\"
  }" \
| jq -r '.id')

echo "
================================================================================
Configured Authentication Flow (Registration)
================================================================================
POST ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS}/copy
{
  newName : ${KC_AUTHN_FLOW_ALIAS_NEW}
}
POST ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}%20forms/executions/execution
{
  provider : registration-new-browser-action
}
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}/authentication/flows/${KC_AUTHN_FLOW_ALIAS_NEW}/executions
{
  id : ${KC_AUTHN_FLOW_EXEC_ID},
  requirement : REQUIRED
}
"

# ================================================================================
# Configure Registration Flow Bindings
#
# [Authentication] > [Bindings] tab
#   1. Chose `registrationWithNewBrowser` in Registration Flow dropdown
#   2. Click [Save] button
# ================================================================================
curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}" \
  -d "{
    \"registrationFlow\" : \"${KC_AUTHN_FLOW_ALIAS_NEW}\"
  }"

echo "
================================================================================
Configured Registration Flow Bindings
================================================================================
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}
{
  registrationFlow : ${KC_AUTHN_FLOW_ALIAS_NEW}
}
"

# ================================================================================
# Configure User registration to Enable in Login
#
# [Realm Settings] > [Login] tab
#   1. Switch [User registration] toggle to `ON`
#   2. Click [Save] button
# ================================================================================
curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}" \
  -d '{
    "registrationAllowed" : true
  }'

echo "
================================================================================
Configured User registration to Enable in Login
================================================================================
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}
{
  registrationAllowed : true
}"

# ================================================================================
# Configured Users
# ================================================================================
KC_USER_ID_ADMIN=$(curl -s -XGET \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/users" \
  -d "username=admin" \
| jq -r ".[0].id")

curl -s -XPUT \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/users/${KC_USER_ID_ADMIN}" \
  -d '{
    "email"         : "admin@localhost",
    "firstName"     : "Alice",
    "lastName"      : "Admin",
    "emailVerified" : true
  }'

curl -s -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  -H "Authorization: bearer ${KC_ACCESS_TOKEN}" \
  "${KC_URI_BASE}/admin/realms/${KC_REALM}/users" \
  -d '{
    "username"      : "user",
    "email"         : "user@localhost",
    "firstName"     : "Bob",
    "lastName"      : "User",
    "enabled"       : true,
    "emailVerified" : true,
    "credentials" : [{
      "type"        : "password",
      "temporary"   : false,
      "value"       : "user1234"
    }]
  }'

echo "
================================================================================
Configured Users
================================================================================
GET ${KC_URI_BASE}/admin/realms/${KC_REALM}/users
- username=admin
PUT ${KC_URI_BASE}/admin/realms/${KC_REALM}/users/${KC_USER_ID_ADMIN}
{
  email         : admin@localhost,
  firstName     : Alice,
  lastName      : Admin,
  emailVerified : true
}
POST ${KC_URI_BASE}/admin/realms/${KC_REALM}/users
{
  username      : user,
  email         : user@localhost,
  firstName     : Bob,
  lastName      : User,
  enabled       : true,
  emailVerified : true,
  credentials : [{
    type        : password,
    temporary   : false,
    value       : user1234
  }]
}
"
