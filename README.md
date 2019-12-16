# OneRealm-MultiTenancy

Deploying AM multi-tenant deployment using One AM realm <br />

Disclaimer of Liability :
=========================
Any sample code, scripts, connectors, or other materials (collectively, “Sample Code”) provided by ForgeRock in connection with ForgeRock’s performance of the Deployment Support Services may be used by Customer solely for purposes of Customer exercising its license to the ForgeRock Software under this Addendum and subject to all restrictions herein (“Purpose”). Unless otherwise specified by ForgeRock, any Sample Code provided by ForgeRock to Customer in source form as part of the Deployment Support Services may be further modified by Customer as required for the Purpose. Any Sample Code provided by ForgeRock under open source license terms will remain subject to the open source license terms under which it is provided. Customer shall not use or combine any open source software with ForgeRock Software in any manner which would subject any ForgeRock Software to any open source license terms. For the avoidance of doubt, any Sample Code provided hereunder is expressly excluded from ForgeRock’s indemnity or support obligations.

Pre-requisites :
================
* Versions used for this project: IG 6.5?, AM 6.5.2.2, DS 6.5.2

DS:
=====================
* Refer DS configs folder: /ds
* Install DS user store: 
```
/opt/forgerock/dsus4/setup directory-server \
          --instancePath /opt/forgerock/dsus4 \
          --rootUserDn "cn=Directory Manager" \
          --rootUserPassword cangetindj \
          --hostname uds.mtservices.com \
          --adminConnectorPort 4344 \
          --ldapPort 4389 \
          --profile am-identity-store \
          --set am-identity-store/amIdentityStoreAdminPassword:cangetindj \
          --set am-identity-store/baseDn:ou=identities,dc=mtservices,dc=com \
          --acceptLicense 
```          
* Import Sample users
```
./import-ldif -h localhost -p 4344 -n amIdentityStore -l users.ldif
```

AM:
=====================
* Refer AM configs folder: /am
* Install AM:
```
install-openam --serverUrl http://login.mtservices.com:8096/am --adminPwd cangetinam --policyAgentPwd camgetinag --acceptLicense --cfgDir /home/forgerock/am12 --cfgStoreAdminPort 9644 --cfgStoreJmxPort 9689 --cfgStorePort 56969 --cookieDomain mtservices.com --userStoreDirMgr uid=am-identity-bind-account,ou=admins,ou=identities,dc=mtservices,dc=com --userStoreDirMgrPwd cangetindj --userStoreHost uds.mtservices.com --userStoreAdminPort 4344 --userStoreType LDAPv3ForOpenDS --userStorePort 4389 --userStoreRootSuffix ou=identities,dc=mtservices,dc=com
```
* Import AM configs:
```
Amster import
```

IG:
=====================
* Refer IG configs folder: /ig



TESTS:
=====================
* SAML endpoints 
http://am651.example.com:8086/am/saml2/jsp/idpSSOInit.jsp?spEntityID=http://login-t1.mtservices.com:8096/am&metaAlias= 	
/employees/idp1&NameIDFormat=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified&binding=HTTP-POST&RelayState=http://login.mtservices.com:8096/am/XUI/?realm=/tenants#profile/details


      
   
        
* * *

The contents of this file are subject to the terms of the Common Development and Distribution License (the License). You may not use this file except in compliance with the License.

You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the specific language governing permission and limitations under the License.

When distributing Covered Software, include this CDDL Header Notice in each file and include the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL Header, with the fields enclosed by brackets [] replaced by your own identifying information: "Portions copyright [year] [name of copyright owner]".

Copyright 2019 ForgeRock AS.

Portions Copyrighted 2019 Charan Mann
