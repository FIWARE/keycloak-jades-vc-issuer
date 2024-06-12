# Obtaining a credential


## Obtaining a credential via Same-Device flow

This gives an example on how to obtain a credential issued by the plugin via the same-device flow. 

An example `docker-compose.yml` file is provided to spin up a Keycloak instance with the plugin.


### Preparation

First build the plugin using 
```shell
cd <PLUGIN_MAIN_DIR>
mvn clean install
```
from the `keycloak-jades-vc-issuer` main directory.

Within the `docker` directory, create a directory `providers`
```shell
cd doc/docker
mkdir providers
```
and copy the libs from the lib target output directory to the `providers` directory of the docker environment
```shell
cp <PLUGIN_MAIN_DIR>/target/lib/*.jar providers/.
cp <PLUGIN_MAIN_DIR>/target/jades-vc-issuer-*.jar providers/.
```

The directory [./docker/realm_data](./docker/realm_data) already contains an example realm config, loading an example keystore 
[see ./docker/keystore](./docker/keystore) with a self-generated key and self-signed eIDAS certificate 
(+ certificate chain up to a self-signed root CA). 

Now start Keycloak using `docker-compose`:
```shell
docker-compose up -d
```
Keycloak will run at port `8080`. Check the logs, until Keycloak is up and running:
```shell
docker logs keycloak

> [io.quarkus] (main) Keycloak 25.0.0 on JVM (powered by Quarkus 3.8.5) started in 17.656s. Listening on: http://0.0.0.0:8080. Management interface listening on http://0.0.0.0:9000.
```


### Get credential

Below the different curl commands are shown to obtain a credential using the same-device flow. 

Alternatively, a [Postman collection](./postman/get_credential_same-device.postman_collection.json) is provided.

First obtain a token using login via password grant_type:
```shell
curl --location 'http://localhost:8080/realms/oid4vc-test/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=test-user' \
--data-urlencode 'password=test' \
--data-urlencode 'client_secret=pR1d6PbbKeUfJTLDs3ksHeYqdSXt9Udv' \
--data-urlencode 'client_id=login-client'
```
This will return the bearer token in the field `access_token` for this login.

Next, using the bearer token, get the credential offer URI:
```shell
curl --location 'http://localhost:8080/realms/oid4vc-test/protocol/oid4vc/credential-offer-uri?credential_configuration_id=verifiable-credential' \
--header 'Authorization: Bearer <ACCESS_TOKEN_LOGIN>'
```
This will return the credential issuer URI (field: `issuer`) and the nonce (field: `nonce`).

Now get the credential offer using the issuer URI, nonce and bearer token:
```shell
curl --location '<CREDENTIAL_ISSUER_URI>/<CREDENTIAL_ISSUER_NONCE>' \
--header 'Authorization: Bearer <ACCESS_TOKEN_LOGIN>'
```
This will return the code in the field `pre-authorized_code` and the credential issuer (field: `credential_issuer`).

For the next requests, the issuer metadata is required:
```shell
curl --location '<CREDENTIAL_ISSUER>/openid-credential-issuer'
```
This returns the authorization server in the field `authorization_servers`, credential endpoint (field: `credential_endpoint`) 
and the credential format (field `format` for the credential configuration with ID `verifiable-credential`). 

Next is to obtain the OpenID config from the authorization server:
```shell
curl --location '<AUTHORIZATION_SERVER>/.well-known/openid-configuration'
```
which returns the token endpoint (field: `token_endpoint`).

Using the code obtained earlier, obtain an access token from the `token_endpoint`:
```shell
curl --location '<TOKEN_ENDPOINT>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code' \
--data-urlencode 'code=<PRE_AUTHORIZED_CODE>'
```
The access token is returned in the field `access_token`.

Finally, using this access token, the credential can be obtained at the `credential_endpoint` (determined earlier):
```shell
curl --location '<CREDENTIAL_ENDPOINT>' \
--header 'Authorization: Bearer <ACCESS_TOKEN>' \
--header 'Content-Type: application/json' \
--data '{
    "format": "jwt_vc",
    "credential_identifier": "verifiable-credential"
}'
```
The credential is returned in the field `credential`.

