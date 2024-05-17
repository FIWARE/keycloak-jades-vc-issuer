# Keycloak JAdES VC Issuer

This is a plugin for [Keycloak](https://www.keycloak.org/) to support 
[SIOP-2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) / 
[OIDC4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) 
clients and issue 
[VerifiableCredentials](https://www.w3.org/TR/vc-data-model/) with 
[JAdES Digital Signatures](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf) 
through the [OIDC4VCI-Protocol](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) to compliant wallets.



## Background

[Keycloak](https://www.keycloak.org/) is a well established OpenSource Identity Management System. It's relied on in
numerous environments and serves credentials and secrets to be used in different protocols, for different types of
clients. While a VerifiableCredentials-based decentralized Identity Management does not necessarily require an IDM, a
component to issue credentials to users is required. Since Keycloak already provides capabilities for managing users,
clients and their roles, it's well suited to also serve VerifiableCredentials. Starting with release 25, Keycloak is capable 
of issuing such credentials as experimental feature.

In order to be compatible 
with [eIDAS 2.0](https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation) and 
[did:elsi](https://alastria.github.io/did-method-elsi), Keycloak should be also 
capable to issue credentials 
with [JAdES Digital Signatures](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf). 
The Keycloak JAdES VC Issuer therefor extends Keycloak with such functionality by adding a new provider with ID `jades-jws-signing`. 




## Install

> :warning: Since this is a plugin for Keycloak, having an instance of Keycloak running is a logical precondition.
> See [the official Keycloak-Documentation](https://www.keycloak.org/guides#server) on how to set it up.

### Jar-File

The JAdES VC Issuer is a fully-self-contained provider, thus its jar-file only has to be added to the ```providers```-folder
of Keycloak(typically under ```/opt/keycloak/providers```). Keycloak will automatically pick up the provider at
start-time. The plugin is available as jar-file
through [the github-releases](https://github.com/dwendland/keycloak-jades-vc-issuer/releases).

### OCI-Container

In order to ease the deployment in containerized environments, a container including the jar-file is available
at [quay.io](https://quay.io/repository/dwendland/keycloak-jades-vc-issuer). The container can be used in containerized
environments, to copy the jar file into a Keycloak instance, without having to manipulate the Keycloak-Image itself. 



## Usage

The plugin makes use of the existing classes for 
[OID4VC](https://github.com/keycloak/keycloak/tree/main/services/src/main/java/org/keycloak/protocol/oid4vc) support by 
implementing 
a [VerifiableCredentialsSigningService](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/oid4vc/issuance/signing/VerifiableCredentialsSigningService.java). 
In the realm config, the provider must be configured with ID `jades-jws-signing`, in order to sign credentials with 
JAdES signatures. The same APIs can be used as before.


### Configuration

Following parameters can be configured for the provider in the realm configuration:

| Parameter | Mandatory | Default | Description |
|-----------|-----------|---------|-------------|
| `keyId`   | yes       |         | ID of the Keycloak KeyProvider key used for signing credentials |
| `algorithmType` | yes |         | Algorithm type of the key |
| `tokenType` | yes     |         | Type of the token to be issued |
| `digestAlgorithm`| no | `"SHA256"` | Algorithm used for computing the digest of the data to be signed |




## License

Keycloak JAdES VC Issuer is licensed under the Apache License, Version 2.0. See LICENSE for the full license text.

© 2024 FIWARE Foundation e.V.
