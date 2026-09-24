package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.JAdESSigningPolicy;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.models.oid4vci.CredentialScopeModel;

/**
 * {@link CredentialBuilder} for the {@code dc+sd-jwt} format.
 * <p>
 * The SD-JWT body itself is always built by Keycloak's {@link SdJwtCredentialBuilder} - selective
 * disclosure is intricate and there is no reason to reimplement it. This builder only decides, per
 * credential configuration, whether the result is wrapped for JAdES signing.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class SdJwtJAdESCredentialBuilder implements CredentialBuilder {

    private final SdJwtCredentialBuilder keycloakCredentialBuilder = new SdJwtCredentialBuilder();
    private final JAdESSigningPolicy signingPolicy;

    public SdJwtJAdESCredentialBuilder(KeycloakSession keycloakSession) {
        this.signingPolicy = new JAdESSigningPolicy(keycloakSession);
    }

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.DC_SD_JWT;
    }

    @Override
    public CredentialBody buildCredentialBody(VerifiableCredential verifiableCredential,
                                              CredentialBuildConfig credentialBuildConfig)
            throws CredentialBuilderException {

        SdJwtCredentialBody credentialBody =
                keycloakCredentialBuilder.buildCredentialBody(verifiableCredential, credentialBuildConfig);

        if (!signingPolicy.isJAdESEnabled(credentialBuildConfig, JAdESCredentialFormat.DC_SD_JWT)) {
            return credentialBody;
        }
        return new SdJwtJAdESCredentialBody(credentialBody);
    }

    @Override
    public void contributeToMetadata(SupportedCredentialConfiguration supportedCredentialConfiguration,
                                     CredentialScopeModel credentialScopeModel) {
        keycloakCredentialBuilder.contributeToMetadata(supportedCredentialConfiguration, credentialScopeModel);
    }
}
