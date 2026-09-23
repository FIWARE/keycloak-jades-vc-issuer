package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.JAdESSigningPolicy;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * {@link CredentialBuilder} assembling the JWT claim set of a W3C VC 1.1 credential, following the
 * JWT encoding rules of the VC data model.
 * <p>
 * Credentials whose configuration switched JAdES off are built by Keycloak's own
 * {@link JwtCredentialBuilder} instead, so the built-in behaviour stays reachable per credential type.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESCredentialBuilder implements CredentialBuilder {

    private static final String ID_TEMPLATE = "urn:uuid:%s";
    private static final String VC_CLAIM_KEY = "vc";
    private static final String ID_CLAIM_KEY = "id";

    private final TimeProvider timeProvider;
    private final JwtCredentialBuilder keycloakCredentialBuilder;
    private final JAdESSigningPolicy signingPolicy;

    public JAdESCredentialBuilder(TimeProvider timeProvider, KeycloakSession keycloakSession) {
        this.timeProvider = timeProvider;
        this.keycloakCredentialBuilder = new JwtCredentialBuilder(timeProvider, keycloakSession);
        this.signingPolicy = new JAdESSigningPolicy(keycloakSession);
    }

    /**
     * Returns the credential id of the given credential, or generates a random {@code urn:uuid} one.
     *
     * @param verifiableCredential credential to take the id from
     * @return the credential id to use as {@code jti}
     */
    static String createCredentialId(VerifiableCredential verifiableCredential) {
        return Optional.ofNullable(verifiableCredential.getId())
                .orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())))
                .toString();
    }

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.JWT_VC_JSON;
    }

    @Override
    public CredentialBody buildCredentialBody(VerifiableCredential verifiableCredential,
                                              CredentialBuildConfig credentialBuildConfig)
            throws CredentialBuilderException {

        if (!signingPolicy.isJAdESEnabled(credentialBuildConfig, JAdESCredentialFormat.JWT_VC_JSON)) {
            return keycloakCredentialBuilder.buildCredentialBody(verifiableCredential, credentialBuildConfig);
        }

        // nbf is mandatory, so fall back to the current time when the credential carries no issuance date
        long iat = Optional.ofNullable(verifiableCredential.getIssuanceDate())
                .map(Instant::getEpochSecond)
                .orElse((long) timeProvider.currentTimeSeconds());

        JsonWebToken jsonWebToken = new JsonWebToken()
                .issuer(Optional.ofNullable(verifiableCredential.getIssuer())
                        .map(Object::toString)
                        .orElseThrow(() -> new CredentialBuilderException("The credential has no issuer.")))
                .nbf(iat)
                .id(createCredentialId(verifiableCredential));
        jsonWebToken.setOtherClaims(VC_CLAIM_KEY, verifiableCredential);

        // expiry is optional
        Optional.ofNullable(verifiableCredential.getExpirationDate())
                .ifPresent(expiration -> jsonWebToken.exp(expiration.getEpochSecond()));

        // the subject is only set when the credential subject carries an id
        Optional.ofNullable(verifiableCredential.getCredentialSubject())
                .map(subject -> subject.getClaims().get(ID_CLAIM_KEY))
                .map(Object::toString)
                .ifPresent(jsonWebToken::subject);

        return new JAdESCredentialBody(jsonWebToken);
    }

    @Override
    public void contributeToMetadata(SupportedCredentialConfiguration supportedCredentialConfiguration,
                                     CredentialScopeModel credentialScopeModel) {
        keycloakCredentialBuilder.contributeToMetadata(supportedCredentialConfiguration, credentialScopeModel);
    }
}
