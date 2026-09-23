package org.keycloak.protocol.oid4vc.issuance.signing;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JAdESCredentialBody;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * {@link CredentialSigner} for the {@code jwt_vc_json} format, producing a JAdES JWS as specified by
 * ETSI TS 119 182-1.
 * <p>
 * Credentials whose configuration switched JAdES off arrive as Keycloak's own credential body and are
 * passed to Keycloak's {@link JwtCredentialSigner} unchanged, so the built-in behaviour stays available
 * per credential type.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESCredentialSigner extends AbstractJAdESCredentialSigner {

    /**
     * The W3C jwt-vc data model does not ask for a {@code typ}, and RFC 7515 makes it optional, so the
     * header is left to the {@code includeSignatureType} setting rather than forced to a value.
     */
    private static final String NO_FORCED_SIGNATURE_TYPE = null;

    private final JwtCredentialSigner keycloakCredentialSigner;

    public JAdESCredentialSigner(KeycloakSession keycloakSession, DigestAlgorithm digestAlgorithm,
                                 boolean includeSignatureType) {
        super(keycloakSession, digestAlgorithm, includeSignatureType);
        this.keycloakCredentialSigner = new JwtCredentialSigner(keycloakSession);
    }

    @Override
    public String signCredential(CredentialBody credentialBody, CredentialBuildConfig credentialBuildConfig)
            throws CredentialSignerException {

        if (!(credentialBody instanceof JAdESCredentialBody jAdESCredentialBody)) {
            // JAdES is disabled for this credential configuration - the builder produced a Keycloak body
            return keycloakCredentialSigner.signCredential(credentialBody, credentialBuildConfig);
        }

        byte[] payload;
        try {
            payload = JsonSerialization.writeValueAsString(jAdESCredentialBody.getJsonWebToken())
                    .getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new CredentialSignerException("Error when serializing data to be signed.", e);
        }

        return signAsJAdES(payload, credentialBuildConfig, NO_FORCED_SIGNATURE_TYPE);
    }
}
