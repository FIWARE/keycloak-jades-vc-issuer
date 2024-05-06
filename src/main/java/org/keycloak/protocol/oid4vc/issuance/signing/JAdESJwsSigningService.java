package org.keycloak.protocol.oid4vc.issuance.signing;

import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;

/**
 * {@link VerifiableCredentialsSigningService} implementing the JAdES JWS format. It returns a string, containing the
 * Signed Credential
 * {@see https://xyz.org}
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESJwsSigningService extends SigningService<String> {

    private static final Logger LOGGER = Logger.getLogger(JAdESJwsSigningService.class);

    private static final String ID_TEMPLATE = "urn:uuid:%s";
    private static final String VC_CLAIM_KEY = "vc";
    private static final String ID_CLAIM_KEY = "id";


    private final SignatureSignerContext signatureSignerContext;
    private final TimeProvider timeProvider;
    private final String tokenType;
    protected final String issuerDid;

    public JAdESJwsSigningService(KeycloakSession keycloakSession, String keyId, String algorithmType,
                                  String tokenType, String issuerDid, TimeProvider timeProvider) {
        super(keycloakSession, keyId, algorithmType);
        this.issuerDid = issuerDid;
        this.timeProvider = timeProvider;
        this.tokenType = tokenType;
        KeyWrapper signingKey = getKey(keyId, algorithmType);
        if (signingKey == null) {
            throw new SigningServiceException(String.format("No key for id %s and algorithm %s available.", keyId, algorithmType));
        }
        SignatureProvider signatureProvider = keycloakSession.getProvider(SignatureProvider.class, algorithmType);
        signatureSignerContext = signatureProvider.signer(signingKey);

        LOGGER.debugf("Successfully initiated the JWT Signing Service with algorithm %s.", algorithmType);
    }

    // retrieve the credential id from the given VC or generate one.
    static String createCredentialId(VerifiableCredential verifiableCredential) {
        return Optional.ofNullable(
                        verifiableCredential.getId())
                .orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())))
                .toString();
    }
}
