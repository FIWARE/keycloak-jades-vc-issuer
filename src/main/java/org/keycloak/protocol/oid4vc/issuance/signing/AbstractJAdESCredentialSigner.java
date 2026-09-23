package org.keycloak.protocol.oid4vc.issuance.signing;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.jades.JAdESCompactSigner;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

import java.io.IOException;

/**
 * Shared base of the JAdES credential signers: resolves the realm key and drives the DSS signature.
 * <p>
 * The concrete signers differ only in the payload they extract from the credential body, the {@code typ}
 * they ask for, and the Keycloak signer they fall back to when JAdES is switched off for a credential.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public abstract class AbstractJAdESCredentialSigner extends AbstractCredentialSigner<String> {

    private static final Logger LOGGER = Logger.getLogger(AbstractJAdESCredentialSigner.class);

    private final JAdESCompactSigner jadesCompactSigner;

    protected AbstractJAdESCredentialSigner(KeycloakSession keycloakSession, DigestAlgorithm digestAlgorithm,
                                            boolean includeSignatureType) {
        super(keycloakSession);
        this.jadesCompactSigner = new JAdESCompactSigner(digestAlgorithm, includeSignatureType);
    }

    /**
     * Signs the given payload as a JAdES baseline-B compact JWS with the credential's realm key.
     *
     * @param payload               payload to sign, serialized as JSON
     * @param credentialBuildConfig build config naming the key and algorithm to use
     * @param signatureType         value for the {@code typ} header, or {@code null} to let DSS decide
     * @return the compact JAdES JWS
     */
    protected String signAsJAdES(byte[] payload, CredentialBuildConfig credentialBuildConfig, String signatureType) {
        KeyWrapper signingKey = resolveSigningKey(credentialBuildConfig);
        try {
            return jadesCompactSigner.sign(payload, signingKey, signatureType);
        } catch (IOException e) {
            throw new CredentialSignerException("Error when writing the signed document to the output stream.", e);
        }
    }

    /**
     * Resolves the realm key to sign with. {@code overrideKeyId} lets the realm advertise a different
     * {@code kid} than the one the key is stored under, which is what the DID-based setups rely on.
     */
    private KeyWrapper resolveSigningKey(CredentialBuildConfig credentialBuildConfig) {
        String signingKeyId = credentialBuildConfig.getSigningKeyId();
        String signingAlgorithm = credentialBuildConfig.getSigningAlgorithm();
        String overrideKeyId = credentialBuildConfig.getOverrideKeyId();

        KeyWrapper signingKey = overrideKeyId == null
                ? getKey(signingKeyId, signingAlgorithm)
                : getKeyWithKidSubstitute(signingKeyId, signingAlgorithm, overrideKeyId);

        if (signingKey == null) {
            throw new CredentialSignerException(
                    String.format("No key for id %s and algorithm %s available.", signingKeyId, signingAlgorithm));
        }
        if (signingKey.getCertificateChain() == null || signingKey.getCertificateChain().isEmpty()) {
            throw new CredentialSignerException(
                    String.format("Key %s carries no certificate chain, so no x5c header can be issued.", signingKeyId));
        }

        LOGGER.debugf("Signing credential as JAdES with key %s and algorithm %s.", signingKeyId, signingAlgorithm);
        return signingKey;
    }
}
