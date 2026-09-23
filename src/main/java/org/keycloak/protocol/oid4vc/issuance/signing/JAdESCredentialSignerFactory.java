package org.keycloak.protocol.oid4vc.issuance.signing;

import com.google.auto.service.AutoService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;

/**
 * Provider factory creating {@link JAdESCredentialSigner}s.
 * <p>
 * The post-26.4 signer SPI has no per-realm component model any more, so the two JAdES knobs are read from
 * the SPI scope, e.g. {@code --spi-credential-signer-jwt-vc-json-digest-algorithm=SHA512}.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(CredentialSignerFactory.class)
public class JAdESCredentialSignerFactory implements CredentialSignerFactory {

    private static final String DIGEST_ALGORITHM_CONFIG_KEY = "digest-algorithm";
    private static final String INCLUDE_SIGNATURE_TYPE_CONFIG_KEY = "include-signature-type";

    private static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;
    private static final boolean DEFAULT_INCLUDE_SIGNATURE_TYPE = false;

    private DigestAlgorithm digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private boolean includeSignatureType = DEFAULT_INCLUDE_SIGNATURE_TYPE;

    @Override
    public void init(Config.Scope config) {
        digestAlgorithm = DigestAlgorithm.valueOf(
                config.get(DIGEST_ALGORITHM_CONFIG_KEY, DEFAULT_DIGEST_ALGORITHM.name()));
        includeSignatureType =
                config.getBoolean(INCLUDE_SIGNATURE_TYPE_CONFIG_KEY, DEFAULT_INCLUDE_SIGNATURE_TYPE);
    }

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.JWT_VC_JSON;
    }

    @Override
    public CredentialSigner<String> create(KeycloakSession session) {
        return new JAdESCredentialSigner(session, digestAlgorithm, includeSignatureType);
    }
}
