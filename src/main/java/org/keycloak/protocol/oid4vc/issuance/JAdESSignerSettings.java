package org.keycloak.protocol.oid4vc.issuance;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.keycloak.Config;

/**
 * SPI-scope settings shared by the JAdES signer factories.
 * <p>
 * The post-26.4 signer SPI has no per-realm component model, so the two JAdES knobs are read from the
 * SPI scope, e.g. {@code --spi-credential-signer-jwt-vc-json-digest-algorithm=SHA512}. Whether a
 * credential is signed as JAdES at all is a per-credential decision and lives on the client scope
 * instead - see {@link JAdESCredentialFormat#JADES_ENABLED_ATTRIBUTE}.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public abstract class JAdESSignerSettings {

    private static final String DIGEST_ALGORITHM_CONFIG_KEY = "digest-algorithm";
    private static final String INCLUDE_SIGNATURE_TYPE_CONFIG_KEY = "include-signature-type";

    private static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;

    /**
     * Per default DSS sets the {@code typ} header parameter to {@code jose}.
     * See: https://github.com/esig/dss/blob/9ad259927d215fb85eb51b004129b9fc701cf177/dss-jades/src/main/java/eu/europa/esig/dss/jades/signature/JAdESLevelBaselineB.java#L277
     * This is in conflict to the W3C jwt-vc data model: https://www.w3.org/TR/vc-data-model/#jwt-encoding
     * According to RfC7515, the typ parameter is optional: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
     * Therefore disabling the setting of the typ parameter here per default (can be overridden with config).
     * Formats that mandate a specific {@code typ}, such as SD-JWT VC, set it explicitly and ignore this.
     */
    private static final boolean DEFAULT_INCLUDE_SIGNATURE_TYPE = false;

    private DigestAlgorithm digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private boolean includeSignatureType = DEFAULT_INCLUDE_SIGNATURE_TYPE;

    /**
     * Reads the JAdES settings from the factory's SPI scope.
     *
     * @param config scope handed over by Keycloak on startup
     */
    public void init(Config.Scope config) {
        digestAlgorithm = DigestAlgorithm.valueOf(
                config.get(DIGEST_ALGORITHM_CONFIG_KEY, DEFAULT_DIGEST_ALGORITHM.name()));
        includeSignatureType =
                config.getBoolean(INCLUDE_SIGNATURE_TYPE_CONFIG_KEY, DEFAULT_INCLUDE_SIGNATURE_TYPE);
    }

    /**
     * @return digest algorithm to compute the signature with
     */
    protected DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @return whether DSS may write its own {@code typ} header when no type is forced
     */
    protected boolean isIncludeSignatureType() {
        return includeSignatureType;
    }
}
