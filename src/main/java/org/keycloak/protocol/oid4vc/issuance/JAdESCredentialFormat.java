package org.keycloak.protocol.oid4vc.issuance;

import java.util.Map;

/**
 * Credential formats served by the JAdES builder/signer pairs, and the per-credential switch that
 * decides whether a credential is signed as JAdES at all.
 * <p>
 * The plugin registers under Keycloak's own format identifiers and therefore replaces the built-in
 * builder/signer pairs. Keycloak collects credential builders into a map keyed by supported format
 * using {@link java.util.stream.Collectors#toMap}, which rejects duplicate keys - so a second factory
 * for the same format must share the provider id rather than register alongside the built-in one.
 * When JAdES is switched off for a credential, the plugin delegates to Keycloak's own
 * implementation, so the built-in behaviour stays reachable.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public final class JAdESCredentialFormat {

    /**
     * OID4VCI format identifier for W3C VC 1.1 credentials encoded as a JWT.
     */
    public static final String JWT_VC_JSON = "jwt_vc_json";

    /**
     * OID4VCI format identifier for SD-JWT VC, as used by Keycloak since 26.4.
     */
    public static final String DC_SD_JWT = "dc+sd-jwt";

    /**
     * Client-scope attribute selecting the signature style for a single credential configuration,
     * e.g. {@code jades.enabled: "false"} on the {@code user-credential} scope.
     */
    public static final String JADES_ENABLED_ATTRIBUTE = "jades.enabled";

    /**
     * Defaults applied when a credential configuration does not set {@link #JADES_ENABLED_ATTRIBUTE}.
     * <p>
     * {@code jwt_vc_json} defaults to JAdES because Keycloak's own JWT signer writes no {@code x5c}
     * header at all, so an eIDAS deployment would silently lose its certificate chain. {@code dc+sd-jwt}
     * defaults to off because Keycloak already adds {@code x5c} there itself, so JAdES buys only the
     * signing time.
     * <p>
     * That default was originally also about interoperability: JAdES used to put {@code sigT} into the
     * {@code crit} header, and RFC 7515 requires a verifier that does not implement a critical extension
     * to reject the JWS outright. Since ETSI TS 119 182-1 v1.2 the signing time is the registered
     * {@code iat} claim and needs no {@code crit} entry, so a JAdES-signed SD-JWT is no longer rejected
     * by wallets that know nothing of JAdES. Turning this default around is therefore a deliberate
     * choice rather than a compatibility risk.
     */
    private static final Map<String, Boolean> JADES_ENABLED_BY_DEFAULT = Map.of(
            JWT_VC_JSON, true,
            DC_SD_JWT, false);

    private JAdESCredentialFormat() {
        // constants only
    }

    /**
     * Returns whether credentials of the given format are signed as JAdES unless the credential
     * configuration says otherwise.
     *
     * @param format one of the OID4VCI format identifiers declared here
     * @return the default for that format, {@code false} for anything unknown
     */
    public static boolean jadesEnabledByDefault(String format) {
        return JADES_ENABLED_BY_DEFAULT.getOrDefault(format, false);
    }
}
