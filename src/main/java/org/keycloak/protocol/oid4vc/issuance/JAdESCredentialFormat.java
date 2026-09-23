package org.keycloak.protocol.oid4vc.issuance;

/**
 * Credential format served by the JAdES builder/signer pair.
 * <p>
 * The plugin registers under Keycloak's own {@code jwt_vc_json} format and therefore replaces the
 * built-in {@code JwtCredentialBuilderFactory}/{@code JwtCredentialSignerFactory}. Keycloak collects
 * credential builders into a map keyed by supported format using {@link java.util.stream.Collectors#toMap},
 * which rejects duplicate keys - so a second factory for the same format must share the provider id
 * rather than register alongside the built-in one.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public final class JAdESCredentialFormat {

    /**
     * OID4VCI format identifier for W3C VC 1.1 credentials encoded as a JWT.
     */
    public static final String JWT_VC_JSON = "jwt_vc_json";

    private JAdESCredentialFormat() {
        // constants only
    }
}
