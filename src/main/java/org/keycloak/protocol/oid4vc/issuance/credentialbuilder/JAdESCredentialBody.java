package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * {@link CredentialBody} carrying the unsigned JWT claim set of a verifiable credential.
 * <p>
 * Unlike Keycloak's {@code JwtCredentialBody}, which hands the signer a pre-assembled
 * {@code JWSBuilder.EncodingBuilder} and therefore fixes the JOSE header before signing, this body keeps
 * the claim set open. The JAdES signer needs to own the protected header so that DSS can place the
 * signing certificate chain ({@code x5c}) and the ETSI TS 119 182-1 signed properties into it.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESCredentialBody implements CredentialBody {

    private static final String CNF_CLAIM_KEY = "cnf";
    private static final String JWK_CLAIM_KEY = "jwk";

    private final JsonWebToken jsonWebToken;

    public JAdESCredentialBody(JsonWebToken jsonWebToken) {
        this.jsonWebToken = jsonWebToken;
    }

    /**
     * Returns the claim set to be signed.
     *
     * @return the unsigned JWT holding the credential
     */
    public JsonWebToken getJsonWebToken() {
        return jsonWebToken;
    }

    /**
     * Binds the credential to the holder's key by adding the OID4VCI {@code cnf} claim.
     *
     * @param jwk public key of the holder, as presented in the credential request proof
     */
    @Override
    public void addKeyBinding(JWK jwk) throws CredentialBuilderException {
        if (jwk == null) {
            throw new CredentialBuilderException("Cannot bind the credential to a null key.");
        }
        jsonWebToken.setOtherClaims(CNF_CLAIM_KEY, Map.of(JWK_CLAIM_KEY, jwk));
    }
}
