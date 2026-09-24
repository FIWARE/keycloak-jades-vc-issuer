package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.jose.jwk.JWK;

/**
 * {@link CredentialBody} marking an SD-JWT VC that is to be signed as JAdES.
 * <p>
 * It wraps Keycloak's own {@link SdJwtCredentialBody} rather than replacing it: selective disclosure,
 * decoys and the {@code _sd} digest computation are Keycloak's, and only the signature envelope around
 * the issuer-signed JWT differs. The wrapper's type is what tells
 * {@link org.keycloak.protocol.oid4vc.issuance.signing.SdJwtJAdESCredentialSigner} which of the two
 * signature styles the credential configuration asked for.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class SdJwtJAdESCredentialBody implements CredentialBody {

    private final SdJwtCredentialBody delegate;

    public SdJwtJAdESCredentialBody(SdJwtCredentialBody delegate) {
        this.delegate = delegate;
    }

    /**
     * Returns the wrapped Keycloak credential body, which owns the issuer-signed JWT and the disclosures.
     *
     * @return the delegate body
     */
    public SdJwtCredentialBody getDelegate() {
        return delegate;
    }

    @Override
    public void addKeyBinding(JWK jwk) throws CredentialBuilderException {
        delegate.addKeyBinding(jwk);
    }
}
