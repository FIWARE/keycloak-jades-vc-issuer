package org.keycloak.protocol.oid4vc.issuance.signing;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtJAdESCredentialBody;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * {@link CredentialSigner} for the {@code dc+sd-jwt} format, signing the issuer-signed JWT as a JAdES JWS
 * following ETSI TS 119 182-1.
 * <p>
 * An SD-JWT is {@code <issuer-signed JWT>~<disclosure>~...~}. Only the leading JWS is signed; the
 * disclosures hang off it and are bound to it through the {@code _sd} digests in its payload. This signer
 * therefore lets Keycloak assemble the whole SD-JWT, then replaces its JWS segment with one produced by
 * DSS over the very same payload. The digests, and with them the disclosures, are unaffected.
 * <p>
 * Letting Keycloak assemble first costs one signature that is then thrown away. That is deliberate: the
 * alternative is to drive {@code SdJwt.Builder} directly and depend on when it does and does not sign,
 * which is not part of its published contract.
 * <p>
 * Note that JAdES lists {@code sigT} in the {@code crit} header, and RFC 7515 section 4.1.11 requires a
 * verifier that does not implement a critical extension to reject the JWS. Wallets that do not implement
 * JAdES will refuse such a credential, which is why {@code dc+sd-jwt} does not default to JAdES - see
 * {@link JAdESCredentialFormat}.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class SdJwtJAdESCredentialSigner extends AbstractJAdESCredentialSigner {

    /**
     * Separator between the issuer-signed JWT and the disclosures of an SD-JWT.
     */
    private static final char DISCLOSURE_SEPARATOR = '~';

    private final SdJwtCredentialSigner keycloakCredentialSigner;

    public SdJwtJAdESCredentialSigner(KeycloakSession keycloakSession, DigestAlgorithm digestAlgorithm,
                                      boolean includeSignatureType) {
        super(keycloakSession, digestAlgorithm, includeSignatureType);
        this.keycloakCredentialSigner = new SdJwtCredentialSigner(keycloakSession);
    }

    @Override
    public String signCredential(CredentialBody credentialBody, CredentialBuildConfig credentialBuildConfig)
            throws CredentialSignerException {

        if (!(credentialBody instanceof SdJwtJAdESCredentialBody sdJwtJAdESCredentialBody)) {
            // JAdES is disabled for this credential configuration - Keycloak adds the x5c header itself
            return keycloakCredentialSigner.signCredential(credentialBody, credentialBuildConfig);
        }

        SdJwtCredentialBody delegate = sdJwtJAdESCredentialBody.getDelegate();
        String keycloakSignedSdJwt = delegate.sign(getSigner(credentialBuildConfig));

        int firstDisclosure = keycloakSignedSdJwt.indexOf(DISCLOSURE_SEPARATOR);
        if (firstDisclosure < 0) {
            throw new CredentialSignerException(
                    "Keycloak produced an SD-JWT without a disclosure separator, so its JWS cannot be replaced.");
        }

        byte[] payload = delegate.getIssuerSignedJWT().getPayload().toString().getBytes(StandardCharsets.UTF_8);
        // the credential configuration may name the type explicitly; SD-JWT VC mandates
        // dc+sd-jwt, so that is the fallback rather than leaving the header to DSS
        String signatureType = Optional.ofNullable(credentialBuildConfig.getTokenJwsType())
                .filter(type -> !type.isBlank())
                .orElse(JAdESCredentialFormat.DC_SD_JWT);
        String jadesJws = signAsJAdES(payload, credentialBuildConfig, signatureType);

        return jadesJws + keycloakSignedSdJwt.substring(firstDisclosure);
    }
}
