package org.keycloak.protocol.oid4vc.issuance.signing;

import com.google.auto.service.AutoService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.JAdESSignerSettings;

/**
 * Provider factory creating {@link SdJwtJAdESCredentialSigner}s.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(CredentialSignerFactory.class)
public class SdJwtJAdESCredentialSignerFactory extends JAdESSignerSettings implements CredentialSignerFactory {

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.DC_SD_JWT;
    }

    @Override
    public CredentialSigner<String> create(KeycloakSession session) {
        return new SdJwtJAdESCredentialSigner(session, getDigestAlgorithm(), isIncludeSignatureType());
    }
}
