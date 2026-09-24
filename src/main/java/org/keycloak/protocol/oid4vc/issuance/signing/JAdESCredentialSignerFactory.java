package org.keycloak.protocol.oid4vc.issuance.signing;

import com.google.auto.service.AutoService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.JAdESSignerSettings;

/**
 * Provider factory creating {@link JAdESCredentialSigner}s.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(CredentialSignerFactory.class)
public class JAdESCredentialSignerFactory extends JAdESSignerSettings implements CredentialSignerFactory {

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.JWT_VC_JSON;
    }

    @Override
    public CredentialSigner<String> create(KeycloakSession session) {
        return new JAdESCredentialSigner(session, getDigestAlgorithm(), isIncludeSignatureType());
    }
}
