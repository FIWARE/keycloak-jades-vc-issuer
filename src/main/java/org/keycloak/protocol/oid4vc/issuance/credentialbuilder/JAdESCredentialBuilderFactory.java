package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import com.google.auto.service.AutoService;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.protocol.oid4vc.issuance.OffsetTimeProvider;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Provider factory creating {@link JAdESCredentialBuilder}s.
 * <p>
 * It deliberately reports Keycloak's own {@code jwt_vc_json} format, so that this builder takes the place
 * of the built-in {@code JwtCredentialBuilderFactory} - see {@link JAdESCredentialFormat}.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(CredentialBuilderFactory.class)
public class JAdESCredentialBuilderFactory implements CredentialBuilderFactory {

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.JWT_VC_JSON;
    }

    @Override
    public CredentialBuilder create(KeycloakSession session) {
        return new JAdESCredentialBuilder(new OffsetTimeProvider(), session);
    }

}
