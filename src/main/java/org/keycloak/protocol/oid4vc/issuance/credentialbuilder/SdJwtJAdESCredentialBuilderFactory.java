package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import com.google.auto.service.AutoService;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.JAdESCredentialFormat;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Provider factory creating {@link SdJwtJAdESCredentialBuilder}s.
 * <p>
 * It reports Keycloak's own {@code dc+sd-jwt} format and therefore takes the place of the built-in
 * {@code SdJwtCredentialBuilderFactory} - see {@link JAdESCredentialFormat}.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(CredentialBuilderFactory.class)
public class SdJwtJAdESCredentialBuilderFactory implements CredentialBuilderFactory {

    private static final String HELP_TEXT =
            "Builds SD-JWT VCs, optionally marked for JAdES signing following ETSI TS 119 182-1.";

    @Override
    public String getSupportedFormat() {
        return JAdESCredentialFormat.DC_SD_JWT;
    }

    @Override
    public CredentialBuilder create(KeycloakSession session, ComponentModel model) {
        return new SdJwtJAdESCredentialBuilder(session);
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
