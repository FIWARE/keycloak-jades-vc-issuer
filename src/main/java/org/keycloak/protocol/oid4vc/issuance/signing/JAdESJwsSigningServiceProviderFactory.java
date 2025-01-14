package org.keycloak.protocol.oid4vc.issuance.signing;

import com.google.auto.service.AutoService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OffsetTimeProvider;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Provider Factory to create {@link  JAdESJwsSigningService}s
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(VCSigningServiceProviderFactory.class)
public class JAdESJwsSigningServiceProviderFactory implements VCSigningServiceProviderFactory {

    // TODO: To be replaced with proper format
    public static final String SUPPORTED_FORMAT = "jwt_vc";
    private static final String HELP_TEXT = "Issues JAdES JWS VCs following the specification of ETSI TS 119 182-1.";

    @Override
    public VerifiableCredentialsSigningService create(KeycloakSession session, ComponentModel model) {

        String keyId = model.get(SigningProperties.KEY_ID.getKey());
        String algorithmType = model.get(SigningProperties.ALGORITHM_TYPE.getKey());

        // Digest Algorithm
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        if (model.contains(AdditionalSigningProperties.DIGEST_ALGORITHM.getKey())) {
            digestAlgorithm = DigestAlgorithm.valueOf(model.get(AdditionalSigningProperties.DIGEST_ALGORITHM.getKey()));
        }

        // Include typ in signed header?
        boolean includeSignatureType = model.get(AdditionalSigningProperties.INCLUDE_SIGNATURE_TYPE.getKey(), false);

        return new JAdESJwsSigningService(session, keyId, algorithmType,
                digestAlgorithm, includeSignatureType, new OffsetTimeProvider());
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return VCSigningServiceProviderFactory.configurationBuilder()
                .property(SigningProperties.ALGORITHM_TYPE.asConfigProperty())
                .property(SigningProperties.TOKEN_TYPE.asConfigProperty())
                .property(SigningProperties.KEY_ID.asConfigProperty())
                .property(AdditionalSigningProperties.DIGEST_ALGORITHM.asConfigProperty())
                .build();
    }

    @Override
    public String getId() {
        // TODO: To be replaced with proper SUPPORTED_FORMAT.toString();
        // Value needs to match "providerId" parameter in provider config
        return "jades-jws-signing";
    }

    @Override
    public void validateSpecificConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkRequired(SigningProperties.KEY_ID.asConfigProperty())
                .checkRequired(SigningProperties.TOKEN_TYPE.asConfigProperty())
                .checkRequired(SigningProperties.ALGORITHM_TYPE.asConfigProperty());

    }

    @Override
    public String supportedFormat() {
        return SUPPORTED_FORMAT;
    }

}
