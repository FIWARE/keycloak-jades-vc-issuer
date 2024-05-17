package org.keycloak.protocol.oid4vc.issuance.signing;

import com.google.auto.service.AutoService;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OffsetTimeProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.jboss.logging.Logger;

/**
 * Provider Factory to create {@link  JAdESJwsSigningService}s
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
@AutoService(VCSigningServiceProviderFactory.class)
public class JAdESJwsSigningServiceProviderFactory implements VCSigningServiceProviderFactory {

    private static final Logger LOGGER = Logger.getLogger(JAdESJwsSigningServiceProviderFactory.class);

    // TODO: To be replaced with proper format
    public static final Format SUPPORTED_FORMAT = Format.JWT_VC;
    private static final String HELP_TEXT = "Issues JAdES JWS VCs following the specification of XYZ.";

    @Override
    public VerifiableCredentialsSigningService create(KeycloakSession session, ComponentModel model) {

        String keyId = model.get(SigningProperties.KEY_ID.getKey());
        String algorithmType = model.get(SigningProperties.ALGORITHM_TYPE.getKey());
        String tokenType = model.get(SigningProperties.TOKEN_TYPE.getKey());
        String issuerDid = Optional.ofNullable(
                        session
                                .getContext()
                                .getRealm()
                                .getAttribute(ISSUER_DID_REALM_ATTRIBUTE_KEY))
                .orElseThrow(() -> new VCIssuerException("No issuerDid configured."));

        // SignatureLevel (Default: JAdES_BASELINE_B)
        SignatureLevel signatureLevel = SignatureLevel.JAdES_BASELINE_B;
        if (model.contains(AdditionalSigningProperties.SIGNATURE_LEVEL.getKey())) {
            signatureLevel = SignatureLevel.valueOf(model.get(AdditionalSigningProperties.SIGNATURE_LEVEL.getKey()));
        }

        // JWS Serialization Type
        JWSSerializationType jwsSerializationType = JWSSerializationType.COMPACT_SERIALIZATION;
        if(model.contains(AdditionalSigningProperties.JWS_SERIALIZATION_TYPE.getKey())) {
            jwsSerializationType = JWSSerializationType.valueOf(model.get(AdditionalSigningProperties.JWS_SERIALIZATION_TYPE.getKey()));
        }

        // Online TSP Sources
        List<String> onlineTspSources = null;
        if(model.contains(AdditionalSigningProperties.ONLINE_TSP_SOURCES.getKey())) {
            String onlineTspSourcesString = model.get(AdditionalSigningProperties.ONLINE_TSP_SOURCES.getKey());
            LOGGER.infof("Online TSP sources: %s", onlineTspSourcesString);
            onlineTspSources = Arrays.asList(onlineTspSourcesString.split(","));
        }

        // KeyEntity TSP Source from Keystore
        String tspSourceKeyId = null;
        String tspSourceKeyAlgorithmType = null;
        if(model.contains(AdditionalSigningProperties.TSP_SOURCE_KEY_ID.getKey()) &&
                model.contains(AdditionalSigningProperties.TSP_SOURCE_KEY_ALGORITHM_TYPE.getKey())) {
            tspSourceKeyId = model.get(AdditionalSigningProperties.TSP_SOURCE_KEY_ID.getKey());
            tspSourceKeyAlgorithmType = model.get(AdditionalSigningProperties.TSP_SOURCE_KEY_ALGORITHM_TYPE.getKey());
        }

        return new JAdESJwsSigningService(session, keyId, algorithmType, tokenType, issuerDid,
                signatureLevel, jwsSerializationType,
                onlineTspSources, tspSourceKeyId, tspSourceKeyAlgorithmType,
                new OffsetTimeProvider());
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
                .property(AdditionalSigningProperties.SIGNATURE_LEVEL.asConfigProperty())
                .property(AdditionalSigningProperties.JWS_SERIALIZATION_TYPE.asConfigProperty())
                .property(AdditionalSigningProperties.ONLINE_TSP_SOURCES.asConfigProperty())
                .property(AdditionalSigningProperties.TSP_SOURCE_KEY_ID.asConfigProperty())
                .property(AdditionalSigningProperties.TSP_SOURCE_KEY_ALGORITHM_TYPE.asConfigProperty())
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
                .checkRequired(SigningProperties.TOKEN_TYPE.asConfigProperty())
                .checkRequired(SigningProperties.ALGORITHM_TYPE.asConfigProperty());

        // Validate Signature Level / JWS Serialization Type
        // TODO: separate function, only validate if values have been set or after values have been loaded (using defaults possible)
        /**JWSSerializationType jwsSerializationType =
                JWSSerializationType.valueOf(model.get(AdditionalSigningProperties.JWS_SERIALIZATION_TYPE.getKey()));
        SignatureLevel signatureLevel =
                SignatureLevel.valueOf(model.get(AdditionalSigningProperties.SIGNATURE_LEVEL.getKey()));

        // COMPACT_SERIALIZATION represents a compact, URL-safe serialization.
        // It has no JWS Unprotected Header, therefore only JAdES-BASELINE-B level is possible with this format.
        if (jwsSerializationType==JWSSerializationType.COMPACT_SERIALIZATION
                && signatureLevel!=SignatureLevel.JAdES_BASELINE_B) {
            throw new ComponentValidationException("COMPACT_SERIALIZATION requires signature level JAdES-BASELINE-B");
        }
        **/
        // TODO: Other serialization --> NOT BASELINE-B

        // TODO: validate KeyEntity TSP source has algorithm
        // TODO: Validate JAdES_BASELINE_T or JAdES_BASELINE_LTA has TSP source configured

    }

    @Override
    public Format supportedFormat() {
        return SUPPORTED_FORMAT;
    }

}
