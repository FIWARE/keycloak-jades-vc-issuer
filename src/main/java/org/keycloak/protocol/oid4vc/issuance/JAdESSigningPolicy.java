package org.keycloak.protocol.oid4vc.issuance;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

import java.util.Optional;

/**
 * Decides per credential configuration whether a credential is signed as JAdES or handed to
 * Keycloak's own builder and signer.
 * <p>
 * The decision is read from the {@value JAdESCredentialFormat#JADES_ENABLED_ATTRIBUTE} attribute of the
 * client scope backing the credential configuration, which is where Keycloak keeps the rest of the
 * per-credential OID4VCI settings. It is taken once, in the credential builder, and carried by the type
 * of the produced credential body - so the signer never has to resolve it a second time and the two can
 * never disagree.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESSigningPolicy {

    private static final Logger LOGGER = Logger.getLogger(JAdESSigningPolicy.class);

    private final KeycloakSession keycloakSession;

    public JAdESSigningPolicy(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    /**
     * Returns whether the credential described by the given build config is to be signed as JAdES.
     *
     * @param credentialBuildConfig build config of the credential about to be issued
     * @param format                OID4VCI format identifier the calling builder serves
     * @return {@code true} to sign as JAdES, {@code false} to delegate to Keycloak
     */
    public boolean isJAdESEnabled(CredentialBuildConfig credentialBuildConfig, String format) {
        boolean enabled = findCredentialScope(credentialBuildConfig)
                .map(scope -> scope.getAttribute(JAdESCredentialFormat.JADES_ENABLED_ATTRIBUTE))
                .filter(value -> !value.isBlank())
                .map(Boolean::parseBoolean)
                .orElseGet(() -> JAdESCredentialFormat.jadesEnabledByDefault(format));

        LOGGER.debugf("JAdES signing is %s for credential configuration %s (format %s).",
                enabled ? "enabled" : "disabled", credentialBuildConfig.getCredentialConfigId(), format);
        return enabled;
    }

    /**
     * Resolves the client scope that carries the attributes of the credential configuration.
     * <p>
     * Keycloak identifies a credential configuration by the scope's
     * {@code credentialConfigurationId}, which defaults to the scope name but does not have to match it,
     * so the realm's scopes are searched rather than looked up by name.
     */
    private Optional<CredentialScopeModel> findCredentialScope(CredentialBuildConfig credentialBuildConfig) {
        String credentialConfigId = credentialBuildConfig.getCredentialConfigId();
        if (credentialConfigId == null || credentialConfigId.isBlank()) {
            return Optional.empty();
        }

        RealmModel realm = keycloakSession.getContext().getRealm();
        if (realm == null) {
            return Optional.empty();
        }

        return realm.getClientScopesStream()
                // a realm holds plenty of ordinary scopes (profile, email, roles); only the OID4VC ones
                // may be wrapped, as CredentialScopeModel asserts the protocol in its constructor
                .filter(scope -> OID4VCLoginProtocolFactory.PROTOCOL_ID.equals(scope.getProtocol()))
                .map(CredentialScopeModel::new)
                .filter(scope -> credentialConfigId.equals(scope.getCredentialConfigurationId()))
                .findFirst();
    }

}
