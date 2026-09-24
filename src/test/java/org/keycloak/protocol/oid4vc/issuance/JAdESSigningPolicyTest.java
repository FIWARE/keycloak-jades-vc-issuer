package org.keycloak.protocol.oid4vc.issuance;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers the per-credential-type switch between JAdES and Keycloak's own signature.
 */
public class JAdESSigningPolicyTest {

    private static final String CREDENTIAL_CONFIGURATION_ID_ATTRIBUTE = "vc.credential_configuration_id";
    private static final String CREDENTIAL_CONFIG_ID = "user-credential";

    private static Stream<Arguments> provideCredentialConfigurations() {
        return Stream.of(
                // jwt_vc_json defaults to JAdES: Keycloak's own JWT signer writes no x5c at all
                Arguments.of(JAdESCredentialFormat.JWT_VC_JSON, null, true),
                // dc+sd-jwt defaults to Keycloak, which adds x5c itself and stays wallet-compatible
                Arguments.of(JAdESCredentialFormat.DC_SD_JWT, null, false),
                // an explicit attribute wins over the per-format default, in both directions
                Arguments.of(JAdESCredentialFormat.JWT_VC_JSON, "false", false),
                Arguments.of(JAdESCredentialFormat.DC_SD_JWT, "true", true),
                // a blank attribute is not a decision and falls back to the default
                Arguments.of(JAdESCredentialFormat.DC_SD_JWT, "  ", false),
                // anything that is not "true" reads as disabled, per Boolean.parseBoolean
                Arguments.of(JAdESCredentialFormat.JWT_VC_JSON, "yes", false)
        );
    }

    @ParameterizedTest
    @MethodSource("provideCredentialConfigurations")
    @DisplayName("JAdES is switched per credential configuration, falling back to the format default")
    public void testIsJAdESEnabled(String format, String jadesEnabledAttribute, boolean expected) {

        ClientScopeModel clientScope = mock(ClientScopeModel.class);
        when(clientScope.getProtocol()).thenReturn(OID4VCLoginProtocolFactory.PROTOCOL_ID);
        when(clientScope.getAttribute(anyString())).thenReturn(null);
        when(clientScope.getAttribute(CREDENTIAL_CONFIGURATION_ID_ATTRIBUTE)).thenReturn(CREDENTIAL_CONFIG_ID);
        when(clientScope.getAttribute(JAdESCredentialFormat.JADES_ENABLED_ATTRIBUTE))
                .thenReturn(jadesEnabledAttribute);

        ClientScopeModel ordinaryScope = mock(ClientScopeModel.class);
        when(ordinaryScope.getProtocol()).thenReturn("openid-connect");

        RealmModel realm = mock(RealmModel.class);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(ordinaryScope, clientScope));

        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getRealm()).thenReturn(realm);

        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(context);

        CredentialBuildConfig credentialBuildConfig =
                new CredentialBuildConfig().setCredentialConfigId(CREDENTIAL_CONFIG_ID);

        assertEquals(expected, new JAdESSigningPolicy(session).isJAdESEnabled(credentialBuildConfig, format),
                "JAdES enablement should follow the credential configuration");
    }

    @ParameterizedTest
    @MethodSource("provideCredentialConfigurations")
    @DisplayName("Without a matching credential scope the format default applies")
    public void testFallsBackWithoutScope(String format, String jadesEnabledAttribute, boolean ignored) {

        RealmModel realm = mock(RealmModel.class);
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());

        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getRealm()).thenReturn(realm);

        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(context);

        CredentialBuildConfig credentialBuildConfig =
                new CredentialBuildConfig().setCredentialConfigId(CREDENTIAL_CONFIG_ID);

        assertEquals(JAdESCredentialFormat.jadesEnabledByDefault(format),
                new JAdESSigningPolicy(session).isJAdESEnabled(credentialBuildConfig, format),
                "An unknown credential configuration should fall back to the format default");
    }
}
