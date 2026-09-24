package org.keycloak.protocol.oid4vc.issuance;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JAdESCredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JAdESCredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.net.URI;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers where the issued credential takes its {@code iss} claim from.
 * <p>
 * Keycloak does not put the issuer on the {@link VerifiableCredential} handed to the builder - it
 * comes from the credential configuration - so a builder that only reads the credential produces
 * credentials without an issuer, or fails outright.
 */
public class JAdESCredentialBuilderTest {

    private static final String CONFIG_ISSUER = "did:elsi:VATDE-1234567";
    private static final String CREDENTIAL_ISSUER = "did:web:already-on-the-credential.org";

    private static Stream<Arguments> provideIssuerSources() {
        return Stream.of(
                // the usual case: Keycloak names the issuer in the credential configuration
                Arguments.of(null, CONFIG_ISSUER, CONFIG_ISSUER),
                // a configured issuer wins, matching Keycloak's own builder
                Arguments.of(CREDENTIAL_ISSUER, CONFIG_ISSUER, CONFIG_ISSUER),
                // without a configured issuer the credential's own value is kept
                Arguments.of(CREDENTIAL_ISSUER, null, CREDENTIAL_ISSUER)
        );
    }

    @ParameterizedTest
    @MethodSource("provideIssuerSources")
    @DisplayName("The issuer is resolved from the credential configuration")
    public void testIssuerResolution(String credentialIssuer, String configIssuer, String expected) {
        VerifiableCredential vc = credential(credentialIssuer);
        CredentialBuildConfig config = new CredentialBuildConfig().setCredentialIssuer(configIssuer);

        JAdESCredentialBody body = (JAdESCredentialBody)
                new JAdESCredentialBuilder(new OffsetTimeProvider(), session()).buildCredentialBody(vc, config);

        assertEquals(expected, body.getJsonWebToken().getIssuer(),
                "The iss claim should come from the credential configuration when it names an issuer");
    }

    @ParameterizedTest
    @MethodSource("provideIssuerSources")
    @DisplayName("A credential with no issuer at all is rejected")
    public void testMissingIssuerIsRejected(String ignoredCredentialIssuer, String ignoredConfigIssuer,
                                            String ignoredExpected) {
        VerifiableCredential vc = credential(null);
        CredentialBuildConfig config = new CredentialBuildConfig();

        JAdESCredentialBuilder builder = new JAdESCredentialBuilder(new OffsetTimeProvider(), session());
        assertThrows(RuntimeException.class, () -> builder.buildCredentialBody(vc, config),
                "Building a credential without any issuer should fail rather than emit an empty iss");
    }

    private static VerifiableCredential credential(String issuer) {
        VerifiableCredential vc = new VerifiableCredential();
        if (issuer != null) {
            vc.setIssuer(URI.create(issuer));
        }
        vc.setType(List.of("VerifiableCredential"));
        vc.setCredentialSubject(new CredentialSubject());
        return vc;
    }

    private static KeycloakSession session() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getRealm()).thenReturn(realm);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(context);
        return session;
    }
}
