package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.JOSEParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.protocol.oid4vc.issuance.jades.JAdESCompactSigner;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the protected header that {@link JAdESCompactSigner} produces, in particular the {@code typ}
 * override that SD-JWT VC needs: DSS hard-codes {@code jose} for compact serialization, so the value has
 * to be forced through a {@code JAdESCompactBuilder} subclass.
 */
public class JAdESCompactSignerTest {

    private static final String PAYLOAD = "{\"iss\":\"did:elsi:VATDE-1234567\"}";
    private static final String SD_JWT_TYPE = "dc+sd-jwt";
    private static final String SIGNING_TIME_HEADER = "sigT";
    private static final String CRITICAL_HEADER = "crit";
    private static final String TYPE_HEADER = "typ";
    private static final String X5C_HEADER = "x5c";

    @BeforeEach
    public void setup() {
        CryptoIntegration.init(this.getClass().getClassLoader());
    }

    private static Stream<Arguments> provideSignatureTypes() {
        return Stream.of(
                // SD-JWT VC mandates typ: dc+sd-jwt on the issuer-signed JWT
                Arguments.of(SD_JWT_TYPE, false, SD_JWT_TYPE),
                // a forced type wins over the includeSignatureType setting
                Arguments.of(SD_JWT_TYPE, true, SD_JWT_TYPE),
                // the W3C jwt-vc data model wants no typ, and RFC 7515 makes it optional
                Arguments.of(null, false, null),
                // without a forced type DSS falls back to its own value
                Arguments.of(null, true, "jose")
        );
    }

    @ParameterizedTest
    @MethodSource("provideSignatureTypes")
    @DisplayName("JAdES header carries the requested type along with x5c and the signing time")
    public void testProtectedHeader(String forcedSignatureType, boolean includeSignatureType,
                                    String expectedType) throws Exception {

        KeyWrapper signingKey = KeyCertFixtures.createClientKeyCertChain(
                KeyCertFixtures.SignatureAlgorithm.SHA256WithECDSA,
                new KeyCertFixtures.KeyPairGenParameters(null, "secp256r1"));

        String jws = new JAdESCompactSigner(DigestAlgorithm.SHA256, includeSignatureType)
                .sign(PAYLOAD.getBytes(StandardCharsets.UTF_8), signingKey, forcedSignatureType);

        JWSInput jwsInput = (JWSInput) JOSEParser.parse(jws);
        Map<?, ?> header = new ObjectMapper().readValue(
                Base64.getUrlDecoder().decode(jwsInput.getEncodedHeader()), Map.class);

        if (expectedType == null) {
            assertFalse(header.containsKey(TYPE_HEADER), "Header should not contain parameter 'typ'");
        } else {
            assertEquals(expectedType, header.get(TYPE_HEADER), "Header 'typ' should equal the expected type");
        }

        assertEquals(KeyCertFixtures.CERT_CHAIN_LENGTH, ((List<?>) header.get(X5C_HEADER)).size(),
                "x5c header should carry the full certificate chain");
        assertTrue(header.containsKey(SIGNING_TIME_HEADER), "Header should contain 'sigT'");
        assertTrue(((List<?>) header.get(CRITICAL_HEADER)).contains(SIGNING_TIME_HEADER),
                "Header 'crit' should contain 'sigT'");
    }
}
