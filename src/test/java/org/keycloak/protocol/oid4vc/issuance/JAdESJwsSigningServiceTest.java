package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import org.junit.jupiter.api.BeforeAll;
//import org.junit.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.*;
import org.keycloak.jose.JOSEParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.signing.JAdESJwsSigningService;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.Role;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

//@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JAdESJwsSigningServiceTest {

    private static final String ISSUER_DID = "did:elsi:VATDE-1234567";
    private static int CERT_CHAIN_LENGTH = 3;
    private JAdESJwsSigningService jAdESJwsSigningService;
    private KeycloakSession keycloakSession;
    private KeycloakContext context;
    private RealmModel realmModel;
    private KeyManager keyManager;

    @BeforeEach
    public void setup() {
        CryptoIntegration.init(this.getClass().getClassLoader());

        this.keycloakSession = mock(KeycloakSession.class);
        this.context = mock(KeycloakContext.class);
        this.keyManager = mock(KeyManager.class);
        this.realmModel = mock(RealmModel.class);

        when(keycloakSession.keys()).thenReturn(keyManager);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
    }

    @ParameterizedTest
    @MethodSource("provideSignatureTypes")
    @DisplayName("Test signing valid credential")
    public void testSignCredential(SignCredentialTestInput signCredentialTestInput,
                                   SignCredentialTestExpectedValues signCredentialTestExpectedValues)
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException, VerificationException, InvalidAlgorithmParameterException {
        VerifiableCredential vc = createVC(signCredentialTestInput.vcIssuer());

        KeyWrapper signingKey = createClientKeyCertChain(signCredentialTestInput.signatureAlgorithm(),
                signCredentialTestInput.keyPairGenParameters());
        String signatureAlgorithm = signCredentialTestInput.signatureAlgorithm().toString();
        when(keyManager.getKey(any(), eq(signatureAlgorithm), any(), anyString())).thenReturn(signingKey);

        jAdESJwsSigningService = new JAdESJwsSigningService(keycloakSession, signatureAlgorithm,
                signatureAlgorithm, signCredentialTestInput.digestAlgorithm(), new OffsetTimeProvider());

        String signedCredentialJwt = jAdESJwsSigningService.signCredential(vc);

        // Verify result
        verifyJwt(signedCredentialJwt, signingKey,
                signCredentialTestInput.signatureAlgorithm(), signCredentialTestExpectedValues);
    }

    // Verify the signed JWT
    private void verifyJwt(String signedJwt, KeyWrapper signingKey, SignatureAlgorithm signatureAlgorithm,
                           SignCredentialTestExpectedValues signCredentialTestExpectedValues) throws VerificationException, IOException {
        SignatureVerifierContext verifierContext = null;

        Key publicKey = signingKey.getCertificateChain().get(0).getPublicKey();
        signingKey.setPublicKey(publicKey);

        switch (signatureAlgorithm) {
            case SHA256WithECDSA:
            case SHA512WithECDSA: {
                verifierContext = new ServerECDSASignatureVerifierContext(signingKey);
                break;
            }
            case SHA256WithRSA:
            case SHA512WithRSA: {
                verifierContext = new AsymmetricSignatureVerifierContext(signingKey);
                break;
            }
            default: {
                fail("Algorithm not supported.");
            }
        }

        TokenVerifier<JsonWebToken> verifier = TokenVerifier
                .create(signedJwt, JsonWebToken.class)
                .verifierContext(verifierContext);
        JsonWebToken jwtPayload = verifier.getToken();
        JWSHeader jwtHeader = verifier.getHeader();
        JWSInput jwsInput = (JWSInput) JOSEParser.parse(signedJwt);
        Map headers = new ObjectMapper().readValue(
                java.util.Base64.getDecoder().decode(jwsInput.getEncodedHeader()),
                Map.class);

        // Verify header parameters
        assertEquals(signCredentialTestExpectedValues.headerAlgorithm(), jwtHeader.getAlgorithm().toString(),
                "Algorithm should equal expected algorithm type");
        assertEquals(signCredentialTestExpectedValues.headerType(), jwtHeader.getType(),
                "Type in header should equal expected type");
        assertEquals(signCredentialTestExpectedValues.headerX5cLength(), ((List) headers.get("x5c")).size(),
                "x5c header should have correct size");

        // Header: sigT
        assertTrue(headers.containsKey("sigT"),
                "Header should contain 'sigT'");

        try {
            ZonedDateTime tokenTime = ZonedDateTime.parse((String) headers.get("sigT"),
                    DateTimeFormatter.ISO_ZONED_DATE_TIME);
            assertTrue(tokenTime.isBefore(ZonedDateTime.now()),
                    "Header 'sigT' timestamp should be in the past");
        } catch (DateTimeParseException dtpe) {
            fail("Header 'sigT' timestamp should have correct format");
        }

        assertTrue( ((List) headers.get("crit")).contains("sigT"),
                "Header 'crit' should contain 'sigT'" );


        // Verify payload
        assertEquals(signCredentialTestExpectedValues.vcIssuer(), jwtPayload.getIssuer(),
                "Issuer DID should equal expected issuer");
        assertTrue(jwtPayload.getOtherClaims().containsKey("vc"),
                "Payload should contain VerifiableCredential vc.");

        Map verifiableCredential = (Map) jwtPayload.getOtherClaims().get("vc");
        assertEquals(signCredentialTestExpectedValues.vcIssuer(), verifiableCredential.get("issuer"),
                "VC should contain issuer field with correct value");

        // Verify signature
        assertDoesNotThrow(verifier::verifySignature, "Signature verification throws no exception");
    }

    private static Arguments getArguments(SignCredentialTestInput signCredentialTestInput,
                                          SignCredentialTestExpectedValues signCredentialTestExpectedValues) {
        return Arguments.of(signCredentialTestInput, signCredentialTestExpectedValues);
    }

    private static Stream<Arguments> provideSignatureTypes() {
        return Stream.of(
                getArguments(new SignCredentialTestInput(
                        SignatureAlgorithm.SHA256WithRSA,
                        new KeyPairGenParameters(4096, null),
                        DigestAlgorithm.SHA256, ISSUER_DID
                ), new SignCredentialTestExpectedValues(
                        "RS256", "jose", CERT_CHAIN_LENGTH, ISSUER_DID
                )),
                getArguments(new SignCredentialTestInput(
                        SignatureAlgorithm.SHA512WithRSA,
                        new KeyPairGenParameters(4096, null),
                        DigestAlgorithm.SHA512, ISSUER_DID
                ), new SignCredentialTestExpectedValues(
                        "RS512", "jose", CERT_CHAIN_LENGTH, ISSUER_DID
                )),
                getArguments(new SignCredentialTestInput(
                        SignatureAlgorithm.SHA256WithECDSA,
                        new KeyPairGenParameters(null, "secp256r1"),
                        DigestAlgorithm.SHA256, ISSUER_DID
                ), new SignCredentialTestExpectedValues(
                        "ES256", "jose", CERT_CHAIN_LENGTH, ISSUER_DID
                )),
                getArguments(new SignCredentialTestInput(
                        SignatureAlgorithm.SHA512WithECDSA,
                        new KeyPairGenParameters(null, "secp521r1"),
                        DigestAlgorithm.SHA512, ISSUER_DID
                ), new SignCredentialTestExpectedValues(
                        "ES512", "jose", CERT_CHAIN_LENGTH, ISSUER_DID
                ))
        );
    }

    // SignatureAlgorithm for BouncyCastle - why do they have no enum?
    // see: https://github.com/bcgit/bc-java/blob/main/pkix/src/main/java/org/bouncycastle/operator/DefaultSignatureAlgorithmIdentifierFinder.java
    private enum SignatureAlgorithm {
        SHA256WithRSA, SHA512WithRSA,
        SHA256WithECDSA, SHA512WithECDSA
    }

    public record KeyPairGenParameters(Integer keySize, // RSA key size
                                       String ecStdName // EC generation parameter standard name
    ) {}

    public record SignCredentialTestInput(SignatureAlgorithm signatureAlgorithm,
                                          KeyPairGenParameters keyPairGenParameters,
                                          DigestAlgorithm digestAlgorithm,
                                          String vcIssuer) {}

    public record SignCredentialTestExpectedValues(String headerAlgorithm,
                                                   String headerType,
                                                   int headerX5cLength,
                                                   String vcIssuer) {}

    // Create VC object
    private VerifiableCredential createVC(String issuer) throws URISyntaxException {
        VerifiableCredential vc = new VerifiableCredential();
        vc.setIssuer(new URI(issuer));
        vc.setType(List.of("VerifiableCredential"));
        vc.setIssuanceDate(new Date());

        CredentialSubject credentialSubject = getCredentialSubject(
                Map.of("email", "test@user.org",
                        "familyName", "Mustermann",
                        "firstName", "Max",
                        "roles", Set.of(new Role(Set.of("MyRole"), "did:key:1")))
        );
        vc.setCredentialSubject(credentialSubject);

        return vc;
    }

    // Get a credential subject
    private static CredentialSubject getCredentialSubject(Map<String, Object> claims) {
        CredentialSubject credentialSubject = new CredentialSubject();
        claims.entrySet().stream().forEach(e -> credentialSubject.setClaims(e.getKey(), e.getValue()));
        return credentialSubject;
    }

    // Class holding a key and a certificate
    final static class KeyCert {
        public final PrivateKey key;
        public final X509Certificate cert;

        public KeyCert(PrivateKey key, X509Certificate cert) {
            this.key = key;
            this.cert = cert;
        }
    }

    // Create key / cert chain pairs consisting of client, intermediate and root CA certificate,
    // and return it as Keycloak KeyWrapper
    private KeyWrapper createClientKeyCertChain(SignatureAlgorithm signatureAlgorithm, KeyPairGenParameters keyPairGenParameters) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, KeyStoreException, InvalidAlgorithmParameterException {

        KeyCert rootCAKeyCert = createKeyCert(
                signatureAlgorithm, keyPairGenParameters,
                createRootCertSubject(), null, 1L, true);
        KeyCert intermediateKeyCert = createKeyCert(
                signatureAlgorithm, keyPairGenParameters,
                createIntermediateCertSubject(), rootCAKeyCert, 2L, true);
        KeyCert clientKeyCert = createKeyCert(
                signatureAlgorithm, keyPairGenParameters,
                createClientCertSubject(), intermediateKeyCert, 3L, false);

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPrivateKey(clientKeyCert.key);
        keyWrapper.setCertificateChain(List.of(clientKeyCert.cert, intermediateKeyCert.cert, rootCAKeyCert.cert));
        keyWrapper.setProviderId("java-keystore");

        switch (signatureAlgorithm) {
            case SHA256WithRSA:
                keyWrapper.setAlgorithm(Algorithm.RS256);
                break;
            case SHA512WithRSA:
                keyWrapper.setAlgorithm(Algorithm.RS512);
                break;
            case SHA256WithECDSA:
                keyWrapper.setAlgorithm(Algorithm.ES256);
                break;
            case SHA512WithECDSA:
                keyWrapper.setAlgorithm(Algorithm.ES512);
                break;
        }

        return keyWrapper;
    }

    // Create a private key and certificate signed by an optional issuer key
    private KeyCert createKeyCert(SignatureAlgorithm signatureAlgorithm, KeyPairGenParameters keyPairGenParameters, X500Name subjectDN, KeyCert issuer, long serial, boolean isCA) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException {

        KeyPairGenerator kpg;
        switch(signatureAlgorithm) {
            case SHA256WithRSA:
            case SHA512WithRSA:
                //keyGenAlgorithm = "RSA";
                kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(keyPairGenParameters.keySize());
                break;
            case SHA256WithECDSA:
            case SHA512WithECDSA:
                kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(keyPairGenParameters.ecStdName()));
                break;
            default:
                kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(keyPairGenParameters.keySize());
                break;
        }

        String signerAlgorithm = signatureAlgorithm.toString();
        var keyPair = kpg.generateKeyPair();

        BigInteger serialNumber = BigInteger.valueOf(serial);
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);

        X500Name issuerSubjectDN;
        PrivateKey issuerKey;
        PrivateKey key = keyPair.getPrivate();
        if (issuer == null) {
            // No issuer --> self-sign
            issuerSubjectDN = subjectDN;
            issuerKey = key;
        } else {
            issuerSubjectDN = new JcaX509CertificateHolder((X509Certificate) issuer.cert).getSubject();
            issuerKey = issuer.key;
        }

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerSubjectDN,
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                subjectDN, keyPair.getPublic());
        if (isCA) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }

        // Sign it
        ContentSigner signer = new JcaContentSignerBuilder(signerAlgorithm).build(issuerKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new KeyCert(key, cert);

    }

    // Create the subject for the root CA cert
    private X500Name createRootCertSubject() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "DE");
        builder.addRDN(BCStyle.ST, "Berlin");
        builder.addRDN(BCStyle.L, "Berlin");
        builder.addRDN(BCStyle.O, "FIWARE CA");
        builder.addRDN(BCStyle.CN, "FIWARE-CA");
        builder.addRDN(BCStyle.EmailAddress, "ca@fiware.org");
        builder.addRDN(BCStyle.SERIALNUMBER, "01");

        return builder.build();
    }

    // Create the subject for the intermediate cert
    private X500Name createIntermediateCertSubject() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "DE");
        builder.addRDN(BCStyle.ST, "Berlin");
        builder.addRDN(BCStyle.L, "Berlin");
        builder.addRDN(BCStyle.O, "FIWARE CA TLS");
        builder.addRDN(BCStyle.CN, "FIWARE-CA-TLS");
        builder.addRDN(BCStyle.EmailAddress, "ca-tls@fiware.org");
        builder.addRDN(BCStyle.SERIALNUMBER, "02");

        return builder.build();
    }

    // Create the subject for the client cert
    private X500Name createClientCertSubject() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "DE");
        builder.addRDN(BCStyle.ST, "Berlin");
        builder.addRDN(BCStyle.L, "Berlin");
        builder.addRDN(BCStyle.O, "FIWARE Foundation");
        builder.addRDN(BCStyle.CN, "FIWARE-Test");
        builder.addRDN(BCStyle.EmailAddress, "test@fiware.org");
        builder.addRDN(BCStyle.SERIALNUMBER, "03");
        builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, "VATDE-1234567");

        return builder.build();
    }
}
