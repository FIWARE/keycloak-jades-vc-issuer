package org.keycloak.protocol.oid4vc.issuance;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSHeader;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JAdESJwsSigningServiceTest {

    private final String ISSUER_DID = "";
    private JAdESJwsSigningService jAdESJwsSigningService;
    private KeycloakSession keycloakSession;
    private KeycloakContext context;
    private RealmModel realmModel;
    private KeyManager keyManager;

    private enum SignatureAlgorithm {
        RS256, RS512
    }

    @BeforeEach
    public void setup() {
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
    public void testSignCredential(SignatureAlgorithm signatureAlgorithm, String tokenType, DigestAlgorithm digestAlgorithm) throws URISyntaxException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException, VerificationException {
        VerifiableCredential vc = createVC();

        KeyWrapper signingKey = createClientKeyCertChain(signatureAlgorithm);
        when(keyManager.getKey(any(), eq(signatureAlgorithm.toString()), any(), anyString())).thenReturn(signingKey);

        jAdESJwsSigningService = new JAdESJwsSigningService(keycloakSession, signatureAlgorithm.toString(),
                signatureAlgorithm.toString(), tokenType, digestAlgorithm, new OffsetTimeProvider());

        String signedCredentialJwt = jAdESJwsSigningService.signCredential(vc);
        System.out.println(signedCredentialJwt);


        // Verify result
        Key pubKey = signingKey.getCertificateChain().get(0).getPublicKey();
        verifyJwt(signedCredentialJwt, pubKey, signatureAlgorithm, tokenType, digestAlgorithm);
    }

    // Verify the signed JWT
    private void verifyJwt(String signedJwt, Key publicKey,
                           SignatureAlgorithm signatureAlgorithm, String tokenType, DigestAlgorithm digestAlgorithm) throws VerificationException {
        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(signedJwt, JsonWebToken.class);
        JsonWebToken jwtPayload = verifier.getToken();
        JWSHeader jwtHeader = verifier.getHeader();

        // Verify parameters
        String expectedHeaderAlgorithm = "RS256";
        if (signatureAlgorithm == SignatureAlgorithm.RS256 && digestAlgorithm == DigestAlgorithm.SHA256) {
            expectedHeaderAlgorithm = "RS256";
        } else if (signatureAlgorithm == SignatureAlgorithm.RS512 && digestAlgorithm == DigestAlgorithm.SHA256) {
            expectedHeaderAlgorithm = "RS256";
        } else if (signatureAlgorithm == SignatureAlgorithm.RS256 && digestAlgorithm == DigestAlgorithm.SHA512) {
            expectedHeaderAlgorithm = "RS512";
        } else if (signatureAlgorithm == SignatureAlgorithm.RS512 && digestAlgorithm == DigestAlgorithm.SHA512) {
            expectedHeaderAlgorithm = "RS512";
        }

        String expectedType = "jose";
        assertEquals(expectedHeaderAlgorithm, jwtHeader.getAlgorithm().toString(), "Algorithm should equal expected algorithm type");
        assertEquals(expectedType, jwtHeader.getType(), "Type in header should equal expected type");
        assertEquals(ISSUER_DID, jwtPayload.getIssuer(), "Issuer DID should equal expected issuer");

        // Verify signature
        verifier.publicKey((PublicKey) publicKey);
        assertDoesNotThrow(verifier::verifySignature, "Signature verification throws no exception");
    }

    private static Arguments getArguments(SignatureAlgorithm signatureAlgorithm, String tokenType, DigestAlgorithm digestAlgorithm) {
        return Arguments.of(signatureAlgorithm, tokenType, digestAlgorithm);
    }

    private static Stream<Arguments> provideSignatureTypes() {
        return Stream.of(
                getArguments(SignatureAlgorithm.RS256, "JWT", DigestAlgorithm.SHA256),
                getArguments(SignatureAlgorithm.RS256, "JWT", DigestAlgorithm.SHA512)
        );
    }

    // Create VC object
    private VerifiableCredential createVC() throws URISyntaxException {
        VerifiableCredential vc = new VerifiableCredential();
        vc.setIssuer(new URI(ISSUER_DID));
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
    private KeyWrapper createClientKeyCertChain(SignatureAlgorithm signatureAlgorithm) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, KeyStoreException {

        KeyCert rootCAKeyCert = createKeyCert(signatureAlgorithm, createRootCertSubject(), null, 1L, true);
        KeyCert intermediateKeyCert = createKeyCert(signatureAlgorithm, createIntermediateCertSubject(), rootCAKeyCert, 2L, true);
        KeyCert clientKeyCert = createKeyCert(signatureAlgorithm, createClientCertSubject(), intermediateKeyCert, 3L, false);

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPrivateKey(clientKeyCert.key);
        keyWrapper.setCertificateChain(List.of(clientKeyCert.cert, intermediateKeyCert.cert, rootCAKeyCert.cert));
        keyWrapper.setProviderId("java-keystore");

        return keyWrapper;
    }

    // Create a private key and certificate signed by an optional issuer key
    private KeyCert createKeyCert(SignatureAlgorithm signatureAlgorithm, X500Name subjectDN, KeyCert issuer, long serial, boolean isCA) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {

        String keyGenAlgorithm = "RSA";
        switch(signatureAlgorithm) {
            case RS256:
            case RS512:
                keyGenAlgorithm = "RSA";
                break;
        }

        String signerAlgorithm = "SHA256WithRSA";
        switch (signatureAlgorithm) {
            case RS256:
                signerAlgorithm = "SHA256WithRSA";
                break;
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyGenAlgorithm);
        kpg.initialize(4096);
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
