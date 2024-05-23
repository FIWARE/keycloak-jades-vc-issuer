package org.keycloak.protocol.oid4vc.issuance;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.issuance.signing.JAdESJwsSigningService;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

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

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JAdESJwsSigningServiceTest {

    private JAdESJwsSigningService jAdESJwsSigningService;

    @Test
    @DisplayName("Simple test")
    void testTrue() throws URISyntaxException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException {
        VerifiableCredential vc = createVC();
        KeyStore keyStore = createClientKeyCertChain();

        assertEquals(true, true, "True is true!");
    }

    // Create VC object
    private VerifiableCredential createVC() throws URISyntaxException {
        VerifiableCredential vc = new VerifiableCredential();
        vc.setIssuer(new URI("did:elsi:VATDE-1234567"));
        vc.setType(List.of("VerifiableCredential"));

        CredentialSubject credentialSubject = new CredentialSubject();
        //credentialSubject.setClaims();
        vc.setCredentialSubject(credentialSubject);

        return vc;
    }

    final static class KeyCert {
        public final PrivateKey key;
        public final X509Certificate cert;

        public KeyCert(PrivateKey key, X509Certificate cert) {
            this.key = key;
            this.cert = cert;
        }
    }

    // Create key / cert chain pair
    private KeyStore createClientKeyCertChain() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, KeyStoreException {

        KeyCert rootCAKeyCert = createKeyCert(createRootCertSubject(), null, 1L, true);
        KeyCert intermediateKeyCert = createKeyCert(createIntermediateCertSubject(), rootCAKeyCert, 2L, true);
        KeyCert clientKeyCert = createKeyCert(createClientCertSubject(), intermediateKeyCert, 3L, false);

        char[] emptyPassword = new char[0];
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, emptyPassword);
        keyStore.setKeyEntry("alias", clientKeyCert.key, emptyPassword,
                new X509Certificate[]{clientKeyCert.cert, intermediateKeyCert.cert, rootCAKeyCert.cert});

        return keyStore;
    }

    private KeyCert createKeyCert(X500Name subjectDN, KeyCert issuer, long serial, boolean isCA) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
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
            issuerSubjectDN = new X500Name(issuer.cert.getSubjectX500Principal().getName());
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
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
        System.out.println(cert.toString());
        return new KeyCert(key, cert);

    }

    private X500Name createRootCertSubject() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "DE");
        builder.addRDN(BCStyle.ST, "Berlin");
        builder.addRDN(BCStyle.L, "Berlin");
        builder.addRDN(BCStyle.O, "FIWARE CA");
        builder.addRDN(BCStyle.CN, "FIWARE-CA");
        builder.addRDN(BCStyle.EmailAddress, "ca@fiware.org");
        builder.addRDN(BCStyle.SERIALNUMBER, "01");
        //X500Name rootCaName = new X500Name("C=DE,ST=Berlin,L=Berlin,O=FIWARE CA,CN=FIWARE-CA,emailAddress=ca@fiware.org,serialNumber=01");

        return builder.build();
    }

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
