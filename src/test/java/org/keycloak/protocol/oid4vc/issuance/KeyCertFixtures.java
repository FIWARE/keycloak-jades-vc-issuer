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
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * Builds the client / intermediate / root certificate chains the signing tests need, and wraps them the
 * way Keycloak hands a realm key to a signer.
 */
public final class KeyCertFixtures {

	public static final int CERT_CHAIN_LENGTH = 3;

	private KeyCertFixtures() {
		// fixtures only
	}

	// SignatureAlgorithm for BouncyCastle - why do they have no enum?
	// see: https://github.com/bcgit/bc-java/blob/main/pkix/src/main/java/org/bouncycastle/operator/DefaultSignatureAlgorithmIdentifierFinder.java
	public enum SignatureAlgorithm {
		SHA256WithRSA, SHA512WithRSA,
		SHA256WithECDSA, SHA512WithECDSA
	}

	public record KeyPairGenParameters(Integer keySize, // RSA key size
									   String ecStdName // EC generation parameter standard name
	) {
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
	public static KeyWrapper createClientKeyCertChain(SignatureAlgorithm signatureAlgorithm, KeyPairGenParameters keyPairGenParameters) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, KeyStoreException, InvalidAlgorithmParameterException {

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
	private static KeyCert createKeyCert(SignatureAlgorithm signatureAlgorithm, KeyPairGenParameters keyPairGenParameters, X500Name subjectDN, KeyCert issuer, long serial, boolean isCA) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException {

		KeyPairGenerator kpg;
		switch (signatureAlgorithm) {
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
	private static X500Name createRootCertSubject() {
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
	private static X500Name createIntermediateCertSubject() {
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
	private static X500Name createClientCertSubject() {
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
