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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JAdESCredentialBuilder;
import org.keycloak.protocol.oid4vc.issuance.signing.JAdESCredentialSigner;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
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

public class JAdESCredentialSignerTest {

	private static final String ISSUER_DID = "did:elsi:VATDE-1234567";
	private JAdESCredentialSigner jAdESCredentialSigner;
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

		KeyWrapper signingKey = KeyCertFixtures.createClientKeyCertChain(signCredentialTestInput.signatureAlgorithm(),
				signCredentialTestInput.keyPairGenParameters());
		String signatureAlgorithm = signCredentialTestInput.signatureAlgorithm().toString();
		when(keyManager.getKey(any(), eq(signatureAlgorithm), any(), anyString())).thenReturn(signingKey);

		// since 26.4 the claim set is assembled by a CredentialBuilder and only then handed to the signer
		CredentialBuildConfig credentialBuildConfig = new CredentialBuildConfig()
				.setSigningKeyId(signatureAlgorithm)
				.setSigningAlgorithm(signatureAlgorithm)
				// the realm configures the typ header through credential_build_config.token_jws_type
				.setTokenJwsType(signCredentialTestExpectedValues.headerType());
		CredentialBody credentialBody = new JAdESCredentialBuilder(new OffsetTimeProvider(), keycloakSession)
				.buildCredentialBody(vc, credentialBuildConfig);

		jAdESCredentialSigner = new JAdESCredentialSigner(keycloakSession,
				signCredentialTestInput.digestAlgorithm(), signCredentialTestInput.includeSignatureType());

		String signedCredentialJwt = jAdESCredentialSigner.signCredential(credentialBody, credentialBuildConfig);

		// Verify result
		verifyJwt(signedCredentialJwt, signingKey,
				signCredentialTestInput.signatureAlgorithm(), signCredentialTestExpectedValues);
	}

	// Verify the signed JWT
	private void verifyJwt(String signedJwt, KeyWrapper signingKey, KeyCertFixtures.SignatureAlgorithm signatureAlgorithm,
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
		if (signCredentialTestExpectedValues.headerType() != null) {
			assertEquals(signCredentialTestExpectedValues.headerType(), jwtHeader.getType(),
					"Type in header should equal expected type");
		} else {
			assertNull(jwtHeader.getType(), "Header should not contain parameter 'typ'");
		}
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

		assertTrue(((List) headers.get("crit")).contains("sigT"),
				"Header 'crit' should contain 'sigT'");


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
						KeyCertFixtures.SignatureAlgorithm.SHA256WithRSA,
						new KeyCertFixtures.KeyPairGenParameters(4096, null),
						DigestAlgorithm.SHA256, ISSUER_DID, false
				), new SignCredentialTestExpectedValues(
						"RS256", null, KeyCertFixtures.CERT_CHAIN_LENGTH, ISSUER_DID
				)),
				getArguments(new SignCredentialTestInput(
						KeyCertFixtures.SignatureAlgorithm.SHA512WithRSA,
						new KeyCertFixtures.KeyPairGenParameters(4096, null),
						DigestAlgorithm.SHA512, ISSUER_DID, false
				), new SignCredentialTestExpectedValues(
						"RS512", null, KeyCertFixtures.CERT_CHAIN_LENGTH, ISSUER_DID
				)),
				getArguments(new SignCredentialTestInput(
						KeyCertFixtures.SignatureAlgorithm.SHA256WithECDSA,
						new KeyCertFixtures.KeyPairGenParameters(null, "secp256r1"),
						DigestAlgorithm.SHA256, ISSUER_DID, false
				), new SignCredentialTestExpectedValues(
						"ES256", null, KeyCertFixtures.CERT_CHAIN_LENGTH, ISSUER_DID
				)),
				getArguments(new SignCredentialTestInput(
						KeyCertFixtures.SignatureAlgorithm.SHA512WithECDSA,
						new KeyCertFixtures.KeyPairGenParameters(null, "secp521r1"),
						DigestAlgorithm.SHA512, ISSUER_DID, false
				), new SignCredentialTestExpectedValues(
						"ES512", null, KeyCertFixtures.CERT_CHAIN_LENGTH, ISSUER_DID
				)),
				// token_jws_type from the credential configuration reaches the protected header
				getArguments(new SignCredentialTestInput(
						KeyCertFixtures.SignatureAlgorithm.SHA256WithRSA,
						new KeyCertFixtures.KeyPairGenParameters(4096, null),
						DigestAlgorithm.SHA256, ISSUER_DID, false
				), new SignCredentialTestExpectedValues(
						"RS256", "JWT", KeyCertFixtures.CERT_CHAIN_LENGTH, ISSUER_DID
				))
		);
	}

	public record SignCredentialTestInput(KeyCertFixtures.SignatureAlgorithm signatureAlgorithm,
										  KeyCertFixtures.KeyPairGenParameters keyPairGenParameters,
										  DigestAlgorithm digestAlgorithm,
										  String vcIssuer,
										  boolean includeSignatureType) {
	}

	public record SignCredentialTestExpectedValues(String headerAlgorithm,
												   String headerType,
												   int headerX5cLength,
												   String vcIssuer) {
	}

	// Create VC object
	private VerifiableCredential createVC(String issuer) throws URISyntaxException {
		VerifiableCredential vc = new VerifiableCredential();
		vc.setIssuer(new URI(issuer));
		vc.setType(List.of("VerifiableCredential"));
		vc.setIssuanceDate(Instant.now());

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

}
