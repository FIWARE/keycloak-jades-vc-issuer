package org.keycloak.protocol.oid4vc.issuance.signing;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.token.KeycloakKeystoreSignatureTokenConnection;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.util.ObjectMapperResolver;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.UUID;

/**
 * {@link VerifiableCredentialsSigningService} implementing the JAdES JWS format. It returns a string, containing the
 * Signed Credential
 * {@see https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf}
 * {@see https://github.com/esig/dss}
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESJwsSigningService extends SigningService<String> {

	private static final Logger LOGGER = Logger.getLogger(JAdESJwsSigningService.class);

	private static final String ID_TEMPLATE = "urn:uuid:%s";
	private static final String VC_CLAIM_KEY = "vc";
	private static final String ID_CLAIM_KEY = "id";

	private final TimeProvider timeProvider;
	private final DigestAlgorithm digestAlgorithm;
	private final boolean includeSignatureType;
	private final KeyWrapper signingKey;

	public JAdESJwsSigningService(KeycloakSession keycloakSession, String keyId, String algorithmType,
								  DigestAlgorithm digestAlgorithm, boolean includeSignatureType,
								  TimeProvider timeProvider) {
		super(keycloakSession, keyId, Format.JWT_VC, algorithmType);
		this.timeProvider = timeProvider;
		this.digestAlgorithm = digestAlgorithm;
		this.includeSignatureType = includeSignatureType;

		signingKey = getKey(keyId, algorithmType);
		if (signingKey == null) {
			throw new SigningServiceException(String.format("No key for id %s and algorithm %s available.",
					keyId, algorithmType));
		}

		LOGGER.debugf("Successfully initiated the JAdES JWS Signing Service with algorithm %s.", algorithmType);
	}

	// retrieve the credential id from the given VC or generate one.
	static String createCredentialId(VerifiableCredential verifiableCredential) {
		return Optional.ofNullable(
						verifiableCredential.getId())
				.orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())))
				.toString();
	}

	@Override
	public String signCredential(VCIssuanceContext vcIssuanceContext) {

		VerifiableCredential verifiableCredential = vcIssuanceContext.getVerifiableCredential();

		// Get the issuance date from the credential. Since nbf is mandatory, we set it to the current time if not
		// provided
		long iat = Optional.ofNullable(verifiableCredential.getIssuanceDate())
				.map(Instant::getEpochSecond)
				.orElse((long) timeProvider.currentTimeSeconds());

		// set mandatory fields
		JsonWebToken jsonWebToken = new JsonWebToken()
				.issuer(verifiableCredential.getIssuer().toString())
				.nbf(iat)
				.id(createCredentialId(verifiableCredential));
		jsonWebToken.setOtherClaims(VC_CLAIM_KEY, verifiableCredential);

		// expiry is optional
		Optional.ofNullable(verifiableCredential.getExpirationDate())
				.ifPresent(d -> jsonWebToken.exp(d.getEpochSecond()));

		// subject id should only be set if the credential subject has an id.
		Optional.ofNullable(
						verifiableCredential
								.getCredentialSubject()
								.getClaims()
								.get(ID_CLAIM_KEY))
				.map(Object::toString)
				.ifPresent(jsonWebToken::subject);

		// Prepare JAdES signature parameters
		JAdESSignatureParameters parameters = new JAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
		parameters.setDigestAlgorithm(digestAlgorithm);

		// Per default, DSS sets the typ header parameter to "jose"
		// See: https://github.com/esig/dss/blob/9ad259927d215fb85eb51b004129b9fc701cf177/dss-jades/src/main/java/eu/europa/esig/dss/jades/signature/JAdESLevelBaselineB.java#L277
		// This is in conflict to the W3C jwt-vc data model: https://www.w3.org/TR/vc-data-model/#jwt-encoding
		// According to RfC7515, the typ parameter is optional: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
		// Therefore disabling the setting of the typ parameter here per default (can be overridden with config)
		parameters.setIncludeSignatureType(includeSignatureType);

		// Set certificates and key
		KeyStore.PrivateKeyEntry privateKeyEntry =
				new KeyStore.PrivateKeyEntry((PrivateKey) signingKey.getPrivateKey(),
						signingKey.getCertificateChain().toArray(new X509Certificate[0]));

		KSPrivateKeyEntry privateKey = new KSPrivateKeyEntry(signingKey.getProviderId(), privateKeyEntry);
		parameters.setSigningCertificate(privateKey.getCertificate());
		parameters.setCertificateChain(privateKey.getCertificateChain());
		SignatureTokenConnection signingToken = new KeycloakKeystoreSignatureTokenConnection(signingKey);

		// JAdES Service init
		CertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		JAdESService service = new JAdESService(commonCertificateVerifier);

		String myJson;
		try {
			myJson = JsonSerialization.writeValueAsString(jsonWebToken);
		} catch (IOException e) {
			throw new SigningServiceException(
					String.format("Error when serializing data to be signed: %s", e));
		}

		DSSDocument toSignDocument = new InMemoryDocument(myJson.getBytes());
		toSignDocument.setMimeType(MimeTypeEnum.JSON);
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		// Get signature using private key
		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

		// Sign document
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		ByteArrayOutputStream stream
				= new ByteArrayOutputStream();
		try {
			signedDocument.writeTo(stream);
		} catch (IOException e) {
			throw new SigningServiceException(
					String.format("Error when writing signed document to output stream: %s", e));
		}

		return new String(stream.toByteArray());
	}
}
