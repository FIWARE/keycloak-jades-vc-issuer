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
import org.keycloak.protocol.oid4vc.issuance.token.KeycloakKeystoreSignatureTokenConnection;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
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
    private final KeyWrapper signingKey;

    public JAdESJwsSigningService(KeycloakSession keycloakSession, String keyId, String algorithmType,
                                  DigestAlgorithm digestAlgorithm, TimeProvider timeProvider) {
        super(keycloakSession, keyId, algorithmType);
        this.timeProvider = timeProvider;
        this.digestAlgorithm = digestAlgorithm;

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
    public String signCredential(VerifiableCredential verifiableCredential) {

        // Get the issuance date from the credential. Since nbf is mandatory, we set it to the current time if not
        // provided
        long iat = Optional.ofNullable(verifiableCredential.getIssuanceDate())
                .map(issuanceDate -> issuanceDate.toInstant().getEpochSecond())
                .orElse((long) timeProvider.currentTimeSeconds());

        // set mandatory fields
        JsonWebToken jsonWebToken = new JsonWebToken()
                .issuer(verifiableCredential.getIssuer().toString())
                .nbf(iat)
                .id(createCredentialId(verifiableCredential));
        jsonWebToken.setOtherClaims(VC_CLAIM_KEY, verifiableCredential);

        // expiry is optional
        Optional.ofNullable(verifiableCredential.getExpirationDate())
                .ifPresent(d -> jsonWebToken.exp(d.toInstant().getEpochSecond()));

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

        // Get data to be signed
        ObjectMapper objectMapper = new ObjectMapper();
        String myJson;
        try {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            myJson = objectMapper.writeValueAsString(jsonWebToken);
        } catch (JsonProcessingException e) {
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
