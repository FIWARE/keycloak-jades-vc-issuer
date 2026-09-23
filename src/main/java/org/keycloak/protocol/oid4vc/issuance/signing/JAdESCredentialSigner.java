package org.keycloak.protocol.oid4vc.issuance.signing;

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
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JAdESCredentialBody;
import org.keycloak.protocol.oid4vc.issuance.token.KeycloakKeystoreSignatureTokenConnection;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * {@link CredentialSigner} producing a JAdES JWS, as specified by ETSI TS 119 182-1.
 * <p>
 * DSS writes the signing certificate chain into the protected header ({@code x5c}), which is what makes the
 * issued credential verifiable through an eIDAS PKIX chain rather than through the issuer DID alone.
 * <p>
 * {@see https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf}
 * {@see https://github.com/esig/dss}
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESCredentialSigner extends AbstractCredentialSigner<String> {

    private static final Logger LOGGER = Logger.getLogger(JAdESCredentialSigner.class);

    /**
     * Alias under which the signing key is held in the in-memory keystore handed to DSS. DSS addresses the
     * key through the {@link KSPrivateKeyEntry} it is given, so the value is never surfaced anywhere.
     */
    private static final String KEY_ALIAS = KeycloakKeystoreSignatureTokenConnection.KEY_ALIAS;

    private final DigestAlgorithm digestAlgorithm;
    private final boolean includeSignatureType;

    public JAdESCredentialSigner(KeycloakSession keycloakSession, DigestAlgorithm digestAlgorithm,
                                 boolean includeSignatureType) {
        super(keycloakSession);
        this.digestAlgorithm = digestAlgorithm;
        this.includeSignatureType = includeSignatureType;
    }

    @Override
    public String signCredential(CredentialBody credentialBody, CredentialBuildConfig credentialBuildConfig)
            throws CredentialSignerException {

        if (!(credentialBody instanceof JAdESCredentialBody jAdESCredentialBody)) {
            throw new CredentialSignerException(
                    String.format("Credential body of type %s cannot be signed as JAdES JWS.",
                            Optional.ofNullable(credentialBody).map(body -> body.getClass().getName()).orElse("null")));
        }

        KeyWrapper signingKey = resolveSigningKey(credentialBuildConfig);

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

        KeyStore.PrivateKeyEntry privateKeyEntry =
                new KeyStore.PrivateKeyEntry((PrivateKey) signingKey.getPrivateKey(),
                        signingKey.getCertificateChain().toArray(new X509Certificate[0]));

        KSPrivateKeyEntry privateKey = new KSPrivateKeyEntry(KEY_ALIAS, privateKeyEntry);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());

        CertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        JAdESService service = new JAdESService(commonCertificateVerifier);

        String serializedCredential;
        try {
            serializedCredential = JsonSerialization.writeValueAsString(jAdESCredentialBody.getJsonWebToken());
        } catch (IOException e) {
            throw new CredentialSignerException("Error when serializing data to be signed.", e);
        }

        DSSDocument toSignDocument = new InMemoryDocument(serializedCredential.getBytes(StandardCharsets.UTF_8));
        toSignDocument.setMimeType(MimeTypeEnum.JSON);
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        try (SignatureTokenConnection signingToken = new KeycloakKeystoreSignatureTokenConnection(signingKey)) {
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            signedDocument.writeTo(stream);
            return stream.toString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new CredentialSignerException("Error when writing the signed document to the output stream.", e);
        }
    }

    /**
     * Resolves the realm key to sign with. {@code overrideKeyId} lets the realm advertise a different
     * {@code kid} than the one the key is stored under, which is what the DID-based setups rely on.
     */
    private KeyWrapper resolveSigningKey(CredentialBuildConfig credentialBuildConfig) {
        String signingKeyId = credentialBuildConfig.getSigningKeyId();
        String signingAlgorithm = credentialBuildConfig.getSigningAlgorithm();
        String overrideKeyId = credentialBuildConfig.getOverrideKeyId();

        KeyWrapper signingKey = overrideKeyId == null
                ? getKey(signingKeyId, signingAlgorithm)
                : getKeyWithKidSubstitute(signingKeyId, signingAlgorithm, overrideKeyId);

        if (signingKey == null) {
            throw new CredentialSignerException(
                    String.format("No key for id %s and algorithm %s available.", signingKeyId, signingAlgorithm));
        }
        if (signingKey.getCertificateChain() == null || signingKey.getCertificateChain().isEmpty()) {
            throw new CredentialSignerException(
                    String.format("Key %s carries no certificate chain, so no x5c header can be issued.", signingKeyId));
        }

        LOGGER.debugf("Signing credential as JAdES JWS with key %s and algorithm %s.", signingKeyId, signingAlgorithm);
        return signingKey;
    }
}
