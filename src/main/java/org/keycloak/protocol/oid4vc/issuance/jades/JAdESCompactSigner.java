package org.keycloak.protocol.oid4vc.issuance.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.oid4vc.issuance.token.KeycloakKeystoreSignatureTokenConnection;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Signs a payload as a JAdES baseline-B compact JWS, as specified by ETSI TS 119 182-1.
 * <p>
 * DSS writes the signing certificate chain into the protected header ({@code x5c}) along with the signing
 * time ({@code sigT}, listed in {@code crit}), which is what makes the issued credential verifiable
 * through an eIDAS PKIX chain rather than through the issuer DID alone. Shared by the {@code jwt_vc_json}
 * and {@code dc+sd-jwt} signers, which differ only in the payload they hand over and the {@code typ} they
 * ask for.
 * <p>
 * {@see https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf}
 * {@see https://github.com/esig/dss}
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class JAdESCompactSigner {

    private final DigestAlgorithm digestAlgorithm;
    private final boolean includeSignatureType;

    /**
     * @param digestAlgorithm      digest used for the signature
     * @param includeSignatureType whether DSS may write a {@code typ} header of its own when the caller
     *                             asks for no specific type. Per default DSS sets {@code typ} to
     *                             {@code jose}, which conflicts with the W3C jwt-vc data model, while
     *                             RFC 7515 makes the parameter optional.
     */
    public JAdESCompactSigner(DigestAlgorithm digestAlgorithm, boolean includeSignatureType) {
        this.digestAlgorithm = digestAlgorithm;
        this.includeSignatureType = includeSignatureType;
    }

    /**
     * Signs the given payload and returns the compact JAdES JWS.
     *
     * @param payload       payload to sign, serialized as JSON
     * @param signingKey    realm key to sign with; it must carry a certificate chain
     * @param signatureType value for the {@code typ} header, or {@code null} to let DSS decide
     * @return the compact serialization {@code <protected>.<payload>.<signature>}
     * @throws IOException if the signed document cannot be written
     */
    public String sign(byte[] payload, KeyWrapper signingKey, String signatureType) throws IOException {

        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        parameters.setDigestAlgorithm(digestAlgorithm);

        // when a type is forced, DSS has to emit the header for TypedJAdESService to overwrite it
        parameters.setIncludeSignatureType(signatureType != null || includeSignatureType);

        KeyStore.PrivateKeyEntry privateKeyEntry =
                new KeyStore.PrivateKeyEntry((PrivateKey) signingKey.getPrivateKey(),
                        signingKey.getCertificateChain().toArray(new X509Certificate[0]));
        KSPrivateKeyEntry privateKey =
                new KSPrivateKeyEntry(KeycloakKeystoreSignatureTokenConnection.KEY_ALIAS, privateKeyEntry);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());

        TypedJAdESService service = new TypedJAdESService(new CommonCertificateVerifier(), signatureType);

        DSSDocument toSignDocument = new InMemoryDocument(payload);
        toSignDocument.setMimeType(MimeTypeEnum.JSON);
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        try (SignatureTokenConnection signingToken = new KeycloakKeystoreSignatureTokenConnection(signingKey)) {
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            signedDocument.writeTo(stream);
            return stream.toString(StandardCharsets.UTF_8);
        }
    }
}
