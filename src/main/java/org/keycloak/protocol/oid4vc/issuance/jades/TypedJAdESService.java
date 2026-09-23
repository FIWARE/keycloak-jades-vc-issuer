package org.keycloak.protocol.oid4vc.issuance.jades;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESBuilder;
import eu.europa.esig.dss.jades.signature.JAdESCompactBuilder;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import java.util.List;

/**
 * {@link JAdESService} that writes a caller-chosen {@code typ} into the protected header.
 * <p>
 * DSS derives {@code typ} from the JWS serialization type and hard-codes it to {@code jose} for compact
 * serialization; {@code JAdESSignatureParameters} only offers a boolean that turns the header on or off.
 * SD-JWT VC, however, requires {@code typ: dc+sd-jwt} on the issuer-signed JWT, and the W3C jwt-vc data
 * model wants either no {@code typ} or {@code JWT} - so the value has to be settable.
 * <p>
 * The override happens in {@code incorporateHeader}, which DSS calls while assembling the protected
 * header and before the signing input is derived, so the emitted {@code typ} is covered by the signature.
 *
 * @author <a href="https://github.com/dwendland">Dr. Dennis Wendland</a>
 */
public class TypedJAdESService extends JAdESService {

    private static final String TYPE_HEADER = "typ";

    private final String signatureType;

    /**
     * @param certificateVerifier verifier handed to DSS; a {@code CommonCertificateVerifier} is enough
     *                            for baseline-B, which embeds no validation data
     * @param signatureType       value to write as {@code typ}, or {@code null} to leave DSS's own value
     */
    public TypedJAdESService(CertificateVerifier certificateVerifier, String signatureType) {
        super(certificateVerifier);
        this.signatureType = signatureType;
    }

    @Override
    protected JAdESBuilder getJAdESBuilder(JAdESSignatureParameters parameters, List<DSSDocument> documents) {
        if (signatureType == null) {
            return super.getJAdESBuilder(parameters, documents);
        }
        return new JAdESCompactBuilder(certificateVerifier, parameters, documents) {
            @Override
            protected void incorporateHeader(JWS jws) {
                super.incorporateHeader(jws);
                jws.setHeader(TYPE_HEADER, signatureType);
            }
        };
    }
}
