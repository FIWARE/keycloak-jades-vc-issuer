package org.keycloak.protocol.oid4vc.issuance.signing;

import org.keycloak.provider.ProviderConfigProperty;

public enum AdditionalSigningProperties {

    SIGNATURE_LEVEL("signatureLevel", "Signature level",
            "Level of the signature (JAdES_BASELINE_B, JAdES_BASELINE_T, JAdES_BASELINE_LT, JAdES_BASELINE_LTA)",
            ProviderConfigProperty.STRING_TYPE, "JAdES_BASELINE_B"),
    JWS_SERIALIZATION_TYPE("jwsSerializationType", "JWS Serialization Type",
            "A JWS signature can be represented in different forms: COMPACT_SERIALIZATION, JSON_SERIALIZATION, FLATTENED_JSON_SERIALIZATION",
            ProviderConfigProperty.STRING_TYPE, "COMPACT_SERIALIZATION"),
    ONLINE_TSP_SOURCES("onlineTspSources", "Online TSP Sources",
            "Timestamp sources are required for signature levels JAdES_BASELINE_T and JAdES_BASELINE_LTA. This parameter allows to set online TSP sources.",
            ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null),
    TSP_SOURCE_KEY_ID("tspSourceKeyId", "Id of the KeyEntity TSP source signing key.",
            "Timestamp sources are required for signature levels JAdES_BASELINE_T and JAdES_BASELINE_LTA. This parameter allows to set the id of the key to be used for creating timestamp tokens. The key needs to be provided as a realm key.",
            ProviderConfigProperty.STRING_TYPE, null),
    TSP_SOURCE_KEY_ALGORITHM_TYPE("tspSourceKeyAlgorithmType", "Algorithm type of the KeyEntity TSP source signing key.",
            "Timestamp sources are required for signature levels JAdES_BASELINE_T and JAdES_BASELINE_LTA. This parameter allows to set the type of the algorithm, fitting the provided key used for creating timestamp tokens.",
            ProviderConfigProperty.STRING_TYPE, null);

    private final String key;
    private final String label;
    private final String helpText;
    private final String type;
    private final Object defaultValue;

    AdditionalSigningProperties(String key, String label, String helpText, String type, Object defaultValue) {
        this.key = key;
        this.label = label;
        this.helpText = helpText;
        this.type = type;
        this.defaultValue = defaultValue;
    }


    public ProviderConfigProperty asConfigProperty() {
        return new ProviderConfigProperty(key, label, helpText, type, defaultValue);
    }

    public String getKey() {
        return key;
    }
}
