package org.keycloak.protocol.oid4vc.issuance.signing;

import org.keycloak.provider.ProviderConfigProperty;

public enum AdditionalSigningProperties {

    DIGEST_ALGORITHM("digestAlgorithm", "Digest Algorithm",
            "Specify the digest ",
            ProviderConfigProperty.STRING_TYPE, "SHA256");

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
