package eu.europa.esig.dss.token;

import org.keycloak.crypto.KeyWrapper;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class KeycloakKeystoreSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

    private KeyStore keyStore;
    private KeyStore.PasswordProtection passwordProtection;

    public KeycloakKeystoreSignatureTokenConnection(KeyWrapper keyWrapper) {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] pwdChars = "pwd".toCharArray();
            passwordProtection = new KeyStore.PasswordProtection(pwdChars);
            keyStore.setKeyEntry("alias", keyWrapper.getPrivateKey(), pwdChars, keyWrapper.getCertificateChain().toArray(new java.security.cert.Certificate[0]));
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected KeyStore getKeyStore() {

        return this.getKeyStore();
    }

    @Override
    protected KeyStore.PasswordProtection getKeyProtectionParameter() {
        return passwordProtection;
    }

    @Override
    public void close() {

    }
}