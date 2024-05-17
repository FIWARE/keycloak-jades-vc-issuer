package org.keycloak.protocol.oid4vc.issuance.token;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import org.keycloak.crypto.KeyWrapper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

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
            keyStore.load(null);
            keyStore.setKeyEntry("alias", keyWrapper.getPrivateKey(), pwdChars, keyWrapper.getCertificateChain().toArray(new java.security.cert.Certificate[0]));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new DSSException(e);
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