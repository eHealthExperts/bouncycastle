package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.crypto.util.EraseUtil;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl package.
 */
public abstract class AbstractTlsCrypto implements TlsCrypto {
    /**
     * Adopt the passed in secret, creating a new copy of it..
     *
     * @param secret
     *            the secret to make a copy of.
     * @return a TlsSecret based the original secret.
     */
    public TlsSecret adoptSecret(final TlsSecret secret) {
        // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
        if (secret instanceof AbstractTlsSecret) {
            final AbstractTlsSecret sec = (AbstractTlsSecret) secret;

            final byte[] copyData = sec.copyData();
            final TlsSecret ret = this.createSecret(copyData);
            EraseUtil.clearByteArray(copyData);
            return ret;
        }

        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }

    /**
     * Create an dhConfig object for the selected CipherSuite and the clientSupportedGroups.
     *
     * @param selectedCipherSuite
     *            the selected CipherSuite to use.
     * @param clientSupportedGroups
     *            the clientSupportedGroups may be null.
     *
     * @return a TlsDHConfig supporting the parameters or null.
     *
     */
    public TlsDHConfig createDHConfig(final int selectedCipherSuite, final int[] clientSupportedGroups) {
        return null;
    }

    /**
     * Return an encryptor based on the public key in certificate.
     *
     * @param certificate
     *            the certificate carrying the public key.
     * @return a TlsEncryptor based on the certificate's public key.
     */
    protected abstract TlsEncryptor createEncryptor(TlsCertificate certificate) throws IOException;
}
