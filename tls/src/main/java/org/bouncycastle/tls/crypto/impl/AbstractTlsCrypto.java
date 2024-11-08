package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.crypto.*;

import java.io.IOException;

/**
 * Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl package.
 */
public abstract class AbstractTlsCrypto
    implements TlsCrypto
{
    public TlsSecret adoptSecret(TlsSecret secret)
    {
        // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
        if (secret instanceof AbstractTlsSecret)
        {
            AbstractTlsSecret sec = (AbstractTlsSecret)secret;

            return createSecret(sec.copyData());
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
     * Create a cipher for the specified encryption and MAC algorithms.
     * <p>
     * See enumeration classes {@link org.bouncycastle.tls.EncryptionAlgorithm}, {@link org.bouncycastle.tls.MACAlgorithm} for appropriate argument values.
     * </p>
     *
     * @param cryptoParams
     *            context specific parameters.
     * @param encryptionAlgorithm
     *            the encryption algorithm to be employed by the cipher.
     * @param macAlgorithm
     *            the MAC algorithm to be employed by the cipher.
     * @return a {@link TlsCipher} implementing the encryption and MAC algorithm.
     * @throws java.io.IOException
     */
    public abstract TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException;
}
