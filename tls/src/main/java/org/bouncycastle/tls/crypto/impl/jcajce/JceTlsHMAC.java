package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.jcajce.provider.asymmetric.DestroyableSecretKeySpec;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHMAC;

/**
 * Wrapper class for a JCE MAC based on HMAC to provide the necessary operations for TLS.
 */
public class JceTlsHMAC
    implements TlsHMAC
{
    private final Mac hmac;
    private final String algorithm;
    private final int internalBlockSize;

    private DestroyableSecretKeySpec secretKeySpec;

    /**
     * Base constructor.
     *
     * @param cryptoHashAlgorithm the hash algorithm underlying the MAC implementation
     * @param hmac MAC implementation.
     * @param algorithm algorithm name to use for keys and to get the internal block size.
     */
    public JceTlsHMAC(int cryptoHashAlgorithm, Mac hmac, String algorithm)
    {
        this.hmac = hmac;
        this.algorithm = algorithm;
        this.internalBlockSize = TlsCryptoUtils.getHashInternalSize(cryptoHashAlgorithm);
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        try
        {
            secretKeySpec =new DestroyableSecretKeySpec(key, keyOff, keyLen, algorithm);
            hmac.init(secretKeySpec);
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public void update(byte[] input, int inOff, int length)
    {
        hmac.update(input, inOff, length);
    }

    public byte[] calculateMAC()
    {
        byte[] mac = hmac.doFinal();
        reset();
        return mac;
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        try
        {
            hmac.doFinal(output, outOff);
            reset();
        }
        catch (ShortBufferException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public int getInternalBlockSize()
    {
        return internalBlockSize;
    }

    public int getMacLength()
    {
        return hmac.getMacLength();
    }

    public void reset()
    {
        if (secretKeySpec != null)
        {
            try
            {
                secretKeySpec.destroy();
            }
            catch (final DestroyFailedException e)
            {
                //ignore
            }
        }
        hmac.reset();
    }
}
