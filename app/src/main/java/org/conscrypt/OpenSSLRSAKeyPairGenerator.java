package org.conscrypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public final class OpenSSLRSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private int modulusBits = 2048;
    private byte[] publicExponent = {1, 0, 1};

    public KeyPair generateKeyPair() {
        OpenSSLKey key = new OpenSSLKey(NativeCrypto.RSA_generate_key_ex(this.modulusBits, this.publicExponent));
        return new KeyPair(new OpenSSLRSAPublicKey(key), OpenSSLRSAPrivateKey.getInstance(key));
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(int keysize, SecureRandom random) {
        this.modulusBits = keysize;
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof RSAKeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only RSAKeyGenParameterSpec supported");
        }
        RSAKeyGenParameterSpec spec = (RSAKeyGenParameterSpec) params;
        BigInteger publicExponent2 = spec.getPublicExponent();
        if (publicExponent2 != null) {
            this.publicExponent = publicExponent2.toByteArray();
        }
        this.modulusBits = spec.getKeysize();
    }
}
