package org.conscrypt;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class OpenSSLRSAPublicKey implements RSAPublicKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 123125005824688292L;
    private transient boolean fetchedParams;
    private transient OpenSSLKey key;
    private BigInteger modulus;
    private BigInteger publicExponent;

    OpenSSLRSAPublicKey(OpenSSLKey key2) {
        this.key = key2;
    }

    @Override // org.conscrypt.OpenSSLKeyHolder
    public OpenSSLKey getOpenSSLKey() {
        return this.key;
    }

    OpenSSLRSAPublicKey(RSAPublicKeySpec spec) throws InvalidKeySpecException {
        try {
            this.key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(spec.getModulus().toByteArray(), spec.getPublicExponent().toByteArray(), null, null, null, null, null, null));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    static OpenSSLKey getInstance(RSAPublicKey rsaPublicKey) throws InvalidKeyException {
        try {
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(rsaPublicKey.getModulus().toByteArray(), rsaPublicKey.getPublicExponent().toByteArray(), null, null, null, null, null, null));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        return NativeCrypto.EVP_marshal_public_key(this.key.getNativeRef());
    }

    private synchronized void ensureReadParams() {
        if (!this.fetchedParams) {
            byte[][] params = NativeCrypto.get_RSA_public_params(this.key.getNativeRef());
            this.modulus = new BigInteger(params[0]);
            this.publicExponent = new BigInteger(params[1]);
            this.fetchedParams = true;
        }
    }

    public BigInteger getModulus() {
        ensureReadParams();
        return this.modulus;
    }

    public BigInteger getPublicExponent() {
        ensureReadParams();
        return this.publicExponent;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if ((o instanceof OpenSSLRSAPublicKey) && this.key.equals(((OpenSSLRSAPublicKey) o).getOpenSSLKey())) {
            return true;
        }
        if (!(o instanceof RSAPublicKey)) {
            return false;
        }
        ensureReadParams();
        RSAPublicKey other = (RSAPublicKey) o;
        return this.modulus.equals(other.getModulus()) && this.publicExponent.equals(other.getPublicExponent());
    }

    public int hashCode() {
        ensureReadParams();
        return this.modulus.hashCode() ^ this.publicExponent.hashCode();
    }

    public String toString() {
        ensureReadParams();
        return "OpenSSLRSAPublicKey{" + "modulus=" + this.modulus.toString(16) + ',' + "publicExponent=" + this.publicExponent.toString(16) + '}';
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
        this.key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(this.modulus.toByteArray(), this.publicExponent.toByteArray(), null, null, null, null, null, null));
        this.fetchedParams = true;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        ensureReadParams();
        stream.defaultWriteObject();
    }
}
