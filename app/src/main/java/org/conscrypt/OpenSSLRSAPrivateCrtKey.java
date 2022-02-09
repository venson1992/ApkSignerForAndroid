package org.conscrypt;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAPrivateCrtKey {
    private static final long serialVersionUID = 3785291944868707197L;
    private BigInteger crtCoefficient;
    private BigInteger primeExponentP;
    private BigInteger primeExponentQ;
    private BigInteger primeP;
    private BigInteger primeQ;
    private BigInteger publicExponent;

    OpenSSLRSAPrivateCrtKey(OpenSSLKey key) {
        super(key);
    }

    OpenSSLRSAPrivateCrtKey(OpenSSLKey key, byte[][] params) {
        super(key, params);
    }

    OpenSSLRSAPrivateCrtKey(RSAPrivateCrtKeySpec rsaKeySpec) throws InvalidKeySpecException {
        super(init(rsaKeySpec));
    }

    private static OpenSSLKey init(RSAPrivateCrtKeySpec rsaKeySpec) throws InvalidKeySpecException {
        byte[] byteArray;
        BigInteger modulus = rsaKeySpec.getModulus();
        BigInteger privateExponent = rsaKeySpec.getPrivateExponent();
        if (modulus == null) {
            throw new InvalidKeySpecException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeySpecException("privateExponent == null");
        } else {
            try {
                BigInteger publicExponent2 = rsaKeySpec.getPublicExponent();
                BigInteger primeP2 = rsaKeySpec.getPrimeP();
                BigInteger primeQ2 = rsaKeySpec.getPrimeQ();
                BigInteger primeExponentP2 = rsaKeySpec.getPrimeExponentP();
                BigInteger primeExponentQ2 = rsaKeySpec.getPrimeExponentQ();
                BigInteger crtCoefficient2 = rsaKeySpec.getCrtCoefficient();
                byte[] byteArray2 = modulus.toByteArray();
                byte[] byteArray3 = publicExponent2 == null ? null : publicExponent2.toByteArray();
                byte[] byteArray4 = privateExponent.toByteArray();
                byte[] byteArray5 = primeP2 == null ? null : primeP2.toByteArray();
                byte[] byteArray6 = primeQ2 == null ? null : primeQ2.toByteArray();
                byte[] byteArray7 = primeExponentP2 == null ? null : primeExponentP2.toByteArray();
                byte[] byteArray8 = primeExponentQ2 == null ? null : primeExponentQ2.toByteArray();
                if (crtCoefficient2 == null) {
                    byteArray = null;
                } else {
                    byteArray = crtCoefficient2.toByteArray();
                }
                return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(byteArray2, byteArray3, byteArray4, byteArray5, byteArray6, byteArray7, byteArray8, byteArray));
            } catch (Exception e) {
                throw new InvalidKeySpecException(e);
            }
        }
    }

    static OpenSSLKey getInstance(RSAPrivateCrtKey rsaPrivateKey) throws InvalidKeyException {
        byte[] byteArray;
        if (rsaPrivateKey.getFormat() == null) {
            return wrapPlatformKey(rsaPrivateKey);
        }
        BigInteger modulus = rsaPrivateKey.getModulus();
        BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();
        if (modulus == null) {
            throw new InvalidKeyException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeyException("privateExponent == null");
        } else {
            try {
                BigInteger publicExponent2 = rsaPrivateKey.getPublicExponent();
                BigInteger primeP2 = rsaPrivateKey.getPrimeP();
                BigInteger primeQ2 = rsaPrivateKey.getPrimeQ();
                BigInteger primeExponentP2 = rsaPrivateKey.getPrimeExponentP();
                BigInteger primeExponentQ2 = rsaPrivateKey.getPrimeExponentQ();
                BigInteger crtCoefficient2 = rsaPrivateKey.getCrtCoefficient();
                byte[] byteArray2 = modulus.toByteArray();
                byte[] byteArray3 = publicExponent2 == null ? null : publicExponent2.toByteArray();
                byte[] byteArray4 = privateExponent.toByteArray();
                byte[] byteArray5 = primeP2 == null ? null : primeP2.toByteArray();
                byte[] byteArray6 = primeQ2 == null ? null : primeQ2.toByteArray();
                byte[] byteArray7 = primeExponentP2 == null ? null : primeExponentP2.toByteArray();
                byte[] byteArray8 = primeExponentQ2 == null ? null : primeExponentQ2.toByteArray();
                if (crtCoefficient2 == null) {
                    byteArray = null;
                } else {
                    byteArray = crtCoefficient2.toByteArray();
                }
                return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(byteArray2, byteArray3, byteArray4, byteArray5, byteArray6, byteArray7, byteArray8, byteArray));
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLRSAPrivateKey
    public synchronized void readParams(byte[][] params) {
        super.readParams(params);
        if (params[1] != null) {
            this.publicExponent = new BigInteger(params[1]);
        }
        if (params[3] != null) {
            this.primeP = new BigInteger(params[3]);
        }
        if (params[4] != null) {
            this.primeQ = new BigInteger(params[4]);
        }
        if (params[5] != null) {
            this.primeExponentP = new BigInteger(params[5]);
        }
        if (params[6] != null) {
            this.primeExponentQ = new BigInteger(params[6]);
        }
        if (params[7] != null) {
            this.crtCoefficient = new BigInteger(params[7]);
        }
    }

    public BigInteger getPublicExponent() {
        ensureReadParams();
        return this.publicExponent;
    }

    public BigInteger getPrimeP() {
        ensureReadParams();
        return this.primeP;
    }

    public BigInteger getPrimeQ() {
        ensureReadParams();
        return this.primeQ;
    }

    public BigInteger getPrimeExponentP() {
        ensureReadParams();
        return this.primeExponentP;
    }

    public BigInteger getPrimeExponentQ() {
        ensureReadParams();
        return this.primeExponentQ;
    }

    public BigInteger getCrtCoefficient() {
        ensureReadParams();
        return this.crtCoefficient;
    }

    @Override // org.conscrypt.OpenSSLRSAPrivateKey
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof OpenSSLRSAPrivateKey) {
            return getOpenSSLKey().equals(((OpenSSLRSAPrivateKey) o).getOpenSSLKey());
        }
        if (o instanceof RSAPrivateCrtKey) {
            ensureReadParams();
            RSAPrivateCrtKey other = (RSAPrivateCrtKey) o;
            return getOpenSSLKey().isHardwareBacked() ? getModulus().equals(other.getModulus()) && this.publicExponent.equals(other.getPublicExponent()) : getModulus().equals(other.getModulus()) && this.publicExponent.equals(other.getPublicExponent()) && getPrivateExponent().equals(other.getPrivateExponent()) && this.primeP.equals(other.getPrimeP()) && this.primeQ.equals(other.getPrimeQ()) && this.primeExponentP.equals(other.getPrimeExponentP()) && this.primeExponentQ.equals(other.getPrimeExponentQ()) && this.crtCoefficient.equals(other.getCrtCoefficient());
        } else if (!(o instanceof RSAPrivateKey)) {
            return false;
        } else {
            ensureReadParams();
            RSAPrivateKey other2 = (RSAPrivateKey) o;
            if (getOpenSSLKey().isHardwareBacked()) {
                return getModulus().equals(other2.getModulus());
            }
            return getModulus().equals(other2.getModulus()) && getPrivateExponent().equals(other2.getPrivateExponent());
        }
    }

    @Override // org.conscrypt.OpenSSLRSAPrivateKey
    public final int hashCode() {
        int hashCode = super.hashCode();
        if (this.publicExponent != null) {
            return hashCode ^ this.publicExponent.hashCode();
        }
        return hashCode;
    }

    @Override // org.conscrypt.OpenSSLRSAPrivateKey
    public String toString() {
        StringBuilder sb = new StringBuilder("OpenSSLRSAPrivateCrtKey{");
        ensureReadParams();
        sb.append("modulus=");
        sb.append(getModulus().toString(16));
        if (this.publicExponent != null) {
            sb.append(',');
            sb.append("publicExponent=");
            sb.append(this.publicExponent.toString(16));
        }
        sb.append('}');
        return sb.toString();
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        byte[] bArr = null;
        stream.defaultReadObject();
        byte[] byteArray = this.modulus.toByteArray();
        byte[] byteArray2 = this.publicExponent == null ? null : this.publicExponent.toByteArray();
        byte[] byteArray3 = this.privateExponent.toByteArray();
        byte[] byteArray4 = this.primeP == null ? null : this.primeP.toByteArray();
        byte[] byteArray5 = this.primeQ == null ? null : this.primeQ.toByteArray();
        byte[] byteArray6 = this.primeExponentP == null ? null : this.primeExponentP.toByteArray();
        byte[] byteArray7 = this.primeExponentQ == null ? null : this.primeExponentQ.toByteArray();
        if (this.crtCoefficient != null) {
            bArr = this.crtCoefficient.toByteArray();
        }
        this.key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(byteArray, byteArray2, byteArray3, byteArray4, byteArray5, byteArray6, byteArray7, bArr));
        this.fetchedParams = true;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (getOpenSSLKey().isHardwareBacked()) {
            throw new NotSerializableException("Hardware backed keys cannot be serialized");
        }
        ensureReadParams();
        stream.defaultWriteObject();
    }
}
