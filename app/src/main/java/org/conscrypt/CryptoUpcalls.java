package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

final class CryptoUpcalls {
    private static final Logger logger = Logger.getLogger(CryptoUpcalls.class.getName());

    private CryptoUpcalls() {
    }

    private static ArrayList<Provider> getExternalProviders(String algorithm) {
        ArrayList<Provider> providers = new ArrayList<>(1);
        Provider[] providers2 = Security.getProviders(algorithm);
        for (Provider p : providers2) {
            if (!Conscrypt.isConscrypt(p)) {
                providers.add(p);
            }
        }
        if (providers.isEmpty()) {
            logger.warning("Could not find external provider for algorithm: " + algorithm);
        }
        return providers;
    }

    static byte[] ecSignDigestWithPrivateKey(PrivateKey javaKey, byte[] message) {
        if ("EC".equals(javaKey.getAlgorithm())) {
            return signDigestWithPrivateKey(javaKey, message, "NONEwithECDSA");
        }
        throw new RuntimeException("Unexpected key type: " + javaKey.toString());
    }

    private static byte[] signDigestWithPrivateKey(PrivateKey javaKey, byte[] message, String algorithm) {
        Signature signature;
        try {
            signature = Signature.getInstance(algorithm);
            signature.initSign(javaKey);
            if (Conscrypt.isConscrypt(signature.getProvider())) {
                signature = null;
            }
        } catch (NoSuchAlgorithmException e) {
            logger.warning("Unsupported signature algorithm: " + algorithm);
            return null;
        } catch (InvalidKeyException e2) {
            logger.warning("Preferred provider doesn't support key:");
            e2.printStackTrace();
            signature = null;
        }
        if (signature == null) {
            RuntimeException savedRuntimeException = null;
            Iterator<Provider> it = getExternalProviders("Signature." + algorithm).iterator();
            while (it.hasNext()) {
                try {
                    signature = Signature.getInstance(algorithm, it.next());
                    signature.initSign(javaKey);
                    break;
                } catch (InvalidKeyException | NoSuchAlgorithmException e3) {
                    signature = null;
                } catch (RuntimeException e4) {
                    signature = null;
                    if (savedRuntimeException == null) {
                        savedRuntimeException = e4;
                    }
                }
            }
            if (signature == null) {
                if (savedRuntimeException != null) {
                    throw savedRuntimeException;
                }
                logger.warning("Could not find provider for algorithm: " + algorithm);
                return null;
            }
        }
        try {
            signature.update(message);
            return signature.sign();
        } catch (Exception e5) {
            logger.log(Level.WARNING, "Exception while signing message with " + javaKey.getAlgorithm() + " private key:", (Throwable) e5);
            return null;
        }
    }

    static byte[] rsaSignDigestWithPrivateKey(PrivateKey javaKey, int openSSLPadding, byte[] message) {
        return rsaOpWithPrivateKey(javaKey, openSSLPadding, 1, message);
    }

    static byte[] rsaDecryptWithPrivateKey(PrivateKey javaKey, int openSSLPadding, byte[] input) {
        return rsaOpWithPrivateKey(javaKey, openSSLPadding, 2, input);
    }

    /* JADX WARNING: Removed duplicated region for block: B:19:0x009c  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static byte[] rsaOpWithPrivateKey(java.security.PrivateKey r12, int r13, int r14, byte[] r15) {
        /*
        // Method dump skipped, instructions count: 332
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.CryptoUpcalls.rsaOpWithPrivateKey(java.security.PrivateKey, int, int, byte[]):byte[]");
    }
}
