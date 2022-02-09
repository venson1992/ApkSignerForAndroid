package org.conscrypt;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

class KeyManagerImpl extends X509ExtendedKeyManager {
    private final HashMap<String, KeyStore.PrivateKeyEntry> hash = new HashMap<>();

    KeyManagerImpl(KeyStore keyStore, char[] pwd) {
        KeyStore.PrivateKeyEntry entry;
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                try {
                    if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                        try {
                            entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(pwd));
                        } catch (UnsupportedOperationException e) {
                            entry = new KeyStore.PrivateKeyEntry((PrivateKey) keyStore.getKey(alias, pwd), keyStore.getCertificateChain(alias));
                        }
                        this.hash.put(alias, entry);
                    }
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e2) {
                }
            }
        } catch (KeyStoreException e3) {
        }
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(keyTypes, issuers);
        if (al == null) {
            return null;
        }
        return al[0];
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(new String[]{keyType}, issuers);
        if (al == null) {
            return null;
        }
        return al[0];
    }

    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] xcerts = null;
        if (alias != null && this.hash.containsKey(alias)) {
            Certificate[] certs = this.hash.get(alias).getCertificateChain();
            if (certs[0] instanceof X509Certificate) {
                xcerts = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    xcerts[i] = (X509Certificate) certs[i];
                }
            }
        }
        return xcerts;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[]{keyType}, issuers);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[]{keyType}, issuers);
    }

    public PrivateKey getPrivateKey(String alias) {
        if (alias != null && this.hash.containsKey(alias)) {
            return this.hash.get(alias).getPrivateKey();
        }
        return null;
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        String[] al = chooseAlias(keyTypes, issuers);
        if (al == null) {
            return null;
        }
        return al[0];
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        String[] al = chooseAlias(new String[]{keyType}, issuers);
        if (al == null) {
            return null;
        }
        return al[0];
    }

    private String[] chooseAlias(String[] keyTypes, Principal[] issuers) {
        String certSigAlg;
        String sigAlgorithm;
        if (keyTypes == null || keyTypes.length == 0) {
            return null;
        }
        List<Principal> issuersList = issuers == null ? null : Arrays.asList(issuers);
        ArrayList<String> found = new ArrayList<>();
        for (Map.Entry<String, KeyStore.PrivateKeyEntry> entry : this.hash.entrySet()) {
            String alias = entry.getKey();
            Certificate[] chain = entry.getValue().getCertificateChain();
            Certificate cert = chain[0];
            String certKeyAlg = cert.getPublicKey().getAlgorithm();
            if (cert instanceof X509Certificate) {
                certSigAlg = ((X509Certificate) cert).getSigAlgName().toUpperCase(Locale.US);
            } else {
                certSigAlg = null;
            }
            int length = keyTypes.length;
            for (int i = 0; i < length; i++) {
                String keyAlgorithm = keyTypes[i];
                if (keyAlgorithm != null) {
                    int index = keyAlgorithm.indexOf(95);
                    if (index == -1) {
                        sigAlgorithm = null;
                    } else {
                        sigAlgorithm = keyAlgorithm.substring(index + 1);
                        keyAlgorithm = keyAlgorithm.substring(0, index);
                    }
                    if (certKeyAlg.equals(keyAlgorithm) && (sigAlgorithm == null || certSigAlg == null || certSigAlg.contains(sigAlgorithm))) {
                        if (issuers == null || issuers.length == 0) {
                            found.add(alias);
                        } else {
                            int length2 = chain.length;
                            for (int i2 = 0; i2 < length2; i2++) {
                                Certificate certFromChain = chain[i2];
                                if ((certFromChain instanceof X509Certificate) && issuersList.contains(((X509Certificate) certFromChain).getIssuerX500Principal())) {
                                    found.add(alias);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!found.isEmpty()) {
            return (String[]) found.toArray(new String[found.size()]);
        }
        return null;
    }
}
