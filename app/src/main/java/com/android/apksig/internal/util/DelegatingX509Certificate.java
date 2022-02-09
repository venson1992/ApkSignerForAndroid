package com.android.apksig.internal.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class DelegatingX509Certificate extends X509Certificate {
    private static final long serialVersionUID = 1;
    private final X509Certificate mDelegate;

    public DelegatingX509Certificate(X509Certificate delegate) {
        this.mDelegate = delegate;
    }

    @Override // java.security.cert.X509Extension
    public Set<String> getCriticalExtensionOIDs() {
        return this.mDelegate.getCriticalExtensionOIDs();
    }

    public byte[] getExtensionValue(String oid) {
        return this.mDelegate.getExtensionValue(oid);
    }

    @Override // java.security.cert.X509Extension
    public Set<String> getNonCriticalExtensionOIDs() {
        return this.mDelegate.getNonCriticalExtensionOIDs();
    }

    public boolean hasUnsupportedCriticalExtension() {
        return this.mDelegate.hasUnsupportedCriticalExtension();
    }

    @Override // java.security.cert.X509Certificate
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        this.mDelegate.checkValidity();
    }

    @Override // java.security.cert.X509Certificate
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        this.mDelegate.checkValidity(date);
    }

    public int getVersion() {
        return this.mDelegate.getVersion();
    }

    public BigInteger getSerialNumber() {
        return this.mDelegate.getSerialNumber();
    }

    public Principal getIssuerDN() {
        return this.mDelegate.getIssuerDN();
    }

    public Principal getSubjectDN() {
        return this.mDelegate.getSubjectDN();
    }

    public Date getNotBefore() {
        return this.mDelegate.getNotBefore();
    }

    public Date getNotAfter() {
        return this.mDelegate.getNotAfter();
    }

    @Override // java.security.cert.X509Certificate
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return this.mDelegate.getTBSCertificate();
    }

    public byte[] getSignature() {
        return this.mDelegate.getSignature();
    }

    public String getSigAlgName() {
        return this.mDelegate.getSigAlgName();
    }

    public String getSigAlgOID() {
        return this.mDelegate.getSigAlgOID();
    }

    public byte[] getSigAlgParams() {
        return this.mDelegate.getSigAlgParams();
    }

    public boolean[] getIssuerUniqueID() {
        return this.mDelegate.getIssuerUniqueID();
    }

    public boolean[] getSubjectUniqueID() {
        return this.mDelegate.getSubjectUniqueID();
    }

    public boolean[] getKeyUsage() {
        return this.mDelegate.getKeyUsage();
    }

    public int getBasicConstraints() {
        return this.mDelegate.getBasicConstraints();
    }

    @Override // java.security.cert.Certificate
    public byte[] getEncoded() throws CertificateEncodingException {
        return this.mDelegate.getEncoded();
    }

    @Override // java.security.cert.Certificate
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        this.mDelegate.verify(key);
    }

    @Override // java.security.cert.Certificate
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        this.mDelegate.verify(key, sigProvider);
    }

    public String toString() {
        return this.mDelegate.toString();
    }

    public PublicKey getPublicKey() {
        return this.mDelegate.getPublicKey();
    }

    public X500Principal getIssuerX500Principal() {
        return this.mDelegate.getIssuerX500Principal();
    }

    public X500Principal getSubjectX500Principal() {
        return this.mDelegate.getSubjectX500Principal();
    }

    @Override // java.security.cert.X509Certificate
    public List<String> getExtendedKeyUsage() throws CertificateParsingException {
        return this.mDelegate.getExtendedKeyUsage();
    }

    @Override // java.security.cert.X509Certificate
    public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
        return this.mDelegate.getSubjectAlternativeNames();
    }

    @Override // java.security.cert.X509Certificate
    public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
        return this.mDelegate.getIssuerAlternativeNames();
    }

    @Override // java.security.cert.X509Certificate, java.security.cert.Certificate
    public void verify(PublicKey key, Provider sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        this.mDelegate.verify(key, sigProvider);
    }
}
