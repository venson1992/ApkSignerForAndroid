package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.conscrypt.NativeRef;

public class ECParameters extends AlgorithmParametersSpi {
    private OpenSSLECGroupContext curve;

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof ECGenParameterSpec) {
            String newCurveName = ((ECGenParameterSpec) algorithmParameterSpec).getName();
            OpenSSLECGroupContext newCurve = OpenSSLECGroupContext.getCurveByName(newCurveName);
            if (newCurve == null) {
                throw new InvalidParameterSpecException("Unknown EC curve name: " + newCurveName);
            }
            this.curve = newCurve;
        } else if (algorithmParameterSpec instanceof ECParameterSpec) {
            ECParameterSpec ecParamSpec = (ECParameterSpec) algorithmParameterSpec;
            try {
                OpenSSLECGroupContext newCurve2 = OpenSSLECGroupContext.getInstance(ecParamSpec);
                if (newCurve2 == null) {
                    throw new InvalidParameterSpecException("Unknown EC curve: " + ecParamSpec);
                }
                this.curve = newCurve2;
            } catch (InvalidAlgorithmParameterException e) {
                throw new InvalidParameterSpecException(e.getMessage());
            }
        } else {
            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec are supported");
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes) throws IOException {
        long ref = NativeCrypto.EC_KEY_parse_curve_name(bytes);
        if (ref == 0) {
            throw new IOException("Error reading ASN.1 encoding");
        }
        this.curve = new OpenSSLECGroupContext(new NativeRef.EC_GROUP(ref));
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            engineInit(bytes);
            return;
        }
        throw new IOException("Unsupported format: " + format);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass) throws InvalidParameterSpecException {
        if (aClass == ECParameterSpec.class) {
            return this.curve.getECParameterSpec();
        }
        if (aClass == ECGenParameterSpec.class) {
            return new ECGenParameterSpec(this.curve.getCurveName());
        }
        throw new InvalidParameterSpecException("Unsupported class: " + aClass);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded() throws IOException {
        return NativeCrypto.EC_KEY_marshal_curve_name(this.curve.getNativeRef());
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    /* access modifiers changed from: protected */
    public String engineToString() {
        return "Conscrypt EC AlgorithmParameters";
    }
}
