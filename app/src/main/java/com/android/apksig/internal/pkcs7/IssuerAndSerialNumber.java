package com.android.apksig.internal.pkcs7;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.math.BigInteger;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class IssuerAndSerialNumber {
    @Asn1Field(index = 1, type = Asn1Type.INTEGER)
    public BigInteger certificateSerialNumber;
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.ANY)
    public Asn1OpaqueObject issuer;

    public IssuerAndSerialNumber() {
    }

    public IssuerAndSerialNumber(Asn1OpaqueObject issuer2, BigInteger certificateSerialNumber2) {
        this.issuer = issuer2;
        this.certificateSerialNumber = certificateSerialNumber2;
    }
}
