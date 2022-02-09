package com.android.apksig.internal.x509;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.math.BigInteger;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class RSAPublicKey {
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.INTEGER)
    public BigInteger modulus;
    @Asn1Field(index = 1, type = Asn1Type.INTEGER)
    public BigInteger publicExponent;
}
