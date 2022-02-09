package com.android.apksig.internal.x509;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import java.nio.ByteBuffer;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class SubjectPublicKeyInfo {
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.SEQUENCE)
    public AlgorithmIdentifier algorithmIdentifier;
    @Asn1Field(index = 1, type = Asn1Type.BIT_STRING)
    public ByteBuffer subjectPublicKey;
}
