package com.android.apksig.internal.pkcs7;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Tagging;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class ContentInfo {
    @Asn1Field(index = 2, tagNumber = BerEncoding.TAG_CLASS_UNIVERSAL, tagging = Asn1Tagging.EXPLICIT, type = Asn1Type.ANY)
    public Asn1OpaqueObject content;
    @Asn1Field(index = 1, type = Asn1Type.OBJECT_IDENTIFIER)
    public String contentType;
}
