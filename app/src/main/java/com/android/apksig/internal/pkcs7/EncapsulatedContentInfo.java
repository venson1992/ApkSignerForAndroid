package com.android.apksig.internal.pkcs7;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1Tagging;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.nio.ByteBuffer;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class EncapsulatedContentInfo {
    @Asn1Field(index = 1, optional = true, tagNumber = BerEncoding.TAG_CLASS_UNIVERSAL, tagging = Asn1Tagging.EXPLICIT, type = Asn1Type.OCTET_STRING)
    public ByteBuffer content;
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.OBJECT_IDENTIFIER)
    public String contentType;

    public EncapsulatedContentInfo() {
    }

    public EncapsulatedContentInfo(String contentTypeOid) {
        this.contentType = contentTypeOid;
    }
}
