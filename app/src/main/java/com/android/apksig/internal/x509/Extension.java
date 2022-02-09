package com.android.apksig.internal.x509;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.nio.ByteBuffer;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class Extension {
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.OBJECT_IDENTIFIER)
    public String extensionID;
    @Asn1Field(index = 2, type = Asn1Type.OCTET_STRING)
    public ByteBuffer extensionValue;
    @Asn1Field(index = 1, optional = true, type = Asn1Type.BOOLEAN)
    public boolean isCritial = false;
}
