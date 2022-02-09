package com.android.apksig.internal.pkcs7;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Tagging;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.nio.ByteBuffer;
import java.util.List;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class SignedData {
    @Asn1Field(index = 3, optional = true, tagNumber = BerEncoding.TAG_CLASS_UNIVERSAL, tagging = Asn1Tagging.IMPLICIT, type = Asn1Type.SET_OF)
    public List<Asn1OpaqueObject> certificates;
    @Asn1Field(index = 4, optional = true, tagNumber = 1, tagging = Asn1Tagging.IMPLICIT, type = Asn1Type.SET_OF)
    public List<ByteBuffer> crls;
    @Asn1Field(index = 1, type = Asn1Type.SET_OF)
    public List<AlgorithmIdentifier> digestAlgorithms;
    @Asn1Field(index = 2, type = Asn1Type.SEQUENCE)
    public EncapsulatedContentInfo encapContentInfo;
    @Asn1Field(index = 5, type = Asn1Type.SET_OF)
    public List<SignerInfo> signerInfos;
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.INTEGER)
    public int version;
}
