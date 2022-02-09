package com.android.apksig.internal.asn1.ber;

public interface BerDataValueReader {
    BerDataValue readDataValue() throws BerDataValueFormatException;
}
