package com.android.apksig.internal.asn1;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Asn1Field {
    Asn1TagClass cls() default Asn1TagClass.AUTOMATIC;

    Asn1Type elementType() default Asn1Type.ANY;

    int index() default 0;

    boolean optional() default false;

    int tagNumber() default -1;

    Asn1Tagging tagging() default Asn1Tagging.NORMAL;

    Asn1Type type();
}
