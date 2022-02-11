package com.venson.apk.signer

import org.junit.Test
import java.security.KeyStore

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {
    @Test
    fun addition_isCorrect() {
        val ksType = KeyStore.getDefaultType()
        print("ksType=$ksType")
        var ks = KeyStore.getInstance(ksType)
    }
}