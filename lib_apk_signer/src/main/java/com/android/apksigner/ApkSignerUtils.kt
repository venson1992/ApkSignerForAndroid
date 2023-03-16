package com.android.apksigner

import android.content.Context
import android.util.Log
import androidx.annotation.RawRes
import com.android.apksig.ApkSigner
import com.android.apksig.SigningCertificateLineage
import com.android.apksig.apk.MinSdkVersionException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.Security

private const val SIGNER_TAG = "signer"

object ApkSignerUtils {

    init {
        try {
            Security.removeProvider("BC")
        } catch (ignore: Exception) {

        }
        try {
            Security.addProvider(BouncyCastleProvider())
        } catch (ignore: Exception) {

        }
    }

    /**
     * 读取签名文件
     * @param context 上下文
     * @param rawResId 文件id
     */
    fun readKeyStoreFromRaw(context: Context, @RawRes rawResId: Int): InputStream {
        return context.resources.openRawResource(rawResId)
    }

    /**
     * 读取签名文件
     * @param context 上下文
     * @param path 文件路径
     */
    fun readKeyStoreFromAsset(context: Context, path: String): InputStream {
        return context.assets.open(path)
    }

    /**
     * 拷贝签名文件到存储系统
     * @param inputStream 签名文件输入流
     * @param filePath 目标文件地址
     */
    fun copyKeyStoreToFile(inputStream: InputStream, filePath: String): Boolean {
        var os: FileOutputStream? = null
        return try {
            val outFile = File(filePath)
            if (!outFile.exists()) {
                val isCreated = outFile.createNewFile()
                if (!isCreated) {
                    return false
                }
            }
            os = FileOutputStream(outFile)
            val buffer = ByteArray(1024)
            var byteCount: Int
            while (inputStream.read(buffer).also { byteCount = it } != -1) {
                os.write(buffer, 0, byteCount)
            }
            os.flush()
            true
        } catch (e: IOException) {
            e.printStackTrace()
            false
        } finally {
            try {
                inputStream.close()
                os?.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    }

    /**
     * 签名
     * @param inputApk 源apk文件
     * @param outputApk 目标apk文件
     * @param signFile 签名文件
     */
    fun sign(
        inputApk: File,
        outputApk: File,
        signFile: File,
        signPassword: String,
        signAlias: String
    ) {
        val v1SigningEnabled = true
        val v2SigningEnabled = true
        val v3SigningEnabled = true
        val v4SigningEnabled = true
        val debuggableApkPermitted = true
        val signers: MutableList<SignerParams> = ArrayList(1)
        val signerParams = SignerParams()
        val lineage: SigningCertificateLineage? = null
        val v4SigningFlagFound = false
        /*
        初始化签名数据
         */
        signerParams.setKeystoreFile(signFile.absolutePath)
        signerParams.keystoreKeyAlias = signAlias
        signerParams.setKeystorePasswordSpec(signPassword)
        signerParams.setKeyPasswordSpec(signPassword)
        if (!signerParams.isEmpty) {
            signers.add(signerParams)
        }
        /*
        签名密码
         */
        val signerConfigs: MutableList<ApkSigner.SignerConfig> = ArrayList(signers.size)
        val passwordRetriever = PasswordRetriever()
        signers.forEachIndexed { index, signer ->
            signer.name = "signer #${index + 1}"
            getSignerConfig(signer, passwordRetriever)?.let { signerConfig ->
                signerConfigs.add(signerConfig)
                Log.d(SIGNER_TAG, "signerConfig=$signerConfig")
            }
        }
        try {
            passwordRetriever.close()
        } catch (var34: Throwable) {
            var34.printStackTrace()
        }
        /*
        签名
         */
        val apkSignerBuilder: ApkSigner.Builder = ApkSigner.Builder(signerConfigs)
            .setInputApk(inputApk)
            .setOutputApk(outputApk)
            .setOtherSignersSignaturesPreserved(false)
            .setV1SigningEnabled(v1SigningEnabled)
            .setV2SigningEnabled(v2SigningEnabled)
            .setV3SigningEnabled(v3SigningEnabled)
            .setV4SigningEnabled(v4SigningEnabled) /*.setForceSourceStampOverwrite(forceSourceStampOverwrite)*/ /*.setVerityEnabled(verityEnabled)*/
            .setV4ErrorReportingEnabled(v4SigningEnabled && v4SigningFlagFound)
            .setDebuggableApkPermitted(debuggableApkPermitted)
            .setSigningCertificateLineage(lineage)
        val apkSigner = apkSignerBuilder.build()
        try {
            apkSigner.sign()
        } catch (var36: MinSdkVersionException) {
            var msg = var36.message
            if (!msg!!.endsWith(".")) {
                msg = "$msg."
            }
            throw MinSdkVersionException(
                "Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override",
                var36
            )
        }
        Log.d(SIGNER_TAG, "Signed")
    }

    /**
     * 获得签名配置
     */
    private fun getSignerConfig(
        signer: SignerParams,
        passwordRetriever: PasswordRetriever
    ): ApkSigner.SignerConfig? {
        try {
            signer.loadPrivateKeyAndCertsFromKeyStore(passwordRetriever)
        } catch (var5: ParameterException) {
            Log.d(
                SIGNER_TAG, "Failed to load signer \"" + signer.name + "\": " + var5.message
            )
            return null
        } catch (var6: java.lang.Exception) {
            Log.d(
                SIGNER_TAG, "Failed to load signer \"" + signer.name + "\""
            )
            var6.printStackTrace()
            return null
        }
        val v1SigBasename: String = if (signer.v1SigFileBasename != null) {
            signer.v1SigFileBasename
        } else if (signer.keystoreKeyAlias != null) {
            signer.keystoreKeyAlias
        } else {
            if (signer.keyFile == null) {
                throw RuntimeException("Neither KeyStore key alias nor private key file available")
            }
            val keyFileName = File(signer.keyFile).name
            val delimiterIndex = keyFileName.indexOf(46.toChar())
            if (delimiterIndex == -1) {
                keyFileName
            } else {
                keyFileName.substring(0, delimiterIndex)
            }
        }
        return ApkSigner.SignerConfig.Builder(
            v1SigBasename,
            signer.privateKey,
            signer.certs
        ).build()
    }
}