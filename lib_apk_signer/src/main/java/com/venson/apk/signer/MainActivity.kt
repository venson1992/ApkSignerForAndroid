package com.venson.apk.signer

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.android.apksig.ApkSigner
import com.android.apksig.SigningCertificateLineage
import com.android.apksig.apk.MinSdkVersionException
import com.android.apksigner.ApkSignerTool.ProviderInstallSpec
import com.android.apksigner.ParameterException
import com.android.apksigner.PasswordRetriever
import com.android.apksigner.SignerParams
import org.conscrypt.OpenSSLProvider
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.security.Security

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "Signer"
        private const val REQUEST_PERMISSION_CODE: Int = 0x0012
        const val ZIP_MAGIC = 67324752
    }

    init {
        Security.addProvider(OpenSSLProvider())
    }

    private val sha256: MessageDigest? = null
    private val sha1: MessageDigest? = null
    private val md5: MessageDigest? = null

    private lateinit var mButton: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mButton = findViewById(R.id.signButton)
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
            REQUEST_PERMISSION_CODE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
            }
        }
        mButton.setOnClickListener {
            clickAction()
        }
    }

    private fun clickAction() {
        val srcFilePath = "/storage/emulated/0/25game/apps/-1702942688.apk"
//        val srcFilePath = "/storage/emulated/0/25game/apps/-2034501281.apk"
        val srcFile = File(srcFilePath)
        val signPath = "$filesDir/Android.keystore"
        val isCopySuccess: Boolean = copyAssetFile("Android.keystore", signPath)
        Log.d(TAG, "isCopySuccess=$isCopySuccess;signPath=$signPath")
        var signFile: File? = null
        try {
            signFile = File(signPath)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        if (signFile == null) {
            Log.d(TAG, "signFile == null")
            return
        }
        val signedApkPath: String =
            srcFile.parent + "/" + srcFile.nameWithoutExtension + "_signed.apk"
        val signedApk = try {
            File(signedApkPath)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
        if (signedApk == null) {
            Log.d(TAG, "signedApk == null")
            return
        }
        if (!signedApk.exists()) {
            val isCreated = signedApk.createNewFile()
            if (!isCreated) {
                Log.d(TAG, "signedApk.createNewFile failed")
                return
            }
        }
        sign(srcFile, signedApk, signFile)
    }

    /**
     * 签名
     * @param inputApk 源apk文件
     * @param outputApk 目标apk文件
     * @param signFile 签名文件
     */
    fun sign(inputApk: File, outputApk: File, signFile: File) {
        val verbose = false
        val v1SigningEnabled = true
        val v2SigningEnabled = true
        val v3SigningEnabled = true
        val v4SigningEnabled = true
        val forceSourceStampOverwrite = false
        val verityEnabled = false
        val debuggableApkPermitted = true
        val minSdkVersion = 1
        val minSdkVersionSpecified = false
        val maxSdkVersion = 2147483647
        val signers: MutableList<SignerParams> = ArrayList(1)
        val signerParams = SignerParams()
        val lineage: SigningCertificateLineage? = null
        val sourceStampSignerParams = SignerParams()
        val sourceStampLineage: SigningCertificateLineage? = null
        val providers: MutableList<ProviderInstallSpec?> = mutableListOf()
        val providerParams = ProviderInstallSpec()
        val v4SigningFlagFound = false
        val sourceStampFlagFound = false
        /*
        初始化签名数据
         */
        val signPassword = "6445569"
        val signAlias = "android.keystore"
        signerParams.setKeystoreFile(signFile.absolutePath)
        signerParams.keystoreKeyAlias = signAlias
//        signerParams.setKeystorePasswordSpec(signPassword)
//        signerParams.setKeyPasswordSpec(signPassword)
        if (!signerParams.isEmpty) {
            signers.add(signerParams)
        }
        /*
        签名密码
         */
        val sourceStampSignerConfig: ApkSigner.SignerConfig? = null
        val signerConfigs: MutableList<ApkSigner.SignerConfig> = ArrayList(signers.size)
        val passwordRetriever = PasswordRetriever()
        signers.forEachIndexed { index, signer ->
            signer.name = "signer #${index + 1}"
            getSignerConfig(signer, passwordRetriever)?.let { signerConfig ->
                signerConfigs.add(signerConfig)
                Log.d(TAG, "signerConfig=$signerConfig")
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
        Log.d(TAG, "Signed")
    }

    /**
     * 复制asset文件到存储空间
     */
    fun copyAssetFile(assetPath: String?, targetPath: String?): Boolean {
        var `is`: InputStream? = null
        var os: FileOutputStream? = null
        val assetManager = assets
        return try {
            `is` = assetManager.open(assetPath!!)
            val outFile = File(targetPath)
            if (!outFile.exists()) {
                val isCreated = outFile.createNewFile()
                if (!isCreated) {
                    return false
                }
            }
            os = FileOutputStream(outFile)
            val buffer = ByteArray(1024)
            var byteCount = 0
            while (`is`.read(buffer).also { byteCount = it } != -1) {
                os.write(buffer, 0, byteCount)
            }
            os.flush()
            true
        } catch (e: IOException) {
            e.printStackTrace()
            false
        } finally {
            try {
                `is`?.close()
                os?.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    }

    /**
     * 获得签名配置
     */
    private fun getSignerConfig(
        signer: SignerParams,
        passwordRetriever: PasswordRetriever
    ): ApkSigner.SignerConfig? {
        try {
            signer.loadPrivateKeyAndCerts(passwordRetriever)
        } catch (var5: ParameterException) {
            Log.d(
                TAG, "Failed to load signer \"" + signer.name + "\": " + var5.message
            )
            return null
        } catch (var6: java.lang.Exception) {
            Log.d(
                TAG, "Failed to load signer \"" + signer.name + "\""
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