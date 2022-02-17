package com.venson.apk.signer

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.android.apksigner.*
import com.blankj.utilcode.util.UriUtils
import java.io.File


class SignActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "Signer"
        private const val REQUEST_PERMISSION_CODE: Int = 0x0012
        private const val REQUEST_DOCUMENT_SIGN: Int = 0x0020
        private const val REQUEST_DOCUMENT_VERIFY: Int = 0x0021
    }

    init {
        addProviders()
    }

    private var mSrcApkFile: File? = null

    private lateinit var mPasswordEditView: EditText
    private lateinit var mAliasEditView: EditText
    private lateinit var mSignButton: View
    private lateinit var mVerifyButton: View
    private lateinit var mScrollView: View
    private lateinit var mLogView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sign)
        mPasswordEditView = findViewById(R.id.passwordEditView)
        mAliasEditView = findViewById(R.id.aliasEditView)
        mSignButton = findViewById(R.id.signButton)
        mVerifyButton = findViewById(R.id.verifyButton)
        mScrollView = findViewById(R.id.scrollView)
        mLogView = findViewById(R.id.logView)
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
        mPasswordEditView.setText(BuildConfig.ks_password)
        mAliasEditView.setText(BuildConfig.ks_alias)
        mSignButton.setOnClickListener {
            clickAction()
            mSrcApkFile = null
        }
        mVerifyButton.setOnClickListener {
            val srcApkFile = mSrcApkFile
            if (srcApkFile?.exists() != true) {
                openDocument(REQUEST_DOCUMENT_VERIFY)
                return@setOnClickListener
            }
            printLog("srcApkFile=$srcApkFile")
            var logBuilder = StringBuilder()
            verify(srcApkFile, logBuilder)
            printLog(logBuilder.toString())
            getSignedFile(srcApkFile)?.let {
                logBuilder = StringBuilder()
                verify(it, logBuilder)
                printLog(logBuilder.toString())
            }
            mSrcApkFile = null
        }
    }

    private fun getSignedFile(srcApkFile: File): File? {
        val signedApkPath: String =
            srcApkFile.parent + "/" + srcApkFile.nameWithoutExtension + "_signed.apk"
        val signedApk = try {
            File(signedApkPath)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
        if (signedApk == null) {
            printLog("signedApk == null")
            return null
        }
        if (!signedApk.exists()) {
            val isCreated = signedApk.createNewFile()
            if (!isCreated) {
                printLog("signedApk.createNewFile failed")
                return null
            }
        }
        printLog("signedApk=$signedApk")
        return signedApk
    }

    private fun clickAction() {
        mLogView.text = ""
        val srcApkFile = mSrcApkFile
        if (srcApkFile?.exists() != true) {
            openDocument(REQUEST_DOCUMENT_SIGN)
            return
        }
        val signPath = "$filesDir/Android.keystore"
        val inputStream = readKeyStoreFromAsset(this, "Android.keystore")
        val isCopySuccess: Boolean = copyKeyStoreToFile(inputStream, signPath)
        printLog("isCopySuccess=$isCopySuccess;signPath=$signPath")
        var signFile: File? = null
        try {
            signFile = File(signPath)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        if (signFile == null) {
            printLog("signFile == null")
            return
        }
        val signPassword = mPasswordEditView.text.toString()
        val signAlias = mAliasEditView.text.toString()
        try {
            val signedApk = getSignedFile(srcApkFile)
            if (signedApk == null || !signedApk.exists()) {
                printLog("signedApk 不存在")
                return
            }
            sign(srcApkFile, signedApk, signFile, signPassword, signAlias)
            printLog("signed successful! ${signedApk.absolutePath}", true)
        } catch (e: Exception) {
            printLog(e, true)
        }
    }

    private fun openDocument(requestCode: Int) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
            printLog("未提供安装包", true)
            return
        }
        try {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            //文档需要是可以打开的
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            //是否支持多选，默认不支持
            intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, false)
            val uri = Uri.Builder()
                .scheme(ContentResolver.SCHEME_CONTENT)
                .authority("com.android.externalstorage.documents")
                .appendPath("document")
                .appendPath("primary")
                .build()
            intent.setDataAndType(uri, "*/*")
            intent.putExtra(
                Intent.EXTRA_MIME_TYPES,
                arrayOf("application/vnd.android.package-archive")
            )
            startActivityForResult(intent, requestCode)
        } catch (e: ActivityNotFoundException) {
            printLog(e)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_DOCUMENT_SIGN, REQUEST_DOCUMENT_VERIFY -> {
                if (resultCode != RESULT_OK) {
                    return
                }
                data?.data?.let { uri ->
                    val file = UriUtils.uri2File(uri)
                    if (file?.exists() != true) {
                        printLog("文件载入失败", true)
                        return
                    }
                    mSrcApkFile = file
                    if (requestCode == REQUEST_DOCUMENT_SIGN) {
                        clickAction()
                    } else {
                        mVerifyButton.performClick()
                    }
                } ?: printLog("文件读取失败", true)
            }
        }
    }

    private fun printLog(msg: String, isShowToast: Boolean = false) {
        val stringBuilder = StringBuilder(mLogView.text)
        if (stringBuilder.isNotEmpty()) {
            stringBuilder.append("\n\n")
        }
        stringBuilder.append(msg)
        mLogView.text = stringBuilder
        Log.d(TAG, msg)
        if (isShowToast) {
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        }
        scrollBottom()
    }

    private fun printLog(e: Throwable, isShowToast: Boolean = false) {
        val stringBuilder = StringBuilder(mLogView.text)
        if (stringBuilder.isNotEmpty()) {
            stringBuilder.append("\n")
        }
        val msg = e.stackTraceToString()
        stringBuilder.append(msg)
        mLogView.text = stringBuilder
        e.printStackTrace()
        if (isShowToast) {
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        }
        scrollBottom()
    }

    private fun scrollBottom() {
        mScrollView.post {
            mScrollView.scrollTo(0, mLogView.measuredHeight)
        }
    }

}