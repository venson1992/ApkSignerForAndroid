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
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.android.apksigner.ApkSignerUtils
import com.android.apksigner.ApkVerifyUtils
import com.blankj.utilcode.util.UriUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class SignActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "Signer"
        private const val REQUEST_PERMISSION_CODE: Int = 0x0012
        private const val REQUEST_DOCUMENT_CODE: Int = 0x0020
    }

    private var mSrcApkFile: File? = null

    private lateinit var mRecyclerView: RecyclerView
    private lateinit var mTextView: TextView
    private lateinit var mPickButton: View
    private lateinit var mSignButton: View
    private lateinit var mVerifyButton: View
    private lateinit var mScrollView: View
    private lateinit var mLogView: TextView

    private val mKeyList = mutableListOf<KeyData>()

    private var mCurrentKeyData: KeyData? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sign)
        mRecyclerView = findViewById(R.id.recyclerView)
        mTextView = findViewById(R.id.textView)
        mPickButton = findViewById(R.id.pickButton)
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
        mKeyList.add(
            KeyData(
                "Android.keystore",
                BuildConfig.ks_alias,
                BuildConfig.ks_password
            )
        )
        mKeyList.add(
            KeyData(
                "Android (1).keystore",
                BuildConfig.ks_alias,
                BuildConfig.ks_password
            )
        )
        mKeyList.add(
            KeyData(
                "android6.jks",
                "andorid",
                BuildConfig.ks_password
            )
        )
        mRecyclerView.run {
            layoutManager = LinearLayoutManager(this@SignActivity, RecyclerView.VERTICAL, false)
            adapter = KeyListAdapter(mKeyList).also { adapter ->
                adapter.setOnItemClickListener { position ->
                    onKeySelected(position)
                }
                onKeySelected(0)
            }
        }
        mPickButton.setOnClickListener {
            mLogView.text = ""
            mSrcApkFile = null
            openDocument()
        }
        mSignButton.setOnClickListener {
            clickAction()
        }
        mVerifyButton.setOnClickListener {
            val srcApkFile = mSrcApkFile
            if (srcApkFile?.exists() != true) {
                printLog("请先选择需要签名的文件")
                return@setOnClickListener
            }
            var logBuilder = StringBuilder()
            ApkVerifyUtils.verify(srcApkFile, logBuilder)
            printLog(logBuilder.toString())
            getSignedFile(srcApkFile)?.let { signedFile ->
                try {
                    logBuilder = StringBuilder()
                    ApkVerifyUtils.verify(signedFile, logBuilder)
                    printLog(logBuilder.toString())
                } catch (ignore: Exception) {

                }
            }
            mSrcApkFile = null
        }
    }

    private fun onKeySelected(position: Int) {
        val keyData = mKeyList[position]
        mCurrentKeyData = keyData
        val text = StringBuilder()
            .append("file:")
            .append(keyData.fileName)
            .append("\n")
            .append("alias:")
            .append(keyData.alias)
            .append("\n")
            .append("ksPassword:")
            .append(keyData.password)
        mTextView.text = text
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
        val srcApkFile = mSrcApkFile
        if (srcApkFile?.exists() != true) {
            printLog("请先选择需要签名的文件")
            return
        }
        val keyData = mCurrentKeyData
        if (keyData == null) {
            printLog("请先选择需要签名文件")
            return
        }
        val signPath = "$filesDir/Android.keystore"
        val inputStream = ApkSignerUtils.readKeyStoreFromAsset(this, keyData.fileName)
        val isCopySuccess: Boolean = ApkSignerUtils.copyKeyStoreToFile(inputStream, signPath)
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
        val signPassword = keyData.password
        val signAlias = keyData.alias
        try {
            val signedApk = getSignedFile(srcApkFile)
            if (signedApk == null || !signedApk.exists()) {
                printLog("signedApk 不存在")
                return
            }
            ApkSignerUtils.sign(srcApkFile, signedApk, signFile, signPassword, signAlias)
            printLog("signed successful! ${signedApk.absolutePath}", true)
        } catch (e: Exception) {
            printLog(e, true)
        }
    }

    private fun openDocument() {
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
            startActivityForResult(intent, REQUEST_DOCUMENT_CODE)
        } catch (e: ActivityNotFoundException) {
            printLog(e)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_DOCUMENT_CODE -> {
                if (resultCode != RESULT_OK) {
                    return
                }
                data?.data?.let { uri ->
                    val file = UriUtils.uri2File(uri)
                    if (file?.exists() != true) {
                        printLog("文件载入失败", true)
                        return
                    }
                    if (file.nameWithoutExtension.endsWith("_signed")) {
                        printLog("该文件已经在工具签过名了")
                        return
                    }
                    mSrcApkFile = file
                    printLog("srcApkFile=${file.absolutePath}")
                    lifecycleScope.launch(Dispatchers.IO) {
                        val appInfo = getAppInfo(this@SignActivity, file)
                        withContext(Dispatchers.Main) {
                            printLog(appInfo.toString())
                        }
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

    data class KeyData(val fileName: String, val alias: String, val password: String)

}