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
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.android.apksigner.copyKeyStoreToFile
import com.android.apksigner.readKeyStoreFromAsset
import com.android.apksigner.sign
import java.io.File

class SignActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "Signer"
        private const val REQUEST_PERMISSION_CODE: Int = 0x0012
    }

//    init {
//        Security.addProvider(OpenSSLProvider())
//    }

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
        mSignButton.setOnClickListener {
            clickAction()
        }
    }

    private fun clickAction() {
        mLogView.text = ""
//        val srcFilePath = "/storage/emulated/0/25game/apps/-1702942688.apk"
        val srcFilePath = "/storage/emulated/0/25game/apps/-2034501281.apk"
        val srcFile = File(srcFilePath)
        printLog("srcFile=$srcFile")
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
        val signedApkPath: String =
            srcFile.parent + "/" + srcFile.nameWithoutExtension + "_signed.apk"
        val signedApk = try {
            File(signedApkPath)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
        if (signedApk == null) {
            printLog("signedApk == null")
            return
        }
        if (!signedApk.exists()) {
            val isCreated = signedApk.createNewFile()
            if (!isCreated) {
                printLog("signedApk.createNewFile failed")
                return
            }
        }
        val signPassword = mPasswordEditView.text.toString()
        val signAlias = mAliasEditView.text.toString()
        try {
            sign(srcFile, signedApk, signFile, signPassword, signAlias)
            printLog("signed successful", true)
        } catch (e: Exception) {
            printLog(e, true)
        }
    }

    private fun printLog(msg: String, isShowToast: Boolean = false) {
        val stringBuilder = StringBuilder(mLogView.text)
        if (stringBuilder.isNotEmpty()) {
            stringBuilder.append("\n")
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