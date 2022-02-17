package com.venson.apk.signer

import android.R
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.AssetManager
import android.os.Build
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import java.io.File
import java.io.IOException
import java.lang.reflect.InvocationTargetException

fun getAppInfo(context: Context, apkFile: File): AppInfo? {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        try {
            val pm: PackageManager = context.applicationContext.packageManager
            val packageInfo = pm.getPackageArchiveInfo(
                apkFile.absolutePath, PackageManager.GET_ACTIVITIES
            )
            packageInfo?.applicationInfo?.let { applicationInfo ->
                val appInfo = AppInfo()
                appInfo.appName = applicationInfo.name
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    appInfo.versionCode = packageInfo.longVersionCode.toInt()
                } else {
                    appInfo.versionCode = packageInfo.versionCode
                }
                appInfo.versionName = packageInfo.versionName
                appInfo.minSdkVersion = applicationInfo.minSdkVersion
                appInfo.targetSdkVersion = applicationInfo.targetSdkVersion
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    appInfo.compileSdkVersion = applicationInfo.compileSdkVersion
                }
                return appInfo
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
    try {
        return getAppInfo(apkFile)
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return null
}

@Throws(
    ClassNotFoundException::class,
    IllegalAccessException::class,
    InstantiationException::class,
    NoSuchMethodException::class,
    InvocationTargetException::class,
    IOException::class,
    XmlPullParserException::class
)
private fun getAppInfo(apkFile: File): AppInfo? {
    val assetManagerClass = Class.forName("android.content.res.AssetManager")
    val assetManager = assetManagerClass.newInstance() as AssetManager
    val addAssetPath = assetManager.javaClass.getMethod(
        "addAssetPath",
        String::class.java
    )
    val cookie = addAssetPath.invoke(assetManager, apkFile.absolutePath) as Int
    val parser = assetManager.openXmlResourceParser(cookie, "AndroidManifest.xml")
    while (parser.next() != XmlPullParser.END_DOCUMENT) {
        if (parser.eventType == XmlPullParser.START_TAG && parser.name == "uses-sdk") {
            val appInfo = AppInfo()
            for (i in 0 until parser.attributeCount) {
                when (parser.getAttributeNameResource(i)) {
                    R.attr.minSdkVersion -> {
                        appInfo.minSdkVersion = parser.getAttributeIntValue(i, -1)
                    }
                    R.attr.maxSdkVersion -> {
                        appInfo.maxSdkVersion = parser.getAttributeIntValue(i, -1)
                    }
                    R.attr.targetSdkVersion -> {
                        appInfo.targetSdkVersion = parser.getAttributeIntValue(i, -1)
                    }
                    R.attr.versionCode -> {
                        appInfo.versionCode = parser.getAttributeIntValue(i, -1)
                    }
                    R.attr.versionName -> {
                        appInfo.versionName = parser.getAttributeValue(i)
                    }
                    R.attr.name -> {
                        appInfo.appName = parser.getAttributeValue(i)
                    }
                }
            }
            return appInfo
        }
    }
    return null
}

class AppInfo {
    var appName: String = ""
    var minSdkVersion: Int = 0
    var maxSdkVersion: Int = 0
    var targetSdkVersion: Int = 0
    var compileSdkVersion: Int = 0
    var versionCode: Int = 0
    var versionName: String = ""

    override fun toString(): String {
        return "AppInfo(" +
                "appName='$appName', " +
                "minSdkVersion=$minSdkVersion, " +
                "maxSdkVersion=$maxSdkVersion, " +
                "targetSdkVersion=$targetSdkVersion, " +
                "compileSdkVersion=$compileSdkVersion, " +
                "versionCode=$versionCode, " +
                "versionName='$versionName'" +
                ")"
    }

}