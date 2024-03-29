package com.android.apksigner

import android.util.Log
import com.android.apksig.ApkVerifier
import com.android.apksig.ApkVerifier.IssueWithParams
import com.android.apksig.ApkVerifier.Result.V1SchemeSignerInfo
import com.android.apksig.ApkVerifier.Result.V2SchemeSignerInfo
import com.android.apksig.ApkVerifier.Result.V3SchemeSignerInfo
import com.android.apksig.apk.MinSdkVersionException
import org.conscrypt.OpenSSLProvider
import java.io.File
import java.security.Security
import java.security.cert.X509Certificate

object ApkVerifyUtils {

    private const val VERIFY_TAG = "verify"

    init {
        try {
            Security.addProvider(OpenSSLProvider())
        } catch (ignore: UnsatisfiedLinkError) {
        }
    }

    fun verify(inputApk: File, logBuilder: StringBuilder? = null) {
        val printCerts = true
        val verbose = true
        val warningsTreatedAsErrors = false
        val verifySourceStamp = false

        val apkVerifierBuilder = ApkVerifier.Builder(inputApk)
        val apkVerifier: ApkVerifier = apkVerifierBuilder.build()

        val result: ApkVerifier.Result
        try {
            result = apkVerifier.verify()
        } catch (var27: MinSdkVersionException) {
            var msg = var27.message
            if (!msg!!.endsWith(".")) {
                msg = "$msg."
            }
            throw MinSdkVersionException(
                "Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override",
                var27
            )
        }
        val verified = result.isVerified
        val sourceStampInfo = result.sourceStampInfo
        var warningsEncountered = false
        if (verified) {
            val signerCerts = result.signerCertificates
            if (verbose) {
                printLog("Verifies", logBuilder)
                printLog(
                    "Verified using v1 scheme (JAR signing): "
                            + result.isVerifiedUsingV1Scheme,
                    logBuilder
                )
                printLog(
                    "Verified using v2 scheme (APK Signature Scheme v2): "
                            + result.isVerifiedUsingV2Scheme,
                    logBuilder
                )
                printLog(
                    "Verified using v3 scheme (APK Signature Scheme v3): "
                            + result.isVerifiedUsingV3Scheme,
                    logBuilder
                )
                printLog(
                    "Verified using v4 scheme (APK Signature Scheme v4): "
                            + result.isVerifiedUsingV4Scheme,
                    logBuilder
                )
                printLog("Verified for SourceStamp: " + result.isSourceStampVerified, logBuilder)
                if (!verifySourceStamp) {
                    printLog("Number of signers: " + signerCerts.size, logBuilder)
                }
            }
            if (printCerts) {
                var signerNumber = 0
                val var23: Iterator<*> = signerCerts.iterator()
                while (var23.hasNext()) {
                    val signerCert = var23.next() as X509Certificate
                    ++signerNumber
                    ApkSignerTool.printCertificate(
                        signerCert,
                        "Signer #$signerNumber",
                        verbose,
                        logBuilder
                    )
                }
                if (sourceStampInfo != null) {
                    ApkSignerTool.printCertificate(
                        sourceStampInfo.certificate,
                        "Source Stamp Signer",
                        verbose,
                        logBuilder
                    )
                }
            }
        } else {
            printLog("DOES NOT VERIFY", logBuilder)
        }
        val var29: Iterator<*> = result.errors.iterator()
        while (var29.hasNext()) {
            val error = var29.next() as IssueWithParams
            printLog("ERROR: $error", logBuilder)
        }
        val warningsOut = if (warningsTreatedAsErrors) System.err else System.out
        var var32: Iterator<*> = result.warnings.iterator()
        var warning: IssueWithParams
        while (var32.hasNext()) {
            warning = var32.next() as IssueWithParams
            warningsEncountered = true
            warningsOut.println("WARNING: $warning")
        }
        var32 = result.v1SchemeSigners.iterator()
        var var25: Iterator<*>
        var signerName: String
        while (var32.hasNext()) {
            val signer = var32.next() as V1SchemeSignerInfo
            signerName = signer.name
            var25 = signer.errors.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                printLog("ERROR: JAR signer $signerName: $warning", logBuilder)
            }
            var25 = signer.warnings.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                warningsEncountered = true
                warningsOut.println("WARNING: JAR signer $signerName: $warning")
            }
        }
        var32 = result.v2SchemeSigners.iterator()
        while (var32.hasNext()) {
            val signer = var32.next() as V2SchemeSignerInfo
            signerName = "signer #" + (signer.index + 1)
            var25 = signer.errors.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                printLog("ERROR: APK Signature Scheme v2 $signerName: $warning", logBuilder)
            }
            var25 = signer.warnings.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                warningsEncountered = true
                warningsOut.println("WARNING: APK Signature Scheme v2 $signerName: $warning")
            }
        }
        var32 = result.v3SchemeSigners.iterator()
        while (var32.hasNext()) {
            val signer = var32.next() as V3SchemeSignerInfo
            signerName = "signer #" + (signer.index + 1)
            var25 = signer.errors.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                printLog("ERROR: APK Signature Scheme v3 $signerName: $warning", logBuilder)
            }
            var25 = signer.warnings.iterator()
            while (var25.hasNext()) {
                warning = var25.next() as IssueWithParams
                warningsEncountered = true
                warningsOut.println("WARNING: APK Signature Scheme v3 $signerName: $warning")
            }
        }
        if (sourceStampInfo != null) {
            var32 = sourceStampInfo.errors.iterator()
            while (var32.hasNext()) {
                warning = var32.next() as IssueWithParams
                printLog("ERROR: SourceStamp: $warning", logBuilder)
            }
            var32 = sourceStampInfo.warnings.iterator()
            while (var32.hasNext()) {
                warning = var32.next() as IssueWithParams
                warningsOut.println("WARNING: SourceStamp: $warning")
            }
        }
    }

    private fun printLog(msg: String, logBuilder: StringBuilder?) {
        Log.d(VERIFY_TAG, msg)
        if (logBuilder == null) {
            return
        }
        if (logBuilder.isNotEmpty()) {
            logBuilder.append("\n")
        }
        logBuilder.append(msg)
    }
}