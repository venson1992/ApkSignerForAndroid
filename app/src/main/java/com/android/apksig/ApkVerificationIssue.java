package com.android.apksig;

public class ApkVerificationIssue {
    public static final int JAR_SIG_NO_SIGNATURES = 36;
    public static final int JAR_SIG_PARSE_EXCEPTION = 37;
    public static final int MALFORMED_APK = 28;
    public static final int SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK = 27;
    public static final int SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING = 25;
    public static final int SOURCE_STAMP_DID_NOT_VERIFY = 21;
    public static final int SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH = 23;
    public static final int SOURCE_STAMP_MALFORMED_ATTRIBUTE = 31;
    public static final int SOURCE_STAMP_MALFORMED_CERTIFICATE = 18;
    public static final int SOURCE_STAMP_MALFORMED_LINEAGE = 33;
    public static final int SOURCE_STAMP_MALFORMED_SIGNATURE = 20;
    public static final int SOURCE_STAMP_NO_SIGNATURE = 17;
    public static final int SOURCE_STAMP_NO_SUPPORTED_SIGNATURE = 26;
    public static final int SOURCE_STAMP_POR_CERT_MISMATCH = 34;
    public static final int SOURCE_STAMP_POR_DID_NOT_VERIFY = 35;
    public static final int SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST = 24;
    public static final int SOURCE_STAMP_SIG_MISSING = 30;
    public static final int SOURCE_STAMP_UNKNOWN_ATTRIBUTE = 32;
    public static final int SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM = 19;
    public static final int SOURCE_STAMP_VERIFY_EXCEPTION = 22;
    public static final int UNEXPECTED_EXCEPTION = 29;
    public static final int V2_SIG_MALFORMED_CERTIFICATE = 6;
    public static final int V2_SIG_MALFORMED_DIGEST = 8;
    public static final int V2_SIG_MALFORMED_SIGNATURE = 4;
    public static final int V2_SIG_MALFORMED_SIGNER = 3;
    public static final int V2_SIG_MALFORMED_SIGNERS = 1;
    public static final int V2_SIG_NO_CERTIFICATES = 7;
    public static final int V2_SIG_NO_SIGNATURES = 5;
    public static final int V2_SIG_NO_SIGNERS = 2;
    public static final int V3_SIG_MALFORMED_CERTIFICATE = 14;
    public static final int V3_SIG_MALFORMED_DIGEST = 16;
    public static final int V3_SIG_MALFORMED_SIGNATURE = 12;
    public static final int V3_SIG_MALFORMED_SIGNER = 11;
    public static final int V3_SIG_MALFORMED_SIGNERS = 9;
    public static final int V3_SIG_NO_CERTIFICATES = 15;
    public static final int V3_SIG_NO_SIGNATURES = 13;
    public static final int V3_SIG_NO_SIGNERS = 10;
    private final String mFormat;
    private final int mIssueId;
    private final Object[] mParams;

    public ApkVerificationIssue(String format, Object... params) {
        this.mIssueId = -1;
        this.mFormat = format;
        this.mParams = params;
    }

    public ApkVerificationIssue(int issueId, Object... params) {
        this.mIssueId = issueId;
        this.mFormat = null;
        this.mParams = params;
    }

    public int getIssueId() {
        return this.mIssueId;
    }

    public Object[] getParams() {
        return this.mParams;
    }

    public String toString() {
        if (this.mFormat != null) {
            return String.format(this.mFormat, this.mParams);
        }
        StringBuilder result = new StringBuilder("mIssueId: ").append(this.mIssueId);
        for (Object param : this.mParams) {
            result.append(", ").append(param.toString());
        }
        return result.toString();
    }
}
