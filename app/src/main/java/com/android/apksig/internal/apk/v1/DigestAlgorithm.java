package com.android.apksig.internal.apk.v1;

import java.util.Comparator;

public enum DigestAlgorithm {
    SHA1("SHA-1"),
    SHA256("SHA-256");
    
    public static Comparator<DigestAlgorithm> BY_STRENGTH_COMPARATOR = new StrengthComparator();
    private final String mJcaMessageDigestAlgorithm;

    private DigestAlgorithm(String jcaMessageDigestAlgoritm) {
        this.mJcaMessageDigestAlgorithm = jcaMessageDigestAlgoritm;
    }

    /* access modifiers changed from: package-private */
    public String getJcaMessageDigestAlgorithm() {
        return this.mJcaMessageDigestAlgorithm;
    }

    private static class StrengthComparator implements Comparator<DigestAlgorithm> {
        private StrengthComparator() {
        }

        public int compare(DigestAlgorithm a1, DigestAlgorithm a2) {
            switch (a1) {
                case SHA1:
                    switch (a2) {
                        case SHA1:
                            return 0;
                        case SHA256:
                            return -1;
                        default:
                            throw new RuntimeException("Unsupported algorithm: " + a2);
                    }
                case SHA256:
                    switch (a2) {
                        case SHA1:
                            return 1;
                        case SHA256:
                            return 0;
                        default:
                            throw new RuntimeException("Unsupported algorithm: " + a2);
                    }
                default:
                    throw new RuntimeException("Unsupported algorithm: " + a1);
            }
        }
    }
}
