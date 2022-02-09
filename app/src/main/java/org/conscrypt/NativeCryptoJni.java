package org.conscrypt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.conscrypt.NativeLibraryLoader;

final class NativeCryptoJni {
    private static final String DYNAMIC_LIB_NAME_PREFIX = "conscrypt_openjdk_jni";
    private static final String STATIC_LIB_NAME = "conscrypt";

    static void init() throws UnsatisfiedLinkError {
        List<NativeLibraryLoader.LoadResult> results = new ArrayList<>();
        if (!NativeLibraryLoader.loadFirstAvailable(classLoader(), results, platformLibName(), DYNAMIC_LIB_NAME_PREFIX, STATIC_LIB_NAME)) {
            logResults(results);
            throwBestError(results);
        }
    }

    private NativeCryptoJni() {
    }

    private static void logResults(List<NativeLibraryLoader.LoadResult> results) {
        for (NativeLibraryLoader.LoadResult result : results) {
            result.log();
        }
    }

    private static void throwBestError(List<NativeLibraryLoader.LoadResult> results) {
        Collections.sort(results, ErrorComparator.INSTANCE);
        Throwable bestError = results.get(0).error;
        for (NativeLibraryLoader.LoadResult result : results.subList(1, results.size())) {
            bestError.addSuppressed(result.error);
        }
        if (bestError instanceof Error) {
            throw ((Error) bestError);
        }
        throw ((Error) new UnsatisfiedLinkError(bestError.getMessage()).initCause(bestError));
    }

    private static ClassLoader classLoader() {
        return NativeCrypto.class.getClassLoader();
    }

    private static String platformLibName() {
        return "conscrypt_openjdk_jni-" + osName() + '-' + archName();
    }

    private static String osName() {
        return HostProperties.OS.getFileComponent();
    }

    private static String archName() {
        return HostProperties.ARCH.getFileComponent();
    }

    /* access modifiers changed from: private */
    public static final class ErrorComparator implements Comparator<NativeLibraryLoader.LoadResult> {
        static final ErrorComparator INSTANCE = new ErrorComparator();

        private ErrorComparator() {
        }

        public int compare(NativeLibraryLoader.LoadResult o1, NativeLibraryLoader.LoadResult o2) {
            int value1;
            int value2;
            int value12;
            int value22;
            Throwable e1 = o1.error;
            Throwable e2 = o2.error;
            if (e1 instanceof UnsatisfiedLinkError) {
                value1 = 1;
            } else {
                value1 = 0;
            }
            if (e2 instanceof UnsatisfiedLinkError) {
                value2 = 1;
            } else {
                value2 = 0;
            }
            if (value1 != value2) {
                return value2 - value1;
            }
            String m1 = e1.getMessage();
            String m2 = e2.getMessage();
            if (m1 == null || !m1.contains("java.library.path")) {
                value12 = 1;
            } else {
                value12 = 0;
            }
            if (m2 == null || !m2.contains("java.library.path")) {
                value22 = 1;
            } else {
                value22 = 0;
            }
            return value22 - value12;
        }
    }
}
