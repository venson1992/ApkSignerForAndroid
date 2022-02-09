package org.conscrypt;

import java.io.File;
import java.util.Locale;
import java.util.logging.Logger;

class HostProperties {
    static final Architecture ARCH = getArchitecture(System.getProperty("os.arch", ""));
    static final OperatingSystem OS = getOperatingSystem(System.getProperty("os.name", ""));
    private static final String TEMP_DIR_PROPERTY_NAME = "org.conscrypt.tmpdir";
    private static final Logger logger = Logger.getLogger(HostProperties.class.getName());

    /* access modifiers changed from: package-private */
    public enum OperatingSystem {
        AIX,
        HPUX,
        OS400,
        LINUX,
        OSX,
        FREEBSD,
        OPENBSD,
        NETBSD,
        SUNOS,
        WINDOWS,
        UNKNOWN;

        public String getFileComponent() {
            return name().toLowerCase();
        }
    }

    /* access modifiers changed from: package-private */
    public enum Architecture {
        X86_64,
        X86_32 {
            @Override // org.conscrypt.HostProperties.Architecture
            public String getFileComponent() {
                return "x86";
            }
        },
        ITANIUM_64,
        SPARC_32,
        SPARC_64,
        ARM_32,
        AARCH_64,
        PPC_32,
        PPC_64,
        PPCLE_64,
        S390_32,
        S390_64,
        UNKNOWN;

        public String getFileComponent() {
            return name().toLowerCase();
        }
    }

    static boolean isWindows() {
        return OS == OperatingSystem.WINDOWS;
    }

    static boolean isOSX() {
        return OS == OperatingSystem.OSX;
    }

    /* JADX WARNING: Removed duplicated region for block: B:19:0x006b  */
    /* JADX WARNING: Removed duplicated region for block: B:23:0x0089  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    static java.io.File getTempDir() {
        /*
        // Method dump skipped, instructions count: 147
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.HostProperties.getTempDir():java.io.File");
    }

    private static File toDirectory(String path) {
        if (path == null) {
            return null;
        }
        File f = new File(path);
        f.mkdirs();
        if (!f.isDirectory()) {
            return null;
        }
        try {
            return f.getAbsoluteFile();
        } catch (Exception e) {
            return f;
        }
    }

    private static String normalize(String value) {
        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
    }

    private static OperatingSystem getOperatingSystem(String value) {
        String value2 = normalize(value);
        if (value2.startsWith("aix")) {
            return OperatingSystem.AIX;
        }
        if (value2.startsWith("hpux")) {
            return OperatingSystem.HPUX;
        }
        if (value2.startsWith("os400") && (value2.length() <= 5 || !Character.isDigit(value2.charAt(5)))) {
            return OperatingSystem.OS400;
        }
        if (value2.startsWith("linux")) {
            return OperatingSystem.LINUX;
        }
        if (value2.startsWith("macosx") || value2.startsWith("osx")) {
            return OperatingSystem.OSX;
        }
        if (value2.startsWith("freebsd")) {
            return OperatingSystem.FREEBSD;
        }
        if (value2.startsWith("openbsd")) {
            return OperatingSystem.OPENBSD;
        }
        if (value2.startsWith("netbsd")) {
            return OperatingSystem.NETBSD;
        }
        if (value2.startsWith("solaris") || value2.startsWith("sunos")) {
            return OperatingSystem.SUNOS;
        }
        if (value2.startsWith("windows")) {
            return OperatingSystem.WINDOWS;
        }
        return OperatingSystem.UNKNOWN;
    }

    private static Architecture getArchitecture(String value) {
        String value2 = normalize(value);
        if (value2.matches("^(x8664|amd64|ia32e|em64t|x64)$")) {
            return Architecture.X86_64;
        }
        if (value2.matches("^(x8632|x86|i[3-6]86|ia32|x32)$")) {
            return Architecture.X86_32;
        }
        if (value2.matches("^(ia64|itanium64)$")) {
            return Architecture.ITANIUM_64;
        }
        if (value2.matches("^(sparc|sparc32)$")) {
            return Architecture.SPARC_32;
        }
        if (value2.matches("^(sparcv9|sparc64)$")) {
            return Architecture.SPARC_64;
        }
        if (value2.matches("^(arm|arm32)$")) {
            return Architecture.ARM_32;
        }
        if ("aarch64".equals(value2)) {
            return Architecture.AARCH_64;
        }
        if (value2.matches("^(ppc|ppc32)$")) {
            return Architecture.PPC_32;
        }
        if ("ppc64".equals(value2)) {
            return Architecture.PPC_64;
        }
        if ("ppc64le".equals(value2)) {
            return Architecture.PPCLE_64;
        }
        if ("s390".equals(value2)) {
            return Architecture.S390_32;
        }
        if ("s390x".equals(value2)) {
            return Architecture.S390_64;
        }
        return Architecture.UNKNOWN;
    }

    private HostProperties() {
    }
}
