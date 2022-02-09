package com.android.apksig.apk;

import com.android.apksig.apk.ApkUtilsLite;
import com.android.apksig.internal.apk.AndroidBinXmlParser;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;

public abstract class ApkUtils {
    public static final String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";
    private static final int DEBUGGABLE_ATTR_ID = 16842767;
    private static final String MANIFEST_ELEMENT_TAG = "manifest";
    private static final int MIN_SDK_VERSION_ATTR_ID = 16843276;
    public static final String SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME = "stamp-cert-sha256";
    private static final int TARGET_SANDBOX_VERSION_ATTR_ID = 16844108;
    private static final int TARGET_SDK_VERSION_ATTR_ID = 16843376;
    private static final String USES_SDK_ELEMENT_TAG = "uses-sdk";
    private static final int VERSION_CODE_ATTR_ID = 16843291;
    private static final int VERSION_CODE_MAJOR_ATTR_ID = 16844150;

    private ApkUtils() {
    }

    public static ZipSections findZipSections(DataSource apk) throws IOException, ZipFormatException {
        com.android.apksig.zip.ZipSections zipSections = ApkUtilsLite.findZipSections(apk);
        return new ZipSections(zipSections.getZipCentralDirectoryOffset(), zipSections.getZipCentralDirectorySizeBytes(), zipSections.getZipCentralDirectoryRecordCount(), zipSections.getZipEndOfCentralDirectoryOffset(), zipSections.getZipEndOfCentralDirectory());
    }

    public static class ZipSections extends com.android.apksig.zip.ZipSections {
        public ZipSections(long centralDirectoryOffset, long centralDirectorySizeBytes, int centralDirectoryRecordCount, long eocdOffset, ByteBuffer eocd) {
            super(centralDirectoryOffset, centralDirectorySizeBytes, centralDirectoryRecordCount, eocdOffset, eocd);
        }
    }

    public static void setZipEocdCentralDirectoryOffset(ByteBuffer zipEndOfCentralDirectory, long offset) {
        ByteBuffer eocd = zipEndOfCentralDirectory.slice();
        eocd.order(ByteOrder.LITTLE_ENDIAN);
        ZipUtils.setZipEocdCentralDirectoryOffset(eocd, offset);
    }

    public static ApkSigningBlock findApkSigningBlock(DataSource apk, ZipSections zipSections) throws IOException, ApkSigningBlockNotFoundException {
        ApkUtilsLite.ApkSigningBlock apkSigningBlock = ApkUtilsLite.findApkSigningBlock(apk, zipSections);
        return new ApkSigningBlock(apkSigningBlock.getStartOffset(), apkSigningBlock.getContents());
    }

    public static class ApkSigningBlock extends ApkUtilsLite.ApkSigningBlock {
        public ApkSigningBlock(long startOffsetInApk, DataSource contents) {
            super(startOffsetInApk, contents);
        }
    }

    public static ByteBuffer getAndroidManifest(DataSource apk) throws IOException, ApkFormatException {
        try {
            ZipSections zipSections = findZipSections(apk);
            CentralDirectoryRecord androidManifestCdRecord = null;
            Iterator<CentralDirectoryRecord> it = V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections).iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                CentralDirectoryRecord cdRecord = it.next();
                if (ANDROID_MANIFEST_ZIP_ENTRY_NAME.equals(cdRecord.getName())) {
                    androidManifestCdRecord = cdRecord;
                    break;
                }
            }
            if (androidManifestCdRecord == null) {
                throw new ApkFormatException("Missing AndroidManifest.xml");
            }
            DataSource lfhSection = apk.slice(0, zipSections.getZipCentralDirectoryOffset());
            try {
                return ByteBuffer.wrap(LocalFileRecord.getUncompressedData(lfhSection, androidManifestCdRecord, lfhSection.size()));
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Failed to read AndroidManifest.xml", e);
            }
        } catch (ZipFormatException e2) {
            throw new ApkFormatException("Not a valid ZIP archive", e2);
        }
    }

    public static int getMinSdkVersionFromBinaryAndroidManifest(ByteBuffer androidManifestContents) throws MinSdkVersionException {
        int result = 1;
        try {
            AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
            for (int eventType = parser.getEventType(); eventType != 2; eventType = parser.next()) {
                if (eventType == 3 && parser.getDepth() == 2 && USES_SDK_ELEMENT_TAG.equals(parser.getName()) && parser.getNamespace().isEmpty()) {
                    int minSdkVersion = 1;
                    int i = 0;
                    while (true) {
                        if (i < parser.getAttributeCount()) {
                            if (parser.getAttributeNameResourceId(i) == MIN_SDK_VERSION_ATTR_ID) {
                                switch (parser.getAttributeValueType(i)) {
                                    case 1:
                                        minSdkVersion = getMinSdkVersionForCodename(parser.getAttributeStringValue(i));
                                        break;
                                    case 2:
                                        minSdkVersion = parser.getAttributeIntValue(i);
                                        break;
                                    default:
                                        throw new MinSdkVersionException("Unable to determine APK's minimum supported Android: unsupported value type in AndroidManifest.xml's minSdkVersion. Only integer values supported.");
                                }
                            } else {
                                i++;
                            }
                        }
                    }
                    result = Math.max(result, minSdkVersion);
                }
            }
            return result;
        } catch (AndroidBinXmlParser.XmlParserException e) {
            throw new MinSdkVersionException("Unable to determine APK's minimum supported Android platform version: malformed binary resource: AndroidManifest.xml", e);
        }
    }

    /* access modifiers changed from: private */
    public static class CodenamesLazyInitializer {
        private static final Comparator<Pair<Character, Integer>> CODENAME_FIRST_CHAR_COMPARATOR = new ByFirstComparator();
        private static final Pair<Character, Integer>[] SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL = {Pair.of('C', 2), Pair.of('D', 3), Pair.of('E', 4), Pair.of('F', 7), Pair.of('G', 8), Pair.of('H', 10), Pair.of('I', 13), Pair.of('J', 15), Pair.of('K', 18), Pair.of('L', 20), Pair.of('M', 22), Pair.of('N', 23), Pair.of('O', 25)};

        private CodenamesLazyInitializer() {
        }

        private static class ByFirstComparator implements Comparator<Pair<Character, Integer>> {
            private ByFirstComparator() {
            }

            public int compare(Pair<Character, Integer> o1, Pair<Character, Integer> o2) {
                return o1.getFirst().charValue() - o2.getFirst().charValue();
            }
        }
    }

    static int getMinSdkVersionForCodename(String codename) throws CodenameMinSdkVersionException {
        char firstChar;
        if (codename.isEmpty()) {
            firstChar = ' ';
        } else {
            firstChar = codename.charAt(0);
        }
        if (firstChar < 'A' || firstChar > 'Z') {
            throw new CodenameMinSdkVersionException("Unable to determine APK's minimum supported Android platform version : Unsupported codename in AndroidManifest.xml's minSdkVersion: \"" + codename + "\"", codename);
        }
        Pair<Character, Integer>[] sortedCodenamesFirstCharToApiLevel = CodenamesLazyInitializer.SORTED_CODENAMES_FIRST_CHAR_TO_API_LEVEL;
        int searchResult = Arrays.binarySearch(sortedCodenamesFirstCharToApiLevel, Pair.of(Character.valueOf(firstChar), null), CodenamesLazyInitializer.CODENAME_FIRST_CHAR_COMPARATOR);
        if (searchResult >= 0) {
            return sortedCodenamesFirstCharToApiLevel[searchResult].getSecond().intValue();
        }
        int insertionIndex = -1 - searchResult;
        if (insertionIndex == 0) {
            return 1;
        }
        Pair<Character, Integer> newestOlderCodenameMapping = sortedCodenamesFirstCharToApiLevel[insertionIndex - 1];
        char newestOlderCodenameFirstChar = newestOlderCodenameMapping.getFirst().charValue();
        return (firstChar - newestOlderCodenameFirstChar) + newestOlderCodenameMapping.getSecond().intValue();
    }

    public static boolean getDebuggableFromBinaryAndroidManifest(ByteBuffer androidManifestContents) throws ApkFormatException {
        try {
            AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
            for (int eventType = parser.getEventType(); eventType != 2; eventType = parser.next()) {
                if (eventType == 3 && parser.getDepth() == 2 && "application".equals(parser.getName()) && parser.getNamespace().isEmpty()) {
                    for (int i = 0; i < parser.getAttributeCount(); i++) {
                        if (parser.getAttributeNameResourceId(i) == DEBUGGABLE_ATTR_ID) {
                            switch (parser.getAttributeValueType(i)) {
                                case 1:
                                case 2:
                                case 4:
                                    String value = parser.getAttributeStringValue(i);
                                    if ("true".equals(value) || "TRUE".equals(value) || "1".equals(value)) {
                                        return true;
                                    }
                                    return false;
                                case 3:
                                    throw new ApkFormatException("Unable to determine whether APK is debuggable: AndroidManifest.xml's android:debuggable attribute references a resource. References are not supported for security reasons. Only constant boolean, string and int values are supported.");
                                default:
                                    throw new ApkFormatException("Unable to determine whether APK is debuggable: AndroidManifest.xml's android:debuggable attribute uses unsupported value type. Only boolean, string and int values are supported.");
                            }
                        }
                    }
                    return false;
                }
            }
            return false;
        } catch (AndroidBinXmlParser.XmlParserException e) {
            throw new ApkFormatException("Unable to determine whether APK is debuggable: malformed binary resource: AndroidManifest.xml", e);
        }
    }

    public static String getPackageNameFromBinaryAndroidManifest(ByteBuffer androidManifestContents) throws ApkFormatException {
        try {
            AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
            for (int eventType = parser.getEventType(); eventType != 2; eventType = parser.next()) {
                if (eventType == 3 && parser.getDepth() == 1 && MANIFEST_ELEMENT_TAG.equals(parser.getName()) && parser.getNamespace().isEmpty()) {
                    for (int i = 0; i < parser.getAttributeCount(); i++) {
                        if ("package".equals(parser.getAttributeName(i)) && parser.getNamespace().isEmpty()) {
                            return parser.getAttributeStringValue(i);
                        }
                    }
                    return null;
                }
            }
            return null;
        } catch (AndroidBinXmlParser.XmlParserException e) {
            throw new ApkFormatException("Unable to determine APK package name: malformed binary resource: AndroidManifest.xml", e);
        }
    }

    public static int getTargetSandboxVersionFromBinaryAndroidManifest(ByteBuffer androidManifestContents) {
        try {
            return getAttributeValueFromBinaryAndroidManifest(androidManifestContents, MANIFEST_ELEMENT_TAG, TARGET_SANDBOX_VERSION_ATTR_ID);
        } catch (ApkFormatException e) {
            return 1;
        }
    }

    public static int getTargetSdkVersionFromBinaryAndroidManifest(ByteBuffer androidManifestContents) {
        int minSdkVersion = 1;
        try {
            return getAttributeValueFromBinaryAndroidManifest(androidManifestContents, USES_SDK_ELEMENT_TAG, TARGET_SDK_VERSION_ATTR_ID);
        } catch (ApkFormatException e) {
            androidManifestContents.rewind();
            try {
                minSdkVersion = getMinSdkVersionFromBinaryAndroidManifest(androidManifestContents);
            } catch (ApkFormatException e2) {
            }
            return minSdkVersion;
        }
    }

    public static int getVersionCodeFromBinaryAndroidManifest(ByteBuffer androidManifestContents) throws ApkFormatException {
        return getAttributeValueFromBinaryAndroidManifest(androidManifestContents, MANIFEST_ELEMENT_TAG, VERSION_CODE_ATTR_ID);
    }

    public static long getLongVersionCodeFromBinaryAndroidManifest(ByteBuffer androidManifestContents) throws ApkFormatException {
        int versionCode = getVersionCodeFromBinaryAndroidManifest(androidManifestContents);
        long versionCodeMajor = 0;
        try {
            androidManifestContents.rewind();
            versionCodeMajor = (long) getAttributeValueFromBinaryAndroidManifest(androidManifestContents, MANIFEST_ELEMENT_TAG, VERSION_CODE_MAJOR_ATTR_ID);
        } catch (ApkFormatException e) {
        }
        return (versionCodeMajor << 32) | ((long) versionCode);
    }

    private static int getAttributeValueFromBinaryAndroidManifest(ByteBuffer androidManifestContents, String elementName, int attributeId) throws ApkFormatException {
        if (elementName == null) {
            throw new NullPointerException("elementName cannot be null");
        }
        try {
            AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
            for (int eventType = parser.getEventType(); eventType != 2; eventType = parser.next()) {
                if (eventType == 3 && elementName.equals(parser.getName())) {
                    for (int i = 0; i < parser.getAttributeCount(); i++) {
                        if (parser.getAttributeNameResourceId(i) == attributeId) {
                            int valueType = parser.getAttributeValueType(i);
                            switch (valueType) {
                                case 1:
                                case 2:
                                    return parser.getAttributeIntValue(i);
                                default:
                                    throw new ApkFormatException("Unsupported value type, " + valueType + ", for attribute " + String.format("0x%08X", Integer.valueOf(attributeId)) + " under element " + elementName);
                            }
                        }
                    }
                    continue;
                }
            }
            throw new ApkFormatException("Failed to determine APK's " + elementName + " attribute " + String.format("0x%08X", Integer.valueOf(attributeId)) + " value");
        } catch (AndroidBinXmlParser.XmlParserException e) {
            throw new ApkFormatException("Unable to determine value for attribute " + String.format("0x%08X", Integer.valueOf(attributeId)) + " under element " + elementName + "; malformed binary resource: " + ANDROID_MANIFEST_ZIP_ENTRY_NAME, e);
        }
    }

    public static byte[] computeSha256DigestBytes(byte[] data) {
        return ApkUtilsLite.computeSha256DigestBytes(data);
    }
}
