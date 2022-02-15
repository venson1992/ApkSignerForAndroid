//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.android.apksigner;

import android.os.Build;

import com.android.apksig.internal.apk.AutoCloseable;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class PasswordRetriever implements AutoCloseable {
    public static final String SPEC_STDIN = "stdin";
    private final Charset mConsoleEncoding = getConsoleEncoding();
    private final Map<File, InputStream> mFileInputStreams = new HashMap();
    private boolean mClosed;

    public PasswordRetriever() {
    }

    public List<char[]> getPasswords(String password, Charset... additionalPwdEncodings) {
        char[] pwd = password.toCharArray();
        return this.getPasswords(pwd, additionalPwdEncodings);
    }

    private List<char[]> getPasswords(char[] pwd, Charset... additionalEncodings) {
        List<char[]> passwords = new ArrayList(3);
        this.addPasswords(passwords, pwd, additionalEncodings);
        return passwords;
    }

    private void addPasswords(List<char[]> passwords, char[] pwd, Charset... additionalEncodings) {
        if (additionalEncodings != null && additionalEncodings.length > 0) {
            Charset[] var4 = additionalEncodings;
            int var5 = additionalEncodings.length;

            for (int var6 = 0; var6 < var5; ++var6) {
                Charset encoding = var4[var6];

                try {
                    char[] encodedPwd = castBytesToChars(encodePassword(pwd, encoding));
                    addPassword(passwords, encodedPwd);
                } catch (IOException var11) {
                }
            }
        }

        addPassword(passwords, pwd);
        char[] encodedPwd;
        if (this.mConsoleEncoding != null) {
            try {
                encodedPwd = castBytesToChars(encodePassword(pwd, this.mConsoleEncoding));
                addPassword(passwords, encodedPwd);
            } catch (IOException var10) {
            }
        }

        try {
            encodedPwd = castBytesToChars(encodePassword(pwd, Charset.defaultCharset()));
            addPassword(passwords, encodedPwd);
        } catch (IOException var9) {
        }

    }

    private static void addPassword(List<char[]> passwords, char[] password) {
        Iterator var2 = passwords.iterator();

        char[] existingPassword;
        do {
            if (!var2.hasNext()) {
                passwords.add(password);
                return;
            }

            existingPassword = (char[]) var2.next();
        } while (!Arrays.equals(password, existingPassword));

    }

    private static byte[] encodePassword(char[] pwd, Charset cs) throws IOException {
        ByteBuffer pwdBytes = cs.newEncoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE).encode(CharBuffer.wrap(pwd));
        byte[] encoded = new byte[pwdBytes.remaining()];
        pwdBytes.get(encoded);
        return encoded;
    }

    private static char[] castBytesToChars(byte[] bytes) {
        if (bytes == null) {
            return null;
        } else {
            char[] chars = new char[bytes.length];

            for (int i = 0; i < bytes.length; ++i) {
                chars[i] = (char) (bytes[i] & 255);
            }

            return chars;
        }
    }

    private static boolean isJava9OrHigherErrOnTheSideOfCaution() {
        String versionString = System.getProperty("java.specification.version");
        if (versionString == null) {
            return true;
        } else {
            return !versionString.startsWith("1.");
        }
    }

    private static Charset getConsoleEncoding() {
        if (isJava9OrHigherErrOnTheSideOfCaution()) {
            return null;
        } else {
            String consoleCharsetName = null;

            try {
                Method encodingMethod = Console.class.getDeclaredMethod("encoding");
                encodingMethod.setAccessible(true);
                consoleCharsetName = (String) encodingMethod.invoke((Object) null);
            } catch (Exception var3) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    if (var3 instanceof ReflectiveOperationException) {
                        return null;
                    }
                }
                return null;
            }

            if (consoleCharsetName == null) {
                return Charset.defaultCharset();
            } else {
                try {
                    return getCharsetByName(consoleCharsetName);
                } catch (IllegalArgumentException var2) {
                    return null;
                }
            }
        }
    }

    public static Charset getCharsetByName(String charsetName) throws IllegalArgumentException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return "cp65001".equalsIgnoreCase(charsetName) ? StandardCharsets.UTF_8 : Charset.forName(charsetName);
        }
        return "cp65001".equalsIgnoreCase(charsetName) ? Charset.forName("UTF-8") : Charset.forName(charsetName);
    }

    public void close() {
        Iterator var1 = this.mFileInputStreams.values().iterator();

        while (var1.hasNext()) {
            InputStream in = (InputStream) var1.next();

            try {
                in.close();
            } catch (IOException var4) {
            }
        }

        this.mFileInputStreams.clear();
        this.mClosed = true;
    }
}
