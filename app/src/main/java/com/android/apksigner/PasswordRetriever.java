package com.android.apksigner;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PasswordRetriever implements AutoCloseable {
    public static final String SPEC_STDIN = "stdin";
    private boolean mClosed;
    private final Charset mConsoleEncoding = getConsoleEncoding();
    private final Map<File, InputStream> mFileInputStreams = new HashMap();

    public List<char[]> getPasswords(String spec, String description, Charset... additionalPwdEncodings) throws IOException {
        assertNotClosed();
        if (spec.startsWith("pass:")) {
            return getPasswords(spec.substring("pass:".length()).toCharArray(), additionalPwdEncodings);
        }
        if (SPEC_STDIN.equals(spec)) {
            Console console = System.console();
            if (console != null) {
                char[] pwd = console.readPassword(description + ": ", new Object[0]);
                if (pwd != null) {
                    return getPasswords(pwd, additionalPwdEncodings);
                }
                throw new IOException("Failed to read " + description + ": console closed");
            }
            System.out.println(description + ": ");
            byte[] encodedPwd = readEncodedPassword(System.in);
            if (encodedPwd.length != 0) {
                return getPasswords(encodedPwd, Charset.defaultCharset(), additionalPwdEncodings);
            }
            throw new IOException("Failed to read " + description + ": standard input closed");
        } else if (spec.startsWith("file:")) {
            File file = new File(spec.substring("file:".length())).getCanonicalFile();
            InputStream in = this.mFileInputStreams.get(file);
            if (in == null) {
                in = new FileInputStream(file);
                this.mFileInputStreams.put(file, in);
            }
            byte[] encodedPwd2 = readEncodedPassword(in);
            if (encodedPwd2.length != 0) {
                return getPasswords(encodedPwd2, Charset.defaultCharset(), additionalPwdEncodings);
            }
            throw new IOException("Failed to read " + description + " : end of file reached in " + file);
        } else if (spec.startsWith("env:")) {
            String value = System.getenv(spec.substring("env:".length()));
            if (value != null) {
                return getPasswords(value.toCharArray(), additionalPwdEncodings);
            }
            throw new IOException("Failed to read " + description + ": environment variable " + value + " not specified");
        } else {
            throw new IOException("Unsupported password spec for " + description + ": " + spec);
        }
    }

    private List<char[]> getPasswords(char[] pwd, Charset... additionalEncodings) {
        List<char[]> passwords = new ArrayList<>(3);
        addPasswords(passwords, pwd, additionalEncodings);
        return passwords;
    }

    private List<char[]> getPasswords(byte[] encodedPwd, Charset encodingForDecoding, Charset... additionalEncodings) {
        List<char[]> passwords = new ArrayList<>(4);
        try {
            addPasswords(passwords, decodePassword(encodedPwd, encodingForDecoding), additionalEncodings);
        } catch (IOException e) {
        }
        addPassword(passwords, castBytesToChars(encodedPwd));
        return passwords;
    }

    private void addPasswords(List<char[]> passwords, char[] pwd, Charset... additionalEncodings) {
        if (additionalEncodings != null && additionalEncodings.length > 0) {
            for (Charset encoding : additionalEncodings) {
                try {
                    addPassword(passwords, castBytesToChars(encodePassword(pwd, encoding)));
                } catch (IOException e) {
                }
            }
        }
        addPassword(passwords, pwd);
        if (this.mConsoleEncoding != null) {
            try {
                addPassword(passwords, castBytesToChars(encodePassword(pwd, this.mConsoleEncoding)));
            } catch (IOException e2) {
            }
        }
        try {
            addPassword(passwords, castBytesToChars(encodePassword(pwd, Charset.defaultCharset())));
        } catch (IOException e3) {
        }
    }

    private static void addPassword(List<char[]> passwords, char[] password) {
        for (char[] existingPassword : passwords) {
            if (Arrays.equals(password, existingPassword)) {
                return;
            }
        }
        passwords.add(password);
    }

    private static byte[] encodePassword(char[] pwd, Charset cs) throws IOException {
        ByteBuffer pwdBytes = cs.newEncoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE).encode(CharBuffer.wrap(pwd));
        byte[] encoded = new byte[pwdBytes.remaining()];
        pwdBytes.get(encoded);
        return encoded;
    }

    private static char[] decodePassword(byte[] pwdBytes, Charset encoding) throws IOException {
        CharBuffer pwdChars = encoding.newDecoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE).decode(ByteBuffer.wrap(pwdBytes));
        char[] result = new char[pwdChars.remaining()];
        pwdChars.get(result);
        return result;
    }

    private static char[] castBytesToChars(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) (bytes[i] & 255);
        }
        return chars;
    }

    private static boolean isJava9OrHigherErrOnTheSideOfCaution() {
        String versionString = System.getProperty("java.specification.version");
        if (versionString != null && versionString.startsWith("1.")) {
            return false;
        }
        return true;
    }

    private static Charset getConsoleEncoding() {
        if (isJava9OrHigherErrOnTheSideOfCaution()) {
            return null;
        }
        try {
            Method encodingMethod = Console.class.getDeclaredMethod("encoding", new Class[0]);
            encodingMethod.setAccessible(true);
            String consoleCharsetName = (String) encodingMethod.invoke(null, new Object[0]);
            if (consoleCharsetName == null) {
                return Charset.defaultCharset();
            }
            try {
                return getCharsetByName(consoleCharsetName);
            } catch (IllegalArgumentException e) {
                return null;
            }
        } catch (ReflectiveOperationException e2) {
            return null;
        }
    }

    public static Charset getCharsetByName(String charsetName) throws IllegalArgumentException {
        if ("cp65001".equalsIgnoreCase(charsetName)) {
            return StandardCharsets.UTF_8;
        }
        return Charset.forName(charsetName);
    }

    private static byte[] readEncodedPassword(InputStream in) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while (true) {
            int b = in.read();
            if (b == -1 || b == 10) {
                break;
            }
            if (b == 13) {
                int next = in.read();
                if (next == -1 || next == 10) {
                    break;
                }
                if (!(in instanceof PushbackInputStream)) {
                    in = new PushbackInputStream(in);
                }
                ((PushbackInputStream) in).unread(next);
            }
            result.write(b);
        }
        return result.toByteArray();
    }

    private void assertNotClosed() {
        if (this.mClosed) {
            throw new IllegalStateException("Closed");
        }
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        for (InputStream in : this.mFileInputStreams.values()) {
            try {
                in.close();
            } catch (IOException e) {
            }
        }
        this.mFileInputStreams.clear();
        this.mClosed = true;
    }
}
