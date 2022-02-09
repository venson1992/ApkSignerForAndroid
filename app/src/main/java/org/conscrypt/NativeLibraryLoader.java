package org.conscrypt;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.MessageFormat;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/* access modifiers changed from: package-private */
public final class NativeLibraryLoader {
    private static final String DELETE_LIB_PROPERTY_NAME = "org.conscrypt.native.deleteLibAfterLoading";
    private static final boolean DELETE_NATIVE_LIB_AFTER_LOADING = Boolean.valueOf(System.getProperty(DELETE_LIB_PROPERTY_NAME, "true")).booleanValue();
    private static final String NATIVE_RESOURCE_HOME = "META-INF/native/";
    private static final File WORKDIR;
    private static final String WORK_DIR_PROPERTY_NAME = "org.conscrypt.native.workdir";
    private static final Logger logger = Logger.getLogger(NativeLibraryLoader.class.getName());

    static {
        File workdir = getWorkDir();
        if (workdir == null) {
            workdir = HostProperties.getTempDir();
        }
        WORKDIR = workdir;
        log("-D{0}: {1}", WORK_DIR_PROPERTY_NAME, WORKDIR);
    }

    private static File getWorkDir() {
        String dirName = System.getProperty(WORK_DIR_PROPERTY_NAME);
        if (dirName == null) {
            return null;
        }
        File f = new File(dirName);
        if (f.mkdirs() || f.exists()) {
            try {
                return f.getAbsoluteFile();
            } catch (Exception e) {
                return f;
            }
        } else {
            log("Unable to find or create working directory: {0}", dirName);
            return null;
        }
    }

    static boolean loadFirstAvailable(ClassLoader loader, List<LoadResult> results, String... names) {
        for (String name : names) {
            if (load(name, loader, results)) {
                return true;
            }
        }
        return DELETE_NATIVE_LIB_AFTER_LOADING;
    }

    /* access modifiers changed from: package-private */
    public static final class LoadResult {
        final boolean absolute;
        final Throwable error;
        final boolean loaded;
        final String name;
        final boolean usingHelperClassloader;

        /* access modifiers changed from: private */
        public static LoadResult newSuccessResult(String name2, boolean absolute2, boolean usingHelperClassloader2) {
            return new LoadResult(name2, absolute2, true, usingHelperClassloader2, null);
        }

        /* access modifiers changed from: private */
        public static LoadResult newFailureResult(String name2, boolean absolute2, boolean usingHelperClassloader2, Throwable error2) {
            return new LoadResult(name2, absolute2, NativeLibraryLoader.DELETE_NATIVE_LIB_AFTER_LOADING, usingHelperClassloader2, error2);
        }

        private LoadResult(String name2, boolean absolute2, boolean loaded2, boolean usingHelperClassloader2, Throwable error2) {
            this.name = name2;
            this.absolute = absolute2;
            this.loaded = loaded2;
            this.usingHelperClassloader = usingHelperClassloader2;
            this.error = error2;
        }

        /* access modifiers changed from: package-private */
        public void log() {
            if (this.error != null) {
                NativeLibraryLoader.log("Unable to load the library {0} (using helper classloader={1})", this.name, Boolean.valueOf(this.usingHelperClassloader), this.error);
            } else {
                NativeLibraryLoader.log("Successfully loaded library {0}  (using helper classloader={1})", this.name, Boolean.valueOf(this.usingHelperClassloader));
            }
        }
    }

    private static boolean load(String name, ClassLoader loader, List<LoadResult> results) {
        if (loadFromWorkdir(name, loader, results) || loadLibrary(loader, name, DELETE_NATIVE_LIB_AFTER_LOADING, results)) {
            return true;
        }
        return DELETE_NATIVE_LIB_AFTER_LOADING;
    }

    private static boolean loadFromWorkdir(String name, ClassLoader loader, List<LoadResult> results) {
        String libname = System.mapLibraryName(name);
        String path = NATIVE_RESOURCE_HOME + libname;
        URL url = loader.getResource(path);
        if (url == null && HostProperties.isOSX()) {
            url = path.endsWith(".jnilib") ? loader.getResource("META-INF/native/lib" + name + ".dynlib") : loader.getResource("META-INF/native/lib" + name + ".jnilib");
        }
        if (url == null) {
            return DELETE_NATIVE_LIB_AFTER_LOADING;
        }
        int index = libname.lastIndexOf(46);
        File tmpFile = null;
        try {
            File tmpFile2 = Platform.createTempFile(libname.substring(0, index), libname.substring(index, libname.length()), WORKDIR);
            if (!tmpFile2.isFile() || !tmpFile2.canRead() || Platform.canExecuteExecutable(tmpFile2)) {
                copyLibrary(url, tmpFile2);
                boolean loadLibrary = loadLibrary(loader, tmpFile2.getPath(), true, results);
                if (tmpFile2 == null) {
                    return loadLibrary;
                }
                boolean deleted = DELETE_NATIVE_LIB_AFTER_LOADING;
                if (DELETE_NATIVE_LIB_AFTER_LOADING) {
                    deleted = tmpFile2.delete();
                }
                if (deleted) {
                    return loadLibrary;
                }
                tmpFile2.deleteOnExit();
                return loadLibrary;
            }
            throw new IOException(MessageFormat.format("{0} exists but cannot be executed even when execute permissions set; check volume for \"noexec\" flag; use -D{1}=[path] to set native working directory separately.", tmpFile2.getPath(), WORK_DIR_PROPERTY_NAME));
        } catch (IOException e) {
            results.add(LoadResult.newFailureResult(name, true, DELETE_NATIVE_LIB_AFTER_LOADING, new UnsatisfiedLinkError(MessageFormat.format("Failed creating temp file ({0})", null)).initCause(e)));
            if (0 == 0) {
                return DELETE_NATIVE_LIB_AFTER_LOADING;
            }
            boolean deleted2 = DELETE_NATIVE_LIB_AFTER_LOADING;
            if (DELETE_NATIVE_LIB_AFTER_LOADING) {
                deleted2 = tmpFile.delete();
            }
            if (deleted2) {
                return DELETE_NATIVE_LIB_AFTER_LOADING;
            }
            tmpFile.deleteOnExit();
            return DELETE_NATIVE_LIB_AFTER_LOADING;
        } catch (Throwable th) {
            if (0 != 0) {
                boolean deleted3 = DELETE_NATIVE_LIB_AFTER_LOADING;
                if (DELETE_NATIVE_LIB_AFTER_LOADING) {
                    deleted3 = tmpFile.delete();
                }
                if (!deleted3) {
                    tmpFile.deleteOnExit();
                }
            }
            throw th;
        }
    }

    private static void copyLibrary(URL classpathUrl, File tmpFile) throws IOException {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = classpathUrl.openStream();
            OutputStream out2 = new FileOutputStream(tmpFile);
            try {
                byte[] buffer = new byte[8192];
                while (true) {
                    int length = in.read(buffer);
                    if (length > 0) {
                        out2.write(buffer, 0, length);
                    } else {
                        out2.flush();
                        closeQuietly(in);
                        closeQuietly(out2);
                        return;
                    }
                }
            } catch (Throwable th) {
                th = th;
                out = out2;
                closeQuietly(in);
                closeQuietly(out);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            closeQuietly(in);
            closeQuietly(out);
            throw th;
        }
    }

    private static boolean loadLibrary(ClassLoader loader, String name, boolean absolute, List<LoadResult> results) {
        try {
            LoadResult result = loadLibraryFromHelperClassloader(tryToLoadClass(loader, NativeLibraryUtil.class), name, absolute);
            results.add(result);
            if (result.loaded) {
                return true;
            }
        } catch (Exception e) {
        }
        LoadResult result2 = loadLibraryFromCurrentClassloader(name, absolute);
        results.add(result2);
        return result2.loaded;
    }

    private static LoadResult loadLibraryFromHelperClassloader(final Class<?> helper, final String name, final boolean absolute) {
        return (LoadResult) AccessController.doPrivileged(new PrivilegedAction<LoadResult>() {
            /* class org.conscrypt.NativeLibraryLoader.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public LoadResult run() {
                try {
                    Method method = helper.getMethod("loadLibrary", String.class, Boolean.TYPE);
                    method.setAccessible(true);
                    method.invoke(null, name, Boolean.valueOf(absolute));
                    return LoadResult.newSuccessResult(name, absolute, true);
                } catch (InvocationTargetException e) {
                    return LoadResult.newFailureResult(name, absolute, true, e.getCause());
                } catch (Throwable e2) {
                    return LoadResult.newFailureResult(name, absolute, true, e2);
                }
            }
        });
    }

    private static LoadResult loadLibraryFromCurrentClassloader(String name, boolean absolute) {
        try {
            NativeLibraryUtil.loadLibrary(name, absolute);
            return LoadResult.newSuccessResult(name, absolute, DELETE_NATIVE_LIB_AFTER_LOADING);
        } catch (Throwable e) {
            return LoadResult.newFailureResult(name, absolute, DELETE_NATIVE_LIB_AFTER_LOADING, e);
        }
    }

    private static Class<?> tryToLoadClass(final ClassLoader loader, final Class<?> helper) throws ClassNotFoundException {
        try {
            return loader.loadClass(helper.getName());
        } catch (ClassNotFoundException e) {
            final byte[] classBinary = classToByteArray(helper);
            return (Class) AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
                /* class org.conscrypt.NativeLibraryLoader.AnonymousClass2 */

                @Override // java.security.PrivilegedAction
                public Class<?> run() {
                    try {
                        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, Integer.TYPE, Integer.TYPE);
                        defineClass.setAccessible(true);
                        return (Class) defineClass.invoke(loader, helper.getName(), classBinary, 0, Integer.valueOf(classBinary.length));
                    } catch (Exception e) {
                        throw new IllegalStateException("Define class failed!", e);
                    }
                }
            });
        }
    }

    private static byte[] classToByteArray(Class<?> clazz) throws ClassNotFoundException {
        String fileName = clazz.getName();
        int lastDot = fileName.lastIndexOf(46);
        if (lastDot > 0) {
            fileName = fileName.substring(lastDot + 1);
        }
        URL classUrl = clazz.getResource(fileName + ".class");
        if (classUrl == null) {
            throw new ClassNotFoundException(clazz.getName());
        }
        byte[] buf = new byte[1024];
        ByteArrayOutputStream out = new ByteArrayOutputStream(ApkSigningBlockUtils.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
        try {
            InputStream in = classUrl.openStream();
            while (true) {
                int r = in.read(buf);
                if (r != -1) {
                    out.write(buf, 0, r);
                } else {
                    byte[] byteArray = out.toByteArray();
                    closeQuietly(in);
                    closeQuietly(out);
                    return byteArray;
                }
            }
        } catch (IOException ex) {
            throw new ClassNotFoundException(clazz.getName(), ex);
        } catch (Throwable th) {
            closeQuietly(null);
            closeQuietly(out);
            throw th;
        }
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException e) {
            }
        }
    }

    private NativeLibraryLoader() {
    }

    private static void log(String format, Object arg) {
        logger.log(Level.FINE, format, arg);
    }

    /* access modifiers changed from: private */
    public static void log(String format, Object arg1, Object arg2) {
        logger.log(Level.FINE, format, new Object[]{arg1, arg2});
    }

    /* access modifiers changed from: private */
    public static void log(String format, Object arg1, Object arg2, Throwable t) {
        debug(MessageFormat.format(format, arg1, arg2), t);
    }

    private static void debug(String message, Throwable t) {
        logger.log(Level.FINE, message, t);
    }
}
