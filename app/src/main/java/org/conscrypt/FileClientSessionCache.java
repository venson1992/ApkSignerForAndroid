package org.conscrypt;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSession;
import org.conscrypt.io.IoUtils;

public final class FileClientSessionCache {
    public static final int MAX_SIZE = 12;
    static final Map<File, Impl> caches = new HashMap();
    private static final Logger logger = Logger.getLogger(FileClientSessionCache.class.getName());

    private FileClientSessionCache() {
    }

    static class Impl implements SSLClientSessionCache {
        Map<String, File> accessOrder = newAccessOrder();
        final File directory;
        String[] initialFiles;
        int size;

        Impl(File directory2) throws IOException {
            boolean exists = directory2.exists();
            if (!exists || directory2.isDirectory()) {
                if (exists) {
                    this.initialFiles = directory2.list();
                    if (this.initialFiles == null) {
                        throw new IOException(directory2 + " exists but cannot list contents.");
                    }
                    Arrays.sort(this.initialFiles);
                    this.size = this.initialFiles.length;
                } else if (!directory2.mkdirs()) {
                    throw new IOException("Creation of " + directory2 + " directory failed.");
                } else {
                    this.size = 0;
                }
                this.directory = directory2;
                return;
            }
            throw new IOException(directory2 + " exists but is not a directory.");
        }

        private static Map<String, File> newAccessOrder() {
            return new LinkedHashMap(12, 0.75f, true);
        }

        private static String fileName(String host, int port) {
            if (host != null) {
                return host + "." + port;
            }
            throw new NullPointerException("host == null");
        }

        /* JADX INFO: finally extract failed */
        @Override // org.conscrypt.SSLClientSessionCache
        public synchronized byte[] getSessionData(String host, int port) {
            byte[] data;
            String name = fileName(host, port);
            File file = this.accessOrder.get(name);
            if (file == null) {
                if (this.initialFiles == null) {
                    data = null;
                } else if (Arrays.binarySearch(this.initialFiles, name) < 0) {
                    data = null;
                } else {
                    file = new File(this.directory, name);
                    this.accessOrder.put(name, file);
                }
            }
            try {
                FileInputStream in = new FileInputStream(file);
                try {
                    data = new byte[((int) file.length())];
                    new DataInputStream(in).readFully(data);
                    IoUtils.closeQuietly(in);
                } catch (IOException e) {
                    logReadError(host, file, e);
                    IoUtils.closeQuietly(in);
                    data = null;
                } catch (Throwable th) {
                    IoUtils.closeQuietly(in);
                    throw th;
                }
            } catch (FileNotFoundException e2) {
                logReadError(host, file, e2);
                data = null;
            }
            return data;
        }

        static void logReadError(String host, File file, Throwable t) {
            FileClientSessionCache.logger.log(Level.WARNING, "FileClientSessionCache: Error reading session data for " + host + " from " + file + ".", t);
        }

        @Override // org.conscrypt.SSLClientSessionCache
        public synchronized void putSessionData(SSLSession session, byte[] sessionData) {
            String host = session.getPeerHost();
            if (sessionData == null) {
                throw new NullPointerException("sessionData == null");
            }
            String name = fileName(host, session.getPeerPort());
            File file = new File(this.directory, name);
            boolean existedBefore = file.exists();
            try {
                FileOutputStream out = new FileOutputStream(file);
                if (!existedBefore) {
                    this.size++;
                    makeRoom();
                }
                try {
                    out.write(sessionData);
                    try {
                        out.close();
                        if (1 == 0 || 1 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (IOException e) {
                        logWriteError(host, file, e);
                        if (1 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (Throwable th) {
                        if (1 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                        throw th;
                    }
                } catch (IOException e2) {
                    logWriteError(host, file, e2);
                    try {
                        out.close();
                        if (0 == 0 || 1 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (IOException e3) {
                        logWriteError(host, file, e3);
                        if (0 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (Throwable th2) {
                        if (0 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                        throw th2;
                    }
                } catch (Throwable th3) {
                    try {
                        out.close();
                        if (0 == 0 || 1 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (IOException e4) {
                        logWriteError(host, file, e4);
                        if (0 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                    } catch (Throwable th4) {
                        if (0 == 0 || 0 == 0) {
                            delete(file);
                        } else {
                            this.accessOrder.put(name, file);
                        }
                        throw th4;
                    }
                    throw th3;
                }
            } catch (FileNotFoundException e5) {
                logWriteError(host, file, e5);
            }
        }

        private void makeRoom() {
            if (this.size > 12) {
                indexFiles();
                int removals = this.size - 12;
                Iterator<File> i = this.accessOrder.values().iterator();
                do {
                    delete(i.next());
                    i.remove();
                    removals--;
                } while (removals > 0);
            }
        }

        private void indexFiles() {
            String[] initialFiles2 = this.initialFiles;
            if (initialFiles2 != null) {
                this.initialFiles = null;
                Set<CacheFile> diskOnly = new TreeSet<>();
                for (String name : initialFiles2) {
                    if (!this.accessOrder.containsKey(name)) {
                        diskOnly.add(new CacheFile(this.directory, name));
                    }
                }
                if (!diskOnly.isEmpty()) {
                    Map<String, File> newOrder = newAccessOrder();
                    for (CacheFile cacheFile : diskOnly) {
                        newOrder.put(cacheFile.name, cacheFile);
                    }
                    newOrder.putAll(this.accessOrder);
                    this.accessOrder = newOrder;
                }
            }
        }

        private void delete(File file) {
            if (!file.delete()) {
                Exception e = new IOException("FileClientSessionCache: Failed to delete " + file + ".");
                FileClientSessionCache.logger.log(Level.WARNING, e.getMessage(), (Throwable) e);
            }
            this.size--;
        }

        static void logWriteError(String host, File file, Throwable t) {
            FileClientSessionCache.logger.log(Level.WARNING, "FileClientSessionCache: Error writing session data for " + host + " to " + file + ".", t);
        }
    }

    public static synchronized SSLClientSessionCache usingDirectory(File directory) throws IOException {
        Impl cache;
        synchronized (FileClientSessionCache.class) {
            cache = caches.get(directory);
            if (cache == null) {
                cache = new Impl(directory);
                caches.put(directory, cache);
            }
        }
        return cache;
    }

    static synchronized void reset() {
        synchronized (FileClientSessionCache.class) {
            caches.clear();
        }
    }

    /* access modifiers changed from: package-private */
    public static class CacheFile extends File {
        long lastModified = -1;
        final String name;

        CacheFile(File dir, String name2) {
            super(dir, name2);
            this.name = name2;
        }

        public long lastModified() {
            long lastModified2 = this.lastModified;
            if (lastModified2 != -1) {
                return lastModified2;
            }
            long lastModified3 = super.lastModified();
            this.lastModified = lastModified3;
            return lastModified3;
        }

        @Override // java.io.File
        public int compareTo(File another) {
            long result = lastModified() - another.lastModified();
            if (result == 0) {
                return super.compareTo(another);
            }
            return result < 0 ? -1 : 1;
        }
    }
}
