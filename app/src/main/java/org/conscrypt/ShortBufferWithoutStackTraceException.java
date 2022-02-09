package org.conscrypt;

import javax.crypto.ShortBufferException;

final class ShortBufferWithoutStackTraceException extends ShortBufferException {
    private static final long serialVersionUID = 676150236007842683L;

    public ShortBufferWithoutStackTraceException() {
    }

    public ShortBufferWithoutStackTraceException(String msg) {
        super(msg);
    }

    public Throwable fillInStackTrace() {
        return this;
    }
}
