package org.conscrypt.ct;

public class SerializationException extends Exception {
    private static final long serialVersionUID = -5317873136664833411L;

    public SerializationException() {
    }

    public SerializationException(String message) {
        super(message);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SerializationException(Throwable cause) {
        super(cause);
    }
}
