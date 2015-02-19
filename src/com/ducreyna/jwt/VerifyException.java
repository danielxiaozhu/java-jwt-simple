package com.ducreyna.jwt;

/**
 * Created by Nathan Ducrey on 19/02/15.
 */
public class VerifyException extends Exception {
    /**
     *
     */
    private static final long serialVersionUID = -4911506451239107610L;

    public VerifyException() {
    }



    public VerifyException(String message, Throwable cause) {
        super(message, cause);
    }


    public VerifyException(String message) {
        super(message);
    }
}
