package com.ducreyna.jwt;

/**
 * Created by nathan on 18/02/15.
 */
public enum Algorithm {
    HS256("HmacSHA256"),
    HS384("HmacSHA384"),
    HS512("HmacSHA512");

    private Algorithm(String value) {
        this.value = value;
    }

    private String value;

    public String getValue() {
        return value;
    }
}
