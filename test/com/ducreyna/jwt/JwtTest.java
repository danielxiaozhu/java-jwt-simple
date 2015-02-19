package com.ducreyna.jwt;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Created by nathan on 19/02/15.
 */
public class JwtTest {
    private final String key = "secret";

    @Test
    public void shouldPayloadEmpty() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        String token = Jwt.encode(payload, key);
        Map<String, Object> decoded = Jwt.decode(token, key, true);

        assertEquals(payload, decoded);
    }

    @Test (expected = IllegalArgumentException.class)
    public void shouldKeyEncodingEmpty() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        Jwt.encode(payload, "");
    }

    @Test (expected = IllegalArgumentException.class)
    public void shouldKeyDecodingEmpty() throws Exception {
        Jwt.decode("token", null, null);
    }

    @Test (expected = IllegalStateException.class)
    public void shouldTokenEmpty() throws Exception {
        Jwt.decode("", key, null);
    }

    @Test (expected = IllegalStateException.class)
    public void shouldBadSegments() throws Exception {
        Jwt.decode("segment1.segment2", key, true);
    }

    @Test
    public void shouldVerifyGoodToken() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        payload.put("name", "ducreyna");
        payload.put("admin", true);
        payload.put("state", new HashMap<String, Object>());
        String token = Jwt.encode(payload, key);
        Map<String, Object> decoded = Jwt.decode(token, key, true);

        assertEquals(payload, decoded);
    }

    @Test
    public void shouldVerifyGoodTokenWithAlgorithm() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        payload.put("name", "ducreyna");
        String token = Jwt.encode(payload, key, Algorithm.HS512);
        Map<String, Object> decoded = Jwt.decode(token, key, true);

        assertEquals(payload, decoded);
    }

    @Test (expected = VerifyException.class)
    public void shouldVerifyBadToken() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        payload.put("name", "ducreyna");
        String token = Jwt.encode(payload, key);
        token = token.concat("IAMJOKER");
        Jwt.decode(token, key, true);
    }

    @Test
    public void shouldNotVerify() throws Exception {
        HashMap<String, Object> payload = new HashMap<String, Object>();
        payload.put("name", "ducreyna");
        String token = Jwt.encode(payload, key);
        token.concat("IAMBATMAN");
        Map<String, Object> decoded = Jwt.decode(token, key, false);

        assertEquals(payload, decoded);
    }
}
