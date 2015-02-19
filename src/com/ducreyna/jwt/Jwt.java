package com.ducreyna.jwt;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.istack.internal.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Nathan Ducrey on 18/02/15.
 */
public class Jwt {

    /**
     * Static method to decode a JSON Web Token
     *
     * @param token     Token to decode
     * @param key       Key used for the signature
     * @param verify    True if you want to verify the signature
     *
     * @return payload
     *
     * @throws IllegalStateException
     * @throws IllegalArgumentException
     * @throws VerifyException
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws AlgorithmException
     */
    public static Map<String, Object> decode(String token, String key, Boolean verify) throws IllegalStateException, VerifyException, IllegalArgumentException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, AlgorithmException {
        if (token == null || token.length() == 0) {
            throw new IllegalStateException("Token not set");
        }
        // Check key
        if(key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        String[] segments = StringUtils.split(token, ".");
        if(segments.length != 3) {
            throw new IllegalStateException("Bad number of segments: " + segments.length);
        }

        // All segment should be base64
        String headerSeg = segments[0];
        String payloadSeg = segments[1];
        String signatureSeg = segments[2];

        Type stringObjectMap = new TypeToken<HashMap<String, Object>>(){}.getType();
        Gson gson = new Gson();
        HashMap<String, Object> header = gson.fromJson(base64Decode(headerSeg), stringObjectMap);
        HashMap<String, Object> payload = gson.fromJson(base64Decode(payloadSeg), stringObjectMap);

        if(verify) {
            Algorithm algorithm = getAlgorithm(header.get("alg").toString());

            // Verify signature. `sign` will return base64 String
            String signinInput = StringUtils.join(new String[] {headerSeg, payloadSeg}, ".");
            if(!verify(signinInput, key, algorithm.getValue(), signatureSeg)) {
                throw new VerifyException("Bad signature");
            }
        }

        return payload;
    }

    /**
     * Static method to generate a JSON Web Token
     *
     * @param payload   JSON to attach
     * @param key       Key used for the signature
     *
     * @return token
     *
     * @throws IllegalArgumentException
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    public static String encode(HashMap<String, Object> payload, String key) throws IllegalArgumentException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        // Check key
        if(key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        Algorithm algorithm = Algorithm.HS256;

        // Header, typ is fixed value
        HashMap<String, String> header = new HashMap<String, String>();
        header.put("typ", "JWT");
        header.put("alg", algorithm.name());

        // Create segments, all segment should be base64 String
        ArrayList<String> segments = new ArrayList<String>();
        Gson gson = new Gson();
        segments.add(base64Encode(gson.toJson(header).getBytes()));
        segments.add(base64Encode(gson.toJson(payload).getBytes()));
        segments.add(base64Encode(sign(StringUtils.join(segments, "."), key, algorithm.getValue())));

        return StringUtils.join(segments, ".");
    }

    /**
     * Static method to generate a JSON Web Token
     *
     * @param payload   JSON to attach
     * @param key       Key used for the signature
     * @param algorithm Encryption algorithm to apply
     *
     * @return token
     *
     * @throws IllegalArgumentException
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    public static String encode(HashMap<String, Object> payload, String key, Algorithm algorithm) throws IllegalArgumentException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        // Check key
        if(key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        if(algorithm == null) {
            algorithm = algorithm.HS256;
        }

        // Header, typ is fixed value
        HashMap<String, String> header = new HashMap<String, String>();
        header.put("typ", "JWT");
        header.put("alg", algorithm.name());

        // Create segments, all segment should be base64 String
        ArrayList<String> segments = new ArrayList<String>();

        Gson gson = new Gson();
        segments.add(base64Encode(gson.toJson(header).getBytes()));
        segments.add(base64Encode(gson.toJson(payload).getBytes()));
        segments.add(base64Encode(sign(StringUtils.join(segments, "."), key, algorithm.getValue())));

        return StringUtils.join(segments, ".");
    }

    /**
     * Private method to generate a signature from a key
     *
     * @param input     Data to sign
     * @param key       Key used for the signature
     * @param method    Algorithm
     *
     * @return Signature
     *
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    private static byte[] sign (String input, String key, String method) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
        Mac hmac = Mac.getInstance(method);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), method);
        hmac.init(secretKey);

        return hmac.doFinal(input.getBytes());
    }

    /**
     * Private method to verify a signature
     *
     * @param input     Data to verify
     * @param key       Key used for the signature
     * @param method    Algorithm
     * @param signature Signature to compare
     *
     * @return Boolean
     *
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    private static Boolean verify (String input, String key, String method, String signature) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        return signature.equals(base64Encode(sign(input, key, method)));
    }

    /**
     * Private method to encode a String in base64
     *
     * @param bytes   Bytes to encode
     *
     * @return String
     *
     * @throws UnsupportedEncodingException
     */
    private static String base64Encode (byte[] bytes) throws UnsupportedEncodingException {
        return Base64.encodeBase64URLSafeString(bytes);
    }

    /**
     * Private method to decode a base64 String
     *
     * @param str String to decode
     *
     * @return String
     */
    private static String base64Decode (String str) {
        byte[] bytes = Base64.decodeBase64(str);
        return (new String(bytes));
    }

    /**
     * Private method to retrieve the algorithm used for encoding
     *
     * @param alg   Algorithm key
     *
     * @return Algorithm
     *
     * @throws AlgorithmException
     */
    private static Algorithm getAlgorithm (String alg) throws AlgorithmException {
        if(alg.equals("HS256")) {
            return Algorithm.HS256;
        } else if(alg.equals("HS384")) {
            return Algorithm.HS384;
        } else if(alg.equals("HS512")) {
            return Algorithm.HS512;
        } else {
            throw new AlgorithmException("Algorithm not supported");
        }
    }
}