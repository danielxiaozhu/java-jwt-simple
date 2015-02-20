# java-jwt-simple

Java implementation of JSON Web Tokens. An easy way to encode and decode a JWT with Java.

## Hashing algorithms

- SHA256
- SHA384
- SHA512

## Dependencies

__Additional libraries__

- [commons-codec-1.10](https://commons.apache.org/proper/commons-codec/download_codec.cgi)
- [commons-lang3-3.3.2](https://commons.apache.org/proper/commons-lang/download_lang.cgi)
- [gson-2.3.1](https://code.google.com/p/google-gson/)

__JUnit__

- [junit-4.12](https://github.com/junit-team/junit/wiki/Download-and-Install)
- [hamcrest-core-1.3](https://github.com/junit-team/junit/wiki/Download-and-Install)

## How to use

```java
import com.ducreyna.jwt;

String key = "secret";

try {
	// Encode a JWT with default algorithm
	HashMap<String, Object> payload = new HashMap<String, Object>();
	payload.put("name", "ducreyna");
	payload.put("admin", true);
	payload.put("state", new HashMap<String, Object>());

	String token = Jwt.encode(payload, key);


	// Encode a JWT with an algorithm of your choice
	HashMap<String, Object> payload = new HashMap<String, Object>();
	payload.put("name", "ducreyna");

	String token = Jwt.encode(payload, key, Algorithm.HS512);


	// Decode a JWT with signature verification
	Map<String, Object> decoded = Jwt.decode(token, key, true);
}
catch(Exception e) {}
```
