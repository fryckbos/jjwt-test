package dev.day2;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JWTDemoTest {

    @Test
    public void testCreateJWT() {
        String jwt = JWTDemo.createJWT("123", "https://day2.dev", "example", 10000);
        assertNotNull(jwt);
    }

    @Test
    public void testDecodeJWT() {
        String jwt = JWTDemo.createJWT("123", "https://day2.dev", "example", 10000);
        Claims claims = JWTDemo.decodeJWT(jwt);
        assertEquals("123", claims.getId());
        assertEquals("example", claims.getSubject());
        assertEquals("https://day2.dev", claims.getIssuer());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
    }

    @Test
    public void testExpiredJWT() throws InterruptedException {
        String jwt = JWTDemo.createJWT("123", "https://day2.dev", "example", 1000);
        Thread.sleep(2000); // Wait for the token to expire
        assertThrows(ExpiredJwtException.class, () -> JWTDemo.decodeJWT(jwt));
    }

    @Test
    public void testInvalidJWT() {
        String invalidJwt = "invalid.jwt.token";
        assertThrows(MalformedJwtException.class, () -> JWTDemo.decodeJWT(invalidJwt));
    }

    @Test
    public void testInvalidSignatureJWT() {
        String jwt = JWTDemo.createJWT("123", "https://day2.dev", "example", 10000);
        // Tamper with the JWT to invalidate the signature
        String tamperedJwt = jwt.substring(0, jwt.length() - 1);
        assertThrows(SignatureException.class, () -> JWTDemo.decodeJWT(tamperedJwt));
    }

    @Test
    public void testNullJWT() {
        assertThrows(IllegalArgumentException.class, () -> JWTDemo.decodeJWT(null));
    }

    @Test
    public void testEmptyJWT() {
        assertThrows(IllegalArgumentException.class, () -> JWTDemo.decodeJWT(""));
    }
}