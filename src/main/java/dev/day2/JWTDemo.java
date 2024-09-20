package dev.day2;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

import io.jsonwebtoken.*;

import java.util.Date;

public class JWTDemo {

    private static String SECRET_KEY = "CfjtqYThkrcD5VgP24pAGO9m9XCNjE40R8uy3yuO28g1Gh137MWPjbm7RSlSJfTkQMSB622lP0Y7cZ12OwZvlqZSWD6QoHj28glk5r88Mhfl9Zv7MDfBqgGVz3WrknVa4pfg3gO24fZh2rY5h7y808PjNBBhjP2JQ7M8S50Se4nefXd85EW41s7NAW7FKGXxt1y631YIe5EKPetai84FOByP9QCd4d1KsUaMmzzD9xQ07gTT7tYL3kB1amcTs4FmOsq2si84l07OLZ5R6CMH9R7Wnvqp3263ehuwNdgVwn0j";

    //Sample method to construct a JWT
    public static String createJWT(String id, String issuer, String subject, long ttlMillis) {

        //The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        //if it has been specified, let's add the expiration
        if (ttlMillis >= 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();
    }

    public static Claims decodeJWT(String jwt) {
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                .parseClaimsJws(jwt).getBody();
        return claims;
    }

    public static void main(String[] args) {
        String jwt = createJWT("123", "http://example.com", "example", 10000);
        System.out.println(jwt);
        Claims claims = decodeJWT(jwt);
        System.out.println(claims.getId());
        System.out.println(claims.getSubject());
        System.out.println(claims.getIssuer());
        System.out.println(claims.getIssuedAt());
        System.out.println(claims.getExpiration());
    }
}