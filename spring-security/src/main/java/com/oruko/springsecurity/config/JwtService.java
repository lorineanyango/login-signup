package com.oruko.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET = "L19Cg4V8Jt8FhmjoY3" +
            "JMfc8Acx62IHluSVtOuvB2zXZBXLcN" +
            "JRp9eAPMnJCPHdo/nh1ROYgoWSxJ8+8ejB" +
            "denkVSZN8e+/AaVpNca7R1gco9x4r8fQn82sJ+" +
            "tL71DItK9veqqhoHWcoVyZL084/3KfyZaLQBynZb4" +
            "YVgRGZmT/9w4A0db7Gfb73rULJMIR7nqpbUsT3Lwce" +
            "ZVONDI/leqVIIKKaO+7l3pZJbG69axkTgebfeEjEIl1wuv" +
            "K2/tMXm2piB9ZYqaVwmxwNxblftkDqdM5wIgAElDspSUdgHp" +
            "193/m1M4fXpoCxQUoVGH+lhTLxy8Vk1Z5WZevYiB/vbVurjFfFkiBMY6TcVd3aEBds=";
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }
    public boolean isTokenValid(String token, UserDetails userDetails){
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
       final Claims claims = extractAllClaims(token);
       return claimsResolver.apply(claims);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaim,
            UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 24))
                .signWith(getSignInKey(),SignatureAlgorithm.HS256)
                .compact();

    }
    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
