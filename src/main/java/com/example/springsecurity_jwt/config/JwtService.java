package com.example.springsecurity_jwt.config;

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

    private static final String SECRET_KEY="294A404E635266556A586E327234753778214125442A472D4B6150645367566B";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //to extract single claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // to generate token out of user details
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    // to generate token out of extra claims and user details
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername()) //it should be username or user email bcz its unique
                .setIssuedAt(new Date(System.currentTimeMillis())) //means when this claim was created  helps us to calculate the expiration date or to check if the token is still valid or not
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24)) // token will be valid for 24 hrs + 1000 milliseconds
                .signWith(getSignInkey(), SignatureAlgorithm.HS256) //which key we want to use to sign this token
                .compact(); //will generate and return the token
    }

    //to check if the token is valid or not
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extraExpiration(token).before(new Date());
    }

    private Date extraExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //to extract all claims
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInkey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
