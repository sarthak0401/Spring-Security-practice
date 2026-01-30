package com.example.springsecurity.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpirationMs}")    // This will be passed by application.properties file
    private int jwtExpirationMs; // If its equal to 300000 ms -> 5 mins, after this time the token will expire
    @Value("${spring.app.jwtSecretKey}")
    private String jwtSecretKey;    // these values will be passed in by application.properties

    // Getting the token from the header
    public String getJwtFromHeader(HttpServletRequest request){
        String tokenFromHeader = request.getHeader("Authorization");

        logger.debug("Authorization Header : {}", tokenFromHeader);

        if(tokenFromHeader !=null && tokenFromHeader.startsWith("Bearer ")){
            return tokenFromHeader.substring(7); // we are removing 'Bearer ' from the string, these are 7 units of length from start
        }
        return null;
    }

    // Generating token from the username
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()   // builder is there to build the token
                .subject(username) // setting the subject as username
                .issuedAt(new Date())  // new Date() object actually sets(refers) to the current time
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())  // signing the token with custom key function
                .compact();       // compact converts the content into JSON object and then encode header, payload and signature, and then concatenate them and convert all into a single jwt token string
    }

    // Getting username from jwt token
     public String getUsernameFromJWTToken(String jwtToken){
        return Jwts.parser() // parse is there to read the token
                .verifyWith((SecretKey) key()) // verifying the token with this key method
                .build().parseSignedClaims(jwtToken)   // build is use to build the parse // Claims -> data inside the jwt token, So parseSignedClaims -> parses the token and extract its claims
                .getPayload().getSubject();  // subject is usually the username
     }

    // Generating the signing key
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecretKey)
        );
    }

    // Validating the JWT token
    public boolean validateJWTToken(String authToken){
        try{
            System.out.println("Validating");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);

            return true;
        }
        catch (MalformedJwtException exception){
            logger.error("Invalid JWT Token: {}", exception.getMessage());
        }
        catch (ExpiredJwtException exception){
            logger.error("JWT Token is expired: {}", exception.getMessage());
        }
        catch (UnsupportedJwtException exception){
            logger.error("JWT Token unsupported: {}", exception.getMessage());
        }
        catch (IllegalArgumentException exception){
            logger.error("String is empty: {}", exception.getMessage());
        }
        return false;
    }

}
