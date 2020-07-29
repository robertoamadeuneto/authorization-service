package br.com.maxplorer.authorizationservice.core.application.domain.token;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.util.Date;

@AllArgsConstructor
@Getter
@Accessors(fluent = true)
public class Token {

    public static final String TOKEN_SECRET = "&3|*2])f:uS@t]i:5kn3#$?dxDZl%|>u";
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer";
    public static final long TOKEN_DURATION = 600000;

    private String token;
    private String refreshToken;

    public static Token newToken(String subject) {

        final String token = Jwts.builder()
                .setSubject(subject)
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_DURATION))
                .signWith(SignatureAlgorithm.HS512, TOKEN_SECRET)
                .compact();

        final String refreshToken = Jwts.builder()
                .setSubject(subject)
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_DURATION))
                .signWith(SignatureAlgorithm.HS512, TOKEN_SECRET)
                .compact();

        return new Token(token, refreshToken);
    }

    public static boolean isTokenValid(String token) {

        final String subject = Jwts.parser()
                .setSigningKey(TOKEN_SECRET)
                .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                .getBody()
                .getSubject();

        return subject != null;
    }
}
