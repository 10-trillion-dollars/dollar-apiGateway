package org.example.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

@Component
public class JwtUtil {

    private Key key;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secret);
        key = Keys.hmacShaKeyFor(bytes);
    }


    @Value("${jwt.key}")
    private String secret;

    public String resolveToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith("Bearer ")) {
            return tokenValue.substring(7);
        }
        return null;
    }

    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public String getTokenFromCookie(ServerHttpRequest request) {
        MultiValueMap<String, HttpCookie> cookies = request.getCookies();
        Optional<HttpCookie> authCookie = Optional.ofNullable(cookies.getFirst("Authorization"));

        return authCookie.map(HttpCookie::getValue)
            .map(value -> URLDecoder.decode(value, StandardCharsets.UTF_8))
            .orElse(null);
    }
}
