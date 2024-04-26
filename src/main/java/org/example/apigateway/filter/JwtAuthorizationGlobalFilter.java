package org.example.apigateway.filter;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.example.apigateway.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration
@Slf4j
public class JwtAuthorizationGlobalFilter implements GlobalFilter, Ordered {


    private final JwtUtil jwtUtil;

    public JwtAuthorizationGlobalFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String tokenValue = jwtUtil.getTokenFromCookie(request);

        tokenValue = jwtUtil.resolveToken(tokenValue);

        log.info("I'm in filter" + tokenValue);
        if (StringUtils.hasText(tokenValue)) {
            try {
                Claims payload = jwtUtil.getUserInfoFromToken(tokenValue);

                // 사용자 정보 추출
                Long userId = Long.valueOf(payload.getSubject());
                String username = payload.get("username", String.class);
                String email = payload.get("email", String.class);
                String role = payload.get("role", String.class);

                // 추출한 사용자 정보를 요청 헤더에 추가
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", userId.toString())
                    .header("X-Username", username)
                    .header("X-User-Email", email)
                    .header("X-UserRole", role)
                    .build();

                log.info(String.format("User %s joined the server", username));

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            } catch (Exception e) {
                log.error("JWT 검증 실패: {}", e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange);
    }


    @Override
    public int getOrder() {
        return -1; // 필터 순서, 낮을수록 먼저 실행됨
    }
}
