package com.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Objects;

public class TokenRevocationCheckFilter extends UsernamePasswordAuthenticationFilter {

//    private final RedisTemplate<String, String> redisTemplate;

//    public TokenRevocationCheckFilter(RedisTemplate<String, String> redisTemplate) {
//        this.redisTemplate = redisTemplate;
//    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authorizationHeader = httpRequest.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String accessToken = authorizationHeader.substring(7); // 获取 accessToken

            // 检查 accessToken 是否在 Redis 中已被标记为撤销
            // Boolean isRevoked = redisTemplate.hasKey("revoked_access_token:" + accessToken);
            Boolean isRevoked = Objects.equals(accessToken, "eyJraWQiOiIzNTJlZDAyMS1mMzgzLTRhODMtOTVjNy1mZjIzODlhODVjMDMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvaWRjLWNsaWVudCIsImF1ZCI6Im9pZGMtY2xpZW50IiwibmJmIjoxNzM5OTY5MjA4LCJzY29wZSI6WyJyZWFkIl0sInJvbGVzIjpbIlJPTEVfVVNFUiIsIlJPTEVfQURNSU4iXSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo5MDAwIiwiZXhwIjoxNzM5OTY5NTA4LCJpYXQiOjE3Mzk5NjkyMDgsImp0aSI6IjgwNGNmZDczLThmZWItNGQwYi04M2VkLTI1NTRkMGFkODQ0OCIsImF1dGhvcml0aWVzIjpbImFiYzoxMjMiLCJhYmM6NDU2Il19.Yd_zY5apisNcPsieyrad_Co6nqZv8BFOO4H5-BJPUBH18FFdRpbHFr3PfEjk9wWGmB-SPdUZu1bddT8rs2XHYWjHiMWtE05SnjTzpqx6BlPHkam7SFCPO5_yRx9jQkEKdSegUFRQ5hepJ0ThV59klFudwM8LZ-QOX3Fa24WZ3hpe0l7YInAn3UdkCxPPZVrIlpn2VER7t4Tfl9VHQ6GcIUNSBBEAxOdixNSmBdsQpEL1FNvkOEvhJQ8fMxXH4CvuQwqwp98bsRPjPidn-hMJEzk6BbuMvxxrmDcOQTW1czzs883JDrkySfGi5oYVH9lW3b8qywQf0IZGN1ngGTxl6Q");
            if (isRevoked != null && isRevoked) {
                // 如果已撤销，返回 401 Unauthorized 或 403 Forbidden
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                return; // 不继续往下处理
            }
        }

        // 继续执行过滤器链
        chain.doFilter(request, response);
    }
}