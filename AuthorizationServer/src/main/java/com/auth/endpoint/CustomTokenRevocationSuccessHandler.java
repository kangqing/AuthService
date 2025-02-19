package com.auth.endpoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 自定义撤销令牌之后，存储被撤销的令牌到redis
 */
@Slf4j
@Component
public class CustomTokenRevocationSuccessHandler implements AuthenticationSuccessHandler {

//    private final RedisTemplate<String, String> redisTemplate;
//
//    public CustomTokenRevocationSuccessHandler(RedisTemplate<String, String> redisTemplate) {
//        this.redisTemplate = redisTemplate;
//    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        if (authentication instanceof OAuth2TokenRevocationAuthenticationToken) {
            // 获取撤销的 accessToken
            OAuth2TokenRevocationAuthenticationToken revocationToken = (OAuth2TokenRevocationAuthenticationToken) authentication;
            String accessToken = revocationToken.getToken();

            log.info(">>>>>>>>===>>> {}", accessToken);
            // 将 token 存储到 Redis 中
            //redisTemplate.opsForValue().set("revoked_access_token:" + accessToken, "revoked");

            // 可以在这里进一步处理其他逻辑，如日志记录等
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }
}
