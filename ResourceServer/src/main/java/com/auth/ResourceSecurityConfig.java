package com.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 开启方法级别安全限制，使 @PreAuthorize 注解生效
 */
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class ResourceSecurityConfig {

    /**
     * 解析授权服务器添加到 claims 中的角色和权限
     * @return
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix(""); // 去掉默认的 SCOPE_ 前缀
        //grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities"); // 指定权限字段

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        //jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        // 自定义的转换逻辑，确保角色和权限都被转换为 GrantedAuthority
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            // 获取 JWT 中的角色
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
            }

            // 获取 JWT 中的权限
            List<String> authoritiesClaim = jwt.getClaimAsStringList("authorities");
            if (authoritiesClaim != null) {
                authoritiesClaim.forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority)));
            }

            return authorities;
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(new TokenRevocationCheckFilter(), BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))  // 使用自定义的 JWT 转换器
                );

        return http.build();
    }

//    @Bean
//    public SpringOpaqueTokenIntrospector opaqueTokenIntrospector() {
//        return new SpringOpaqueTokenIntrospector(
//                "http://127.0.0.1:9000/oauth2/introspect", // 内省端点 URL
//                "oidc-client", // 客户端 ID
//                "123456" // 客户端密钥
//        );
//    }
}
