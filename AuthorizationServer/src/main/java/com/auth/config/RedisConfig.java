package com.auth.config;

import java.util.Arrays;


import com.auth.dao.OAuth2RegisteredClientRepository;
import com.auth.service.RedisRegisteredClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@EnableRedisRepositories("com.auth.dao")
@Configuration(proxyBeanMethods = false)
public class RedisConfig {

    @Bean
    public RedisTemplate<String, String> redisTemplate(LettuceConnectionFactory lettuceConnectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(lettuceConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }

//    @Bean
//    public RedisCustomConversions redisCustomConversions() {
//        return new RedisCustomConversions(Arrays.asList(new UsernamePasswordAuthenticationTokenToBytesConverter(),
//                new BytesToUsernamePasswordAuthenticationTokenConverter(),
//                new OAuth2AuthorizationRequestToBytesConverter(), new BytesToOAuth2AuthorizationRequestConverter(),
//                new ClaimsHolderToBytesConverter(), new BytesToClaimsHolderConverter()));
//    }

//    @Bean
//    public RedisRegisteredClientRepository registeredClientRepository(
//            OAuth2RegisteredClientRepository registeredClientRepository) {
//        return new RedisRegisteredClientRepository(registeredClientRepository);
//    }

//    @Bean
//    public RedisOAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository,
//                                                                OAuth2AuthorizationGrantAuthorizationRepository authorizationGrantAuthorizationRepository) {
//        return new RedisOAuth2AuthorizationService(registeredClientRepository,
//                authorizationGrantAuthorizationRepository);
//    }
//
//    @Bean
//    public RedisOAuth2AuthorizationConsentService authorizationConsentService(
//            OAuth2UserConsentRepository userConsentRepository) {
//        return new RedisOAuth2AuthorizationConsentService(userConsentRepository);
//    }

}
