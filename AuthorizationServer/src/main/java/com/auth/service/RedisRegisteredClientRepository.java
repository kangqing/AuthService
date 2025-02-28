package com.auth.service;

import com.auth.dao.OAuth2RegisteredClientRepository;
import com.auth.entity.OAuth2RegisteredClient;
import org.springframework.context.annotation.Primary;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
@Primary
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2RegisteredClientRepository registeredClientRepository;

    public RedisRegisteredClientRepository(OAuth2RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    /**
     * 保存注册的客户端信息。
     *
     * @param registeredClient 要保存的注册客户端对象
     * @throws IllegalArgumentException 如果传入的 registeredClient 为 null，则抛出此异常
     */
    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        OAuth2RegisteredClient oauth2RegisteredClient = ModelMapper.convertOAuth2RegisteredClient(registeredClient);
        this.registeredClientRepository.save(oauth2RegisteredClient);
    }

    /**
     * 根据注册客户端ID查找注册客户端信息。
     *
     * @param id 注册客户端的唯一标识符。
     * @return 如果找到对应的注册客户端，则返回转换后的RegisteredClient对象；否则返回null。
     * @throws IllegalArgumentException 如果提供的ID为空，则抛出此异常。
     */
    @Nullable
    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.registeredClientRepository.findById(id).map(ModelMapper::convertRegisteredClient).orElse(null);
    }

    /**
     * 根据客户端ID查找已注册的客户端信息。
     *
     * @param clientId 客户端ID，用于唯一标识一个客户端。
     * @return 如果找到了对应的客户端信息，则返回封装后的RegisteredClient对象；如果未找到，则返回null。
     * @throws IllegalArgumentException 如果clientId为空或仅包含空白字符，则抛出此异常。
     */
    @Nullable
    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        OAuth2RegisteredClient oauth2RegisteredClient = this.registeredClientRepository.findByClientId(clientId);
        return oauth2RegisteredClient != null ? ModelMapper.convertRegisteredClient(oauth2RegisteredClient) : null;
    }

}
