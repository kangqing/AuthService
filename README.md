# 1.0 最简单方案，仅yml配置即可

## 授权码模式演示流程
1. 访问授权端点，触发授权流程 http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=oidc-client&scope=openid%20profile&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client
2. 跳转登录页面，用户名密码在yml中已经配置，abc/123456, 点击授权
3. url返回授权码code http://127.0.0.1:8080/login/oauth2/code/oidc-client?code=6bC8V9B78nH1xOVOYX1sBggXWEQPGVvg2eKOYjwY3p_GBqc3xsIFmcrUWZNYrZlLDWvHGL6D2e-ONgi8ZG3vKHVLF9giYRL0j5N4B0g8VwIjAmPZm7rHJnInQh0hmJae
4. 携带 appKey 和 appSecret 和 code 去换取 token
5. 请求token
```bash
curl -X POST \
  -u "oidc-client:123456" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=Vf_cEwx25tGO_zfmedsnuLxssJhqumvlQ5cXXlULDpi-H_I32hi2Ttao3-DXFU-lBQgKUTeqiKTa6T80FpDztHw5_5L4mKZXjxT_GuuZkVZUiae-Gozx1DVk-nBNyacM" \
  -d "redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client" \
  http://127.0.0.1:9000/oauth2/token
```
6. 返回结果
```json
{
    "access_token": "eyJraWQiOiJmYTUwYTM3Zi0xZjU3LTRlNzQtODFkZC04N2IzZDlhYmI3YmYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMiLCJhdWQiOiJvaWRjLWNsaWVudCIsIm5iZiI6MTczOTE1MzE2MSwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE3MzkxNTM0NjEsImlhdCI6MTczOTE1MzE2MSwianRpIjoiYzBhMmYyNDktOWY2Mi00M2FlLWIzYTEtMWY4ZTRlYzY2YTI4In0.SugSmbwRnRHywmgb_ojFI8GnTdFgeO67szrCs2CW2wN1EIWAeornfNIZTEfqSK7fteqDKl1Uc23BxxiCxHo8X-S3O0xpBTj5SEz02PYmGLQM9VfFWo4FFGGHZbxkFUBwVKXjwQpRdoHKlWmSl4GYE1-wAfUgI4_hGOnRpEKej2deuNUz3WdEpKupWSAN9tFVrH5ck8YqDZ5xlC_Vl7WKiN-Plgu2-uRsajoU-cTE0U-S4GRlAkTi7xL9SpO5GAGH1ilIQBVy0OR1UnVI0E7956UgWQduDz1F3fGbAiN4vH4R34zrcbITsnPJv1YyoS_w1zBmSuJoqjZ2vtR23oi3gg",
    "refresh_token": "XSgYRjy62ZspZPJQg_30p6bvR3OF924YMLH2XIzah39A9aEZjoN02EDTFvnMtqq5gI1i21H4oPc0KUV82yr_GCipR8Mwn62tUWJ54o39FTRYTO-Nz7h1ykzxRlGmHfzT",
    "scope": "openid profile",
    "id_token": "eyJraWQiOiJmYTUwYTM3Zi0xZjU3LTRlNzQtODFkZC04N2IzZDlhYmI3YmYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMiLCJhdWQiOiJvaWRjLWNsaWVudCIsImF6cCI6Im9pZGMtY2xpZW50IiwiYXV0aF90aW1lIjoxNzM5MTUzMTExLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE3MzkxNTQ5NjEsImlhdCI6MTczOTE1MzE2MSwianRpIjoiYzNhOGZhMmEtZTcyZS00MWVhLWJjZWUtMmUxM2RlODI2NjI3Iiwic2lkIjoiWjZRd2c4SUpaemFWUllPaUFfTERwS0NOQ2J0VXZqcnZDNk9YTzlqMGFlVSJ9.V3CrSTl6fq-Weuynm9j2V-hL4fmDjMCplsiqmB-xFxwbUlguJxGy3wGXGIRlsyS5WVVLpJ4E6gELQXVtnUrhyzXKXYT4xey238qKmr6NCoV39NzGEPdBcGGjbv-hHhSgrq0ZZw3DnpnUmFzar2CbrqYtd_grdMq11lyuO-W9PoS1tusGlU0sEOg5_T37yUbiykT1Kety7yypbqbLibo4dP_IMVdzHObjqXq86sQLeC8b4bDj3yRXeO4rZLxeyOMXA0e-nd-CxxOhcQgfwV2qly4Dfd0tpXdgcgM1u-FdN1k1WC76FVCWpWedzX1SC-fGzPpGKZtkj6tfeyTs9yp1WQ",
    "token_type": "Bearer",
    "expires_in": 299
}
```

7. 携带 access_token 访问资源服务器接口

```bash
curl -H "Authorization: Bearer eyJraWQiOiI1YTQwOGUyNi1hMGU4LTRkMGQtYjllZS01Nzk1YmRmMGIzMGMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMiLCJhdWQiOiJvaWRjLWNsaWVudCIsIm5iZiI6MTczOTE1NjI0OSwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE3MzkxNTY1NDksImlhdCI6MTczOTE1NjI0OSwianRpIjoiMmZmYzQ5YTMtYzcxMy00ZmQxLWFkYWQtMjY3YjUwZjBmNTUzIn0.L3j1D3OJilmWCsVFOcxhmPUzex8hbxjP4CmL2pxmuoRDm_PNt_EEsqj0xsvV9ZUb8_a-LygEI5SppFK5nioFT7ubKQyCDNDpWRxw02q-ag6ZRoNEmkborKP_wU7IrkJ2wIBuiXDWGwh3bYBFAP_cRV9zE7rzeR-xVcUr2xSaBcHRP49zHIOy855a65aMCSiIDzyyict0XA4DjsFKfE_9scMHvALn1V4jyy_eofyupDOrfueENVuSQ_C4LZQ9DEjDTYdo_LX9AX_FR9wfn0dE0iOmYP7Mr5chEYzDjw0zdkDYWvg8RWGJvo5V-HEHwbwWTc7YcYTjqEk1sFP_f2f0sA" \
     http://127.0.0.1:9001/test
```

7.1 携带 access_token 访问授权服务器的 /userinfo 端点
```bash
curl -H "Authorization: Bearer eyJraWQiOiI1YTQwOGUyNi1hMGU4LTRkMGQtYjllZS01Nzk1YmRmMGIzMGMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMiLCJhdWQiOiJvaWRjLWNsaWVudCIsIm5iZiI6MTczOTE1NjI0OSwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE3MzkxNTY1NDksImlhdCI6MTczOTE1NjI0OSwianRpIjoiMmZmYzQ5YTMtYzcxMy00ZmQxLWFkYWQtMjY3YjUwZjBmNTUzIn0.L3j1D3OJilmWCsVFOcxhmPUzex8hbxjP4CmL2pxmuoRDm_PNt_EEsqj0xsvV9ZUb8_a-LygEI5SppFK5nioFT7ubKQyCDNDpWRxw02q-ag6ZRoNEmkborKP_wU7IrkJ2wIBuiXDWGwh3bYBFAP_cRV9zE7rzeR-xVcUr2xSaBcHRP49zHIOy855a65aMCSiIDzyyict0XA4DjsFKfE_9scMHvALn1V4jyy_eofyupDOrfueENVuSQ_C4LZQ9DEjDTYdo_LX9AX_FR9wfn0dE0iOmYP7Mr5chEYzDjw0zdkDYWvg8RWGJvo5V-HEHwbwWTc7YcYTjqEk1sFP_f2f0sA" \
     http://127.0.0.1:9000/userinfo
```

8. 刷新token

```bash
curl -X POST \
  -u "oidc-client:123456" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=XSgYRjy62ZspZPJQg_30p6bvR3OF924YMLH2XIzah39A9aEZjoN02EDTFvnMtqq5gI1i21H4oPc0KUV82yr_GCipR8Mwn62tUWJ54o39FTRYTO-Nz7h1ykzxRlGmHfzT" \
  http://127.0.0.1:9000/oauth2/token
```

## 注意
1. 授权服务器和资源服务器要分开，否则需要配置资源服务器接口不走授权服务器拦截器等

2. 授权服务器更简单，仅仅需要声明接口和授权服务器公钥的地址
```yml
server:
  port: 9001  # 资源服务器在 9001 端口运行

spring:
  security:
    oauth2:
      resource server:
        jwt:
          jwk-set-uri: http://127.0.0.1:9000/oauth2/jwks  # 设置授权服务器的公钥 JWK URL
```



## 授权码模式结合 PKCE 
![](./截屏2025-02-14%2011.30.42.png)
PKCE 主要用于 公共客户端，尤其是没有安全存储密钥的客户端，如移动端应用或单页应用（SPA）。这些应用程序通常运行在用户的浏览器或移动设备上，
不能像传统的服务端应用那样安全地存储 client_secret。因此，PKCE 提供了一种安全的方式来交换授权码，从而防止授权码被拦截。

![截屏2025-02-14 11.42.02.png](%E6%88%AA%E5%B1%8F2025-02-14%2011.42.02.png)

在这种情况下，PKCE 结合授权码模式（Authorization Code Flow）并不返回 refresh_token，而是只返回 access_token。这是因为，通常来说，
refresh_token 是一种长期的凭证，在公共客户端中返回它可能会带来安全风险。

1. 检查 code_verifier 和 code_challenge 的生成
确保客户端在授权请求和令牌请求中正确生成和使用 code_verifier 和 code_challenge。

code_verifier：一个随机字符串，长度为 43 到 128 个字符，包含字母、数字、-、.、_ 和 ~。

code_challenge：code_verifier 的 SHA-256 哈希值，并进行 Base64 URL 编码。

2. 访问浏览器
```bash
localhost:9000/oauth2/authorize?response_type=code&client_id=oidc-client&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client&scope=openid profile&state=12345&code_challenge=fsvt2qKn7CczAeQgZKTMpP84ymJdgkZEdEI7815HjUk&code_challenge_method=S256
```

3. 得到 code
4. 使用 code 换取 accessToken

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=Vf_cEwx25tGO_zfmedsnuLxssJhqumvlQ5cXXlULDpi-H_I32hi2Ttao3-DXFU-lBQgKUTeqiKTa6T80FpDztHw5_5L4mKZXjxT_GuuZkVZUiae-Gozx1DVk-nBNyacM" \
  -d "redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client" \
  -d "client_id=oidc-client" \
  -d "code_verifier=LNnxnxU6xZtT7Bnd98yacF5LKsp5T675dg7X-SWLtPQ" \
  http://127.0.0.1:9000/oauth2/token
```


