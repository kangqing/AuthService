# 1.0 最简单方案，仅yml配置即可

## 一、授权码模式演示流程
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

## 二、客户端模式：Client Credentials Grant
适用于：无需用户接入，直接用 key 和 secret 换取 accessToken
如果 access_token 失效，客户端需要重新获取一个新的 access_token，因为在此模式下是基于客户端(服务器作为客户端)与授权服务器之间的机器到机器
（无用户交互）的授权， 因此 refresh_token 并不会提供；

```bash
curl -X POST http://127.0.0.1:9000/oauth2/token \
  -u "oidc-client:123456" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read"
```

## 三、客户端直接请求 AccessToken 模式 (不安全) 安全性较低，因为 access_token 通过 URL 返回
适用于：公共客户端（前端应用、SPA）
Implicit Grant 是 OAuth 2.0 授权流程中的一种授权模式，通常用于 Web 应用 和 SPA（单页应用）。与其他授权方式（如授权码授权）相比，
Implicit Grant 主要用于 客户端直接从授权服务器获取 Access Token，而不需要在服务器端进行中转。


## 四、密码模式
密码模式 适用于受信任的客户端（如桌面应用、移动端应用等），它可以直接通过用户名和密码获取 access_token，并支持刷新令牌，适合长期访问和频繁刷新令牌的场景。




