---
title: "API Gateway Authentication"
description: "Xác thực JWT tập trung ở API Gateway: vì sao verify ở biên, mẫu offload verify + tiêm header danh tính, đính kèm cấu hình thực tế (Kong, Nginx, Envoy, AWS API Gateway), kết hợp gateway + zero-trust phía sau, rate limit theo subject, xử lý JWKS & xoay khóa, và checklist."
---

# API Gateway Authentication

## Mục lục

- [Tổng quan](#tổng-quan)
- [1. Vì sao verify token ở gateway](#1-vì-sao-verify-token-ở-gateway)
- [2. Mẫu offload: gateway verify, service tin có kiểm soát](#2-mẫu-offload-gateway-verify-service-tin-có-kiểm-soát)
- [3. Tiêm header danh tính an toàn](#3-tiêm-header-danh-tính-an-toàn)
- [4. Cấu hình theo gateway](#4-cấu-hình-theo-gateway)
  - [4.1 Kong](#41-kong)
  - [4.2 Nginx (njs/lua)](#42-nginx-njslua)
  - [4.3 Envoy](#43-envoy)
  - [4.4 AWS API Gateway (JWT authorizer)](#44-aws-api-gateway-jwt-authorizer)
- [5. JWKS & xoay khóa ở gateway](#5-jwks--xoay-khóa-ở-gateway)
- [6. Rate limit & quota theo subject](#6-rate-limit--quota-theo-subject)
- [7. Bẫy thường gặp ở gateway](#7-bẫy-thường-gặp-ở-gateway)
- [8. Checklist API gateway auth](#8-checklist-api-gateway-auth)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan

API Gateway là cánh cửa vào hệ thống — nơi lý tưởng để verify JWT **một lần** thay vì lặp ở mọi service, đồng thời gắn rate limit, CORS, logging tập trung. Nhưng làm sai sẽ tạo ra điểm tin tưởng mù: service phía sau "tin gateway" và mở cửa cho ai vượt qua được gateway hoặc gọi thẳng vào trong. Doc này chỉ cách offload verify ở gateway **mà vẫn** giữ phòng thủ chiều sâu.

```diagram
            ┌──────────────── API GATEWAY ────────────────┐
Client ─▶   │ verify JWT (alg allowlist, iss, aud, exp)    │ ─▶ service
            │ → từ chối 401 nếu sai                         │
            │ → tiêm X-User-* (đã verify) cho service phía sau│
            │ rate limit / CORS / log tập trung             │
            └───────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Gateway verify ở biên giúp giảm lặp và chặn sớm token rác. Nhưng **đừng biến gateway thành điểm tin tưởng duy nhất**: service nội bộ phải hoặc (a) verify lại JWT (zero-trust), hoặc (b) chỉ nhận traffic *đã qua gateway* (network policy + tiêm header có ký/đáng tin). Mục 2–3 trình bày cách làm an toàn.

---

## 1. Vì sao verify token ở gateway

| Lợi ích | Giải thích |
|---------|-----------|
| Chặn sớm | Token sai/hết hạn bị từ chối ngay ở biên, không tốn tài nguyên service |
| Tập trung cấu hình | Một chỗ quản allowlist alg, iss, aud, JWKS — không rải rác |
| Đính kèm xuyên suốt | Gateway lo CORS, rate limit, request log một lần |
| Đơn giản hóa service | Service phía sau bớt phần lặp đọc/verify token |

```diagram
KHÔNG có gateway verify:            CÓ gateway verify:
mỗi service tự verify token         token rác bị chặn ở biên
token rác đi sâu vào trong          service nhận request đã sạch
cấu hình verify rải rác             cấu hình tập trung 1 nơi
```

> [!NOTE]
> Verify ở gateway **không loại trừ** verify ở service. Trong hệ nhạy cảm, hai tầng cùng tồn tại: gateway chặn phần lớn rác + lo cross-cutting concerns; service vẫn verify (hoặc kiểm header đáng tin) để chống lateral movement. Xem [Microservices Auth](/implementation/microservices-auth/) phần zero-trust.

---

## 2. Mẫu offload: gateway verify, service tin có kiểm soát

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant S as Service
    C->>G: Authorization: Bearer <jwt>
    G->>G: verify (alg allowlist, iss, aud, exp) qua JWKS cache
    alt token hợp lệ
        G->>G: strip Authorization gốc; tiêm X-User-Id/X-User-Scope (đã verify)
        G->>S: forward (header danh tính đáng tin)
        S-->>G: 200
    else token sai
        G-->>C: 401 (service không bị gọi)
    end
```

> [!TIP]
> Có hai biến thể của mẫu offload: (1) **gateway chuyển tiếp nguyên JWT** và service tự verify lại — an toàn nhất (zero-trust); (2) **gateway tiêm header danh tính** đã verify và service tin header đó — nhanh hơn nhưng phải đảm bảo service *chỉ* nhận traffic từ gateway và gateway *xóa* mọi header danh tính do client gửi vào (mục 3). Chọn theo mức nhạy cảm.

---

## 3. Tiêm header danh tính an toàn

Khi gateway tiêm `X-User-Id` cho service phía sau, có một lỗ hổng kinh điển: client tự gửi `X-User-Id: admin` và nếu gateway không xóa, service tin nhầm.

```diagram
NGUY HIỂM:  client gửi  X-User-Id: admin  ──▶ gateway QUÊN strip ──▶ service tin "admin"
AN TOÀN:    gateway STRIP mọi X-User-* từ client TRƯỚC ──▶ verify JWT ──▶ tiêm X-User-* MỚI
```

```diagram
QUY TẮC TIÊM HEADER:
1) STRIP mọi header danh tính (X-User-*, X-Auth-*) đến từ client — luôn luôn
2) verify JWT
3) tiêm header danh tính MỚI từ claim ĐÃ verify
4) khóa mạng: service CHỈ nhận traffic từ gateway (network policy / mTLS)
```

<Callout type="error" title="Lỗ hổng header spoofing">
Nếu gateway tiêm <code>X-User-Id</code> nhưng <b>không xóa</b> header cùng tên do client gửi, kẻ tấn công đặt <code>X-User-Id: admin</code> và (tùy thứ tự) có thể mạo danh. Luôn <b>strip trước, tiêm sau</b>. Và service không bao giờ được phép gọi trực tiếp bỏ qua gateway — dùng network policy hoặc mTLS để ép mọi traffic đi qua gateway.
</Callout>

---

## 4. Cấu hình theo gateway

### 4.1 Kong

```yaml
# Kong: plugin jwt — verify chữ ký + claim, từ chối token sai ở biên
plugins:
  - name: jwt
    config:
      claims_to_verify: ["exp"]          # bắt buộc kiểm hết hạn
      key_claim_name: iss                 # map issuer → credential/khóa
      maximum_expiration: 3600            # chặn token TTL quá dài
      run_on_preflight: false
```

> [!NOTE]
> Kong `jwt` plugin verify chữ ký theo credential gắn với `iss`. Cấu hình `claims_to_verify` để ép kiểm `exp`. Với allowlist thuật toán + `aud`, nhiều team dùng plugin `jwt` cộng thêm logic hoặc chuyển sang OIDC plugin cho luồng đầy đủ. Luôn đảm bảo thuật toán cố định, không để token tự khai `alg`.

### 4.2 Nginx (njs/lua)

```nginx
# Nginx với module auth_jwt (NGINX Plus) — verify trước khi proxy
location /api/ {
    auth_jwt "api";
    auth_jwt_key_request /_jwks;            # nạp JWKS để lấy khóa công khai
    # ép thuật toán & claim qua biến/map; từ chối nếu thiếu
    proxy_set_header Authorization "";       # STRIP token gốc nếu tiêm header
    proxy_set_header X-User-Id $jwt_claim_sub;   # tiêm claim ĐÃ verify
    proxy_pass http://api_upstream;
}

location = /_jwks {
    internal;
    proxy_pass https://auth.example.com/.well-known/jwks.json;
}
```

### 4.3 Envoy

```yaml
# Envoy: jwt_authn filter — verify + tiêm payload, remote JWKS có cache
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
      providers:
        main:
          issuer: https://auth.example.com
          audiences: ["api.orders"]
          remote_jwks:
            http_uri:
              uri: https://auth.example.com/.well-known/jwks.json
              cluster: auth_cluster
              timeout: 5s
            cache_duration: { seconds: 600 }   # cache JWKS
          forward_payload_header: x-jwt-payload  # tiêm payload đã verify cho service
      rules:
        - match: { prefix: /api }
          requires: { provider_name: main }
```

> [!TIP]
> Envoy `jwt_authn` là lựa chọn mạnh cho service mesh: nó verify `iss`/`aud`, cache JWKS, và `forward_payload_header` tiêm payload đã verify cho service phía sau. Kết hợp với mTLS của mesh, bạn có cả xác thực user (JWT) lẫn xác thực service (cert) ở tầng hạ tầng.

### 4.4 AWS API Gateway (JWT authorizer)

```yaml
# AWS API Gateway v2 (HTTP API) — JWT authorizer tích hợp sẵn với Cognito/OIDC
Authorizer:
  Type: JWT
  IdentitySource: $request.header.Authorization
  JwtConfiguration:
    Issuer: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxx
    Audience:
      - my-app-client-id
```

> [!NOTE]
> AWS HTTP API JWT authorizer verify `iss`/`aud`/`exp` và lấy JWKS tự động từ OIDC discovery. Claim sau verify có trong `$context.authorizer.jwt.claims` để dùng ở mapping/route. Phù hợp khi IdP là Cognito hoặc OIDC provider chuẩn; ít linh hoạt hơn gateway tự quản lý cho luồng phức tạp.

---

## 5. JWKS & xoay khóa ở gateway

Gateway là nơi tập trung nạp khóa công khai — phải cache nhưng cũng phải kịp nhận khóa mới khi IdP xoay khóa.

```diagram
Token kid=key-2025 đến  ─▶  cache có key-2025?
                              │ có → verify ngay
                              │ không → refetch JWKS (có cooldown) → cache → verify
IdP xoay khóa (thêm key-2026 cạnh key-2025):
   cửa sổ overlap: gateway chấp nhận cả hai cho tới khi token cũ hết hạn hết
```

| Vấn đề | Triệu chứng | Khắc phục |
|--------|-------------|-----------|
| Cache JWKS quá lâu, không refetch | Token mới (kid mới) 401 hàng loạt sau khi IdP xoay khóa | Refetch theo kid lạ + cache có TTL |
| Refetch mỗi request | Quá tải IdP, chậm | Cache + cooldown giữa các lần refetch |
| Không overlap khi xoay | Đứt gãy lúc chuyển khóa | IdP giữ cả khóa cũ+mới trong JWKS một thời gian |

> [!WARNING]
> Một sự cố kinh điển: IdP xoay sang `kid` mới, nhưng gateway cache JWKS cứng và không refetch → **mọi token mới 401** cho tới khi cache hết hạn. Luôn dùng client JWKS có khả năng refetch khi gặp `kid` lạ (với cooldown chống spam), và đảm bảo IdP công bố khóa mới *trước* khi bắt đầu ký bằng nó. Xem [Debugging JWT](/operations/debugging-jwt/) ca "401 chập chờn do kid lệch".

---

## 6. Rate limit & quota theo subject

Gateway đã verify token nên biết `sub` — tận dụng để rate limit theo người dùng/khách hàng thay vì chỉ theo IP.

```diagram
Rate limit theo IP    → thô, nhiều user sau NAT chung 1 IP bị ảnh hưởng
Rate limit theo sub   → đúng người dùng (claim đã verify) → công bằng + chống abuse
Quota theo tenant     → giới hạn theo khách hàng (claim tenant đã verify)
```

```yaml
# Ví dụ ý tưởng: key rate-limit theo claim sub đã verify
rate_limit:
  key: jwt.claim.sub        # mỗi subject một bucket
  limit: 100
  window: 1m
```

> [!TIP]
> Vì gateway đã verify, `sub`/`tenant` là dữ liệu đáng tin để làm khóa rate limit — chính xác và công bằng hơn rate limit theo IP (nhiều người dùng có thể chung IP qua NAT/proxy). Đừng dùng claim *chưa* verify làm khóa; phải đặt rate limit *sau* bước verify.

---

## 7. Bẫy thường gặp ở gateway

| Bẫy | Hậu quả | Khắc phục |
|-----|---------|-----------|
| Không strip header `X-User-*` từ client | Header spoofing → mạo danh | Strip trước, tiêm sau |
| Service gọi được trực tiếp, bỏ qua gateway | Bỏ qua mọi verify | Network policy / mTLS ép qua gateway |
| Tin gateway hoàn toàn, service không verify | 1 lỗ hổng = toàn hệ thống | Zero-trust ở service nhạy cảm |
| JWKS cache không refetch | 401 hàng loạt khi xoay khóa | Refetch theo kid + cooldown |
| Không ép allowlist `alg` | alg:none / confusion lọt qua | Cố định thuật toán ở gateway |
| Quên kiểm `aud` | Token service khác lọt | Cấu hình audience |

---

## 8. Checklist API gateway auth

```diagram
VERIFY Ở GATEWAY:
□ Allowlist alg cố định (không tin header.alg)
□ Kiểm iss + aud + exp; clockTolerance hợp lý
□ JWKS cache + refetch theo kid (cooldown)
□ Từ chối 401 sớm cho token sai

TIÊM HEADER / TIN TƯỞNG:
□ STRIP mọi X-User-*/X-Auth-* từ client TRƯỚC khi tiêm
□ Tiêm header danh tính từ claim ĐÃ verify
□ Service chỉ nhận traffic qua gateway (network policy/mTLS)
□ Service nhạy cảm vẫn verify lại (zero-trust)

CROSS-CUTTING:
□ Rate limit/quota theo sub/tenant (sau verify)
□ CORS + request log tập trung
□ Không lộ chi tiết lỗi verify ra client

XOAY KHÓA:
□ IdP công bố khóa mới trước khi ký bằng nó
□ Cửa sổ overlap chấp nhận cả khóa cũ+mới
```

<Callout type="success" title="Một câu để nhớ">
<b>Gateway verify ở biên (allowlist alg + iss/aud/exp + JWKS cache), strip header client trước khi tiêm danh tính đã verify, và service nhạy cảm vẫn verify lại.</b> Gateway là lớp một — không phải lớp duy nhất.
</Callout>

---

## Tài liệu tham khảo

- [Backend API Auth](/implementation/backend-api-auth/) — verify chi tiết ở từng service
- [Microservices Auth](/implementation/microservices-auth/) — zero-trust, tin tưởng nội bộ
- [HTTP Transport & Storage](/implementation/http-transport-and-storage/) — Bearer, CORS
- [Algorithm Confusion](/security/algorithm-confusion-deep-dive/) — vì sao ép allowlist alg
- [Token Validation Deep Dive](/internals/token-validation-deep-dive/) — pipeline verify
- [Debugging JWT](/operations/debugging-jwt/) — ca 401 do JWKS/kid
- [Zero-Trust API](/case-studies/zero-trust-api/) — không tin mạng nội bộ
- [Production Checklist](/operations/production-checklist/) — verify ở biên là P0
