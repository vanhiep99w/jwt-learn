---
title: "API Gateway Authentication"
description: "API Gateway như biên xác thực siêu chi tiết: vì sao verify ở biên, offload khỏi service, mô hình tiêm header an toàn (strip input client TRƯỚC rồi tiêm SAU verify), JWKS cache + xoay khóa, rate limit theo subject, lỗi tin header giả mạo, cấu hình cụ thể Kong / Nginx (auth_request) / Envoy / AWS API Gateway, edge cases, anti-patterns và checklist."
---

# API Gateway Authentication

## Mục lục

- [1. Bối cảnh: cửa khóa nhưng cửa sổ mở](#1-bối-cảnh-cửa-khóa-nhưng-cửa-sổ-mở)
- [2. Tổng quan: gateway là biên tin cậy](#2-tổng-quan-gateway-là-biên-tin-cậy)
- [3. Vì sao verify ở gateway](#3-vì-sao-verify-ở-gateway)
- [4. Mô hình tiêm header an toàn](#4-mô-hình-tiêm-header-an-toàn)
  - [4.1 Strip trước, tiêm sau](#41-strip-trước-tiêm-sau)
  - [4.2 Vì sao thứ tự này sống còn](#42-vì-sao-thứ-tự-này-sống-còn)
- [5. JWKS cache & xoay khóa ở gateway](#5-jwks-cache--xoay-khóa-ở-gateway)
- [6. Rate limit & quota theo subject](#6-rate-limit--quota-theo-subject)
- [7. Gateway verify nhưng service vẫn nên verify](#7-gateway-verify-nhưng-service-vẫn-nên-verify)
- [8. Cấu hình cụ thể theo nền tảng](#8-cấu-hình-cụ-thể-theo-nền-tảng)
  - [8.1 Kong](#81-kong)
  - [8.2 Nginx (auth_request)](#82-nginx-auth_request)
  - [8.3 Envoy](#83-envoy)
  - [8.4 AWS API Gateway](#84-aws-api-gateway)
- [9. Edge cases thực tế — những lỗi khó debug](#9-edge-cases-thực-tế--những-lỗi-khó-debug)
- [10. Anti-patterns cần tránh](#10-anti-patterns-cần-tránh)
- [11. Câu hỏi thường gặp](#11-câu-hỏi-thường-gặp)
- [12. Checklist API gateway auth](#12-checklist-api-gateway-auth)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## 1. Bối cảnh: cửa khóa nhưng cửa sổ mở

Một công ty đặt API Gateway verify JWT cho toàn bộ traffic vào. Gateway verify xong sẽ **tiêm** header `X-User-Id`, `X-User-Role` để các service phía sau dùng cho tiện (khỏi parse token). Nghe rất hợp lý. Nhưng cấu hình bỏ sót một dòng: gateway **không xóa** các header `X-User-*` mà client gửi lên trước khi tiêm.

```text
Client gửi:
  GET /api/admin/users
  Authorization: Bearer <token-user-thường>
  X-User-Role: admin          ← client tự đặt!

Gateway verify token (user thường, role=user) → OK, cho qua
Gateway tiêm X-User-Role: user  ... NHƯNG header X-User-Role: admin của client VẪN CÒN
Service phía sau đọc X-User-Role → thấy "admin" (giá trị nào?) → cho quyền admin
```

Tùy thứ tự header và cách service đọc, giá trị client gửi có thể "thắng" giá trị gateway tiêm — và một user thường trở thành admin. Gateway verify token *đúng*, nhưng quên rằng **client có thể giả mạo chính những header mà gateway dùng để giao tiếp với backend**.

> [!IMPORTANT]
> API Gateway là điểm vào tập trung của hệ thống. Đặt xác thực ở đây giúp chuẩn hóa và giảm tải cho service phía sau, nhưng kéo theo một trách nhiệm sống còn: **luôn xóa (strip) các header danh tính do client gửi TRƯỚC, rồi mới tiêm header từ claim đã verify**. Quên bước strip = mở toang cửa cho giả mạo. Doc này đi sâu vào mô hình tiêm header an toàn và cấu hình cụ thể từng nền tảng.

---

## 2. Tổng quan: gateway là biên tin cậy

```diagram
                         ┌──────────────────────────────────────────┐
   Client (Bearer JWT)   │              API GATEWAY                  │
   ───────────────────▶  │  1. STRIP mọi header X-User-*, X-Auth-*   │
                         │     do client gửi (chống giả mạo)         │
                         │  2. verify JWT (alg allowlist+iss+aud+exp) │
                         │  3. TIÊM header từ claim đã verify         │
                         │     X-User-Id, X-User-Scope (an toàn)      │
                         │  4. rate limit theo sub; route             │
                         └───────────────┬──────────────────────────┘
                  thất bại → 401/403      │  (chỉ traffic đã verify đi qua)
                                          ▼
                              ┌─────────────────────┐
                              │  service nội bộ      │  (vẫn nên verify lại — zero-trust)
                              └─────────────────────┘
```

Gateway gánh bốn việc: **strip** header giả mạo, **verify** token, **tiêm** danh tính an toàn, và **điều phối** (rate limit, route). Mọi traffic chưa verify bị chặn ngay tại biên, không bao giờ chạm tới service.

---

## 3. Vì sao verify ở gateway

| Lợi ích | Giải thích |
|---------|------------|
| Chuẩn hóa | Một chỗ cấu hình verify (alg, iss, aud, JWKS) thay vì lặp ở mọi service |
| Offload | Service phía sau nhận traffic *đã lọc rác*; chặn token sai/hết hạn ở biên |
| Chặn sớm | Token hỏng bị từ chối ngay, không tiêu tốn tài nguyên service |
| Tập trung quan sát | Log/metric xác thực một chỗ; dễ phát hiện tấn công |
| Quản khóa một nơi | JWKS cache + xoay khóa cấu hình tại gateway |

```diagram
KHÔNG có gateway verify:                 CÓ gateway verify:
  rác + tấn công + token sai               gateway lọc → service chỉ thấy traffic SẠCH
  đập thẳng vào MỖI service                + service đỡ phải nhúng logic verify phức tạp
  → mỗi service tự chống, dễ lệch          → cấu hình verify nhất quán một nơi
```

> [!NOTE]
> Verify ở gateway **không** có nghĩa service phía sau khỏi verify (xem [mục 7](#7-gateway-verify-nhưng-service-vẫn-nên-verify)). Nó là *lớp đầu tiên* lọc rác và chuẩn hóa, không phải lớp *duy nhất*. Với hệ nhạy cảm, kết hợp gateway verify + service verify (zero-trust) — xem [Microservices Auth](/implementation/microservices-auth/).

---

## 4. Mô hình tiêm header an toàn

### 4.1 Strip trước, tiêm sau

```diagram
THỨ TỰ BẮT BUỘC (không được đảo):
  ┌─────────────────────────────────────────────────────────────────┐
  │ B1. STRIP: xóa MỌI header danh tính client có thể gửi            │
  │      X-User-Id, X-User-Role, X-User-Scope, X-Auth-*, X-Tenant-*  │
  │ B2. VERIFY: kiểm token (alg allowlist + iss + aud + exp + nbf)    │
  │ B3. INJECT: tiêm lại các header trên TỪ CLAIM đã verify          │
  └─────────────────────────────────────────────────────────────────┘
  → service phía sau chỉ bao giờ thấy header do GATEWAY tiêm, không bao giờ của client
```

```text
# Pseudo-config (ý tưởng chung mọi gateway)
request_in:
  remove_header: [X-User-Id, X-User-Role, X-User-Scope, X-Tenant-Id, X-Auth-*]   # STRIP trước
  jwt_verify:
    algorithms: [RS256]
    issuer: https://auth.example.com
    audience: api-gateway
    jwks_uri: https://auth.example.com/.well-known/jwks.json
  on_success:
    set_header:                                                                   # TIÊM sau
      X-User-Id:    "{{ claims.sub }}"
      X-User-Scope: "{{ claims.scope }}"
      X-Tenant-Id:  "{{ claims.tenant }}"
  on_failure: respond 401
```

### 4.2 Vì sao thứ tự này sống còn

```diagram
NẾU TIÊM TRƯỚC KHI STRIP (hoặc QUÊN strip):
  client gửi X-User-Role: admin
  gateway tiêm X-User-Role: user (từ claim)
  → tồn tại HAI header cùng tên → service đọc cái nào? (tùy framework: cái đầu/cái cuối)
  → có thể đọc trúng "admin" của client → LEO QUYỀN

NẾU STRIP TRƯỚC RỒI TIÊM:
  client gửi X-User-Role: admin → bị XÓA sạch
  gateway tiêm X-User-Role: user (từ claim đã verify) → chỉ còn 1 header đúng
  → service luôn đọc đúng giá trị từ token
```

<Callout type="error" title="Lỗi chí mạng: tiêm header mà không strip">
Nếu gateway tiêm <code>X-User-Id</code>/<code>X-User-Role</code> từ claim nhưng <b>không xóa</b> header cùng tên client gửi, kẻ tấn công chỉ việc tự đặt <code>X-User-Role: admin</code>. Tùy cách service đọc header trùng tên, giá trị giả của client có thể "thắng". Luôn <b>strip trước, verify, rồi mới tiêm</b>. Xem <a href="/security/common-vulnerabilities/">Common Vulnerabilities</a>.
</Callout>

> [!TIP]
> Dùng tiền tố thống nhất (vd `X-Auth-*`) cho mọi header gateway tiêm, và cấu hình strip theo *pattern* tiền tố đó — nhờ vậy thêm claim mới (vd `X-Auth-Tenant`) tự động được bảo vệ mà không phải nhớ liệt kê từng cái. An toàn hơn nữa: service phía sau **chỉ tin** kết nối đến từ gateway (network policy/mTLS) và lý tưởng là tự verify token (zero-trust).

---

## 5. JWKS cache & xoay khóa ở gateway

Gateway verify RS256/ES256 cần public key từ JWKS endpoint của IdP. Vì gateway xử lý *mọi* request, cache JWKS là bắt buộc, và phải refetch đúng khi IdP xoay khóa.

```diagram
Request kid=key-2025 ──▶ JWKS cache có key-2025?
                            │ có → verify ngay (0 gọi mạng)
                            │ không → refetch JWKS (có cooldown) → verify
Xoay khóa (overlap window):
   IdP công bố key-2026 cạnh key-2025 TRƯỚC khi ký bằng key-2026
   → gateway refetch thấy cả hai → token cũ & mới đều verify được suốt cửa sổ chuyển
Nếu KHÔNG overlap / cache cứng:
   IdP đổi sang key-2026 ngay → gateway còn cache key-2025 → token mới 401 HÀNG LOẠT
```

| Cấu hình | Khuyến nghị | Vì sao |
|----------|-------------|--------|
| Cache JWKS | TTL ~5–10 phút | Không gọi IdP mỗi request |
| Refetch theo `kid` lạ | Bật + có cooldown | Nhận khóa mới khi xoay, chống spam refetch |
| Cooldown refetch | ~30–60s | Tránh "bão" refetch khi nhiều token kid mới |
| Timeout gọi JWKS | Vài giây | Không treo request chờ IdP |
| Fallback khi IdP sập | Dùng cache còn hạn | Không sập verify khi IdP tạm lỗi |

> [!WARNING]
> Hai lỗi xoay khóa hay gặp: (1) cache JWKS quá cứng, không refetch theo `kid` → token ký bằng khóa mới bị 401 hàng loạt ngay khi IdP xoay; (2) IdP đổi khóa *không* có cửa sổ overlap → đứt gãy lúc chuyển. Khắc phục: gateway refetch theo `kid` lạ (có cooldown), và IdP công bố khóa mới *trước* khi bắt đầu ký bằng nó. Xem [Migration Strategy](/operations/migration-strategy/) phần xoay khóa.

---

## 6. Rate limit & quota theo subject

Gateway là nơi lý tưởng để rate limit — và sau khi verify, bạn có `sub` để giới hạn *theo người dùng* thay vì chỉ theo IP.

```diagram
RATE LIMIT THEO IP            RATE LIMIT THEO SUBJECT (sau verify)
─────────────────            ───────────────────────────────────
một NAT/proxy = nhiều user   mỗi user một hạn mức riêng (sub)
dễ chặn nhầm cả văn phòng    công bằng + chống lạm dụng theo tài khoản
attacker đổi IP né dễ        gắn với danh tính đã verify, khó né hơn
```

```text
# Pseudo: rate limit theo sub đã verify
after jwt_verify:
  key   = claims.sub                 # giới hạn theo người dùng, không phải IP
  limit = 100 requests / minute
  on_exceed: respond 429 (Retry-After: 60)

# kết hợp: limit thô theo IP cho traffic CHƯA verify (chống brute-force login)
before jwt_verify:
  key   = client_ip
  limit = 20 requests / minute       # bảo vệ endpoint /login, /token
```

> [!TIP]
> Kết hợp hai tầng: rate limit thô **theo IP** cho traffic *chưa* xác thực (bảo vệ `/login`, `/token` khỏi brute-force), và rate limit tinh **theo `sub`** cho traffic *đã* verify (công bằng theo người dùng, chống một tài khoản lạm dụng). Trả `429` kèm `Retry-After` để client lùi đúng cách. Đừng chỉ limit theo IP — nhiều user sau cùng một NAT sẽ bị chặn nhầm.

---

## 7. Gateway verify nhưng service vẫn nên verify

```diagram
CHỈ GATEWAY VERIFY (edge-only)        GATEWAY + SERVICE VERIFY (zero-trust)
─────────────────────────────        ─────────────────────────────────────
service tin header gateway tiêm        service verify lại token / kiểm aud của nó
RỦI RO: ai vào được mạng nội bộ        một service thủng không lan ngang được
  (SSRF/RCE/pod bị chiếm) →            (token aud hẹp, mỗi service tự kiểm)
  giả header → leo quyền
phù hợp: hệ nhỏ, mạng thật kín         phù hợp: hệ lớn, dữ liệu nhạy cảm
```

| Điều kiện để "tin gateway" tạm chấp nhận được | |
|---|---|
| Service **chỉ** nhận traffic qua gateway | Network policy chặn gọi tắt vào service |
| Có mTLS giữa gateway ↔ service | Chống mạo danh kết nối |
| Header tiêm có tiền tố rõ + service strip lại | Phòng thủ chiều sâu |
| Hệ không quá nhạy cảm | Đánh đổi đơn giản vs an toàn |

> [!NOTE]
> "Gateway đã verify nên service khỏi verify" chỉ an toàn nếu service **chắc chắn** chỉ nhận traffic qua gateway (network policy + mTLS). Nếu một service bị xâm nhập (SSRF/RCE) có thể gọi service khác trực tiếp, nó sẽ tự đặt header giả — đúng kịch bản lateral movement ở [Microservices Auth](/implementation/microservices-auth/) mục 1. Mặc định an toàn: gateway verify *và* mỗi service tự verify token (chữ ký + `aud` của nó).

---

## 8. Cấu hình cụ thể theo nền tảng

### 8.1 Kong

```yaml
# Kong: plugin jwt / hoặc openid-connect, kèm request-transformer để strip header client
plugins:
  - name: request-transformer            # STRIP trước: xóa header danh tính client gửi
    config:
      remove:
        headers:
          - X-User-Id
          - X-User-Role
          - X-Auth-Tenant
  - name: jwt                            # VERIFY: kiểm chữ ký + claim
    config:
      claims_to_verify:
        - exp
      key_claim_name: iss
      maximum_expiration: 1800
  - name: request-transformer            # TIÊM sau: từ claim đã verify (qua biến/serverless)
    config:
      add:
        headers:
          - "X-User-Id:$(jwt_claims.sub)"
          - "X-Auth-Tenant:$(jwt_claims.tenant)"
```

<Callout type="info">
Với Kong, dùng plugin <b>openid-connect</b> (Enterprise) để verify qua JWKS discovery của IdP tự động + xoay khóa, hoặc plugin <b>jwt</b> (community) cấu hình key thủ công. Quan trọng: đặt <code>request-transformer</code> <i>remove</i> các header danh tính <b>trước</b> bước verify, và chỉ <i>add</i> header từ claim <b>sau</b> verify.
</Callout>

### 8.2 Nginx (auth_request)

```nginx
# Nginx ủy quyền verify cho một auth service nội bộ qua auth_request
server {
  location /api/ {
    # STRIP header danh tính client gửi (chống giả mạo)
    proxy_set_header X-User-Id    "";
    proxy_set_header X-User-Role  "";

    auth_request /_verify;                         # gọi nội bộ verify token

    # TIÊM từ phản hồi của auth service (đã verify)
    auth_request_set $user_id   $upstream_http_x_user_id;
    auth_request_set $user_scope $upstream_http_x_user_scope;
    proxy_set_header X-User-Id    $user_id;
    proxy_set_header X-User-Scope $user_scope;

    proxy_pass http://backend;
  }

  location = /_verify {
    internal;
    proxy_pass http://auth-svc/verify;             # auth-svc verify JWT, trả 200 + X-User-* hoặc 401
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Authorization $http_authorization;
  }
}
```

### 8.3 Envoy

```yaml
# Envoy: jwt_authn filter verify bằng remote JWKS (tự cache + refetch)
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
      providers:
        auth0:
          issuer: https://auth.example.com
          audiences: [api-gateway]
          remote_jwks:
            http_uri:
              uri: https://auth.example.com/.well-known/jwks.json
              cluster: auth_jwks
              timeout: 5s
            cache_duration: { seconds: 600 }       # cache JWKS 10 phút
          forward_payload_header: x-jwt-payload     # tiêm payload đã verify (an toàn)
      rules:
        - match: { prefix: / }
          requires: { provider_name: auth0 }
```

> [!NOTE]
> Envoy `jwt_authn` tự quản JWKS (cache + refetch theo `cache_duration`) và chỉ tiêm payload *đã verify* qua `forward_payload_header`. Vì filter chạy trước khi route tới upstream, các header client gửi không thể giả mạo payload đã verify này — nhưng vẫn nên cấu hình strip header danh tính client nếu service đọc các header tùy chỉnh khác.

### 8.4 AWS API Gateway

```diagram
AWS API Gateway — hai kiểu authorizer:
  JWT authorizer (HTTP API)     → khai báo issuer + audience; API GW tự verify qua JWKS của IdP
  Lambda authorizer (REST/HTTP) → Lambda tự verify token, trả IAM policy + context
        context → tiêm vào request tới backend (an toàn, không từ client)
```

```javascript
// AWS Lambda authorizer (TOKEN type) — verify rồi trả context an toàn
import { createRemoteJWKSet, jwtVerify } from 'jose';
const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

export async function handler(event) {
  const token = (event.authorizationToken ?? '').replace(/^Bearer\s+/i, '');
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ['RS256'], issuer: 'https://auth.example.com', audience: 'api-gateway',
    });
    return {
      principalId: payload.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{ Action: 'execute-api:Invoke', Effect: 'Allow', Resource: event.methodArn }],
      },
      context: { userId: payload.sub, scope: payload.scope ?? '', tenant: payload.tenant },  // tiêm an toàn
    };
  } catch {
    throw new Error('Unauthorized');                  // → API GW trả 401
  }
}
```

> [!TIP]
> Với HTTP API, **JWT authorizer** dựng sẵn (khai báo `issuer`/`audience`) là cách đơn giản nhất — AWS tự verify và xoay khóa qua JWKS của IdP. Khi cần logic tùy biến (kiểm revocation, claim đặc thù), dùng **Lambda authorizer**: token đến từ `context` do Lambda trả về — *không* phải header client — nên an toàn khỏi giả mạo. Bật cache authorizer để giảm số lần verify cho cùng token.

---

## 9. Edge cases thực tế — những lỗi khó debug

### 9.1 Header trùng tên (client + gateway)

Triệu chứng: thỉnh thoảng user thường có quyền admin. Nguyên nhân: quên strip → tồn tại 2 header `X-User-Role`, service đọc trúng cái của client. Khắc phục: strip theo pattern tiền tố trước verify (mục 4).

### 9.2 Token mới 401 hàng loạt sau khi IdP xoay khóa

Nguyên nhân: cache JWKS cứng, không refetch theo `kid`. Khắc phục: bật refetch theo kid lạ + cooldown; IdP overlap khóa cũ/mới (mục 5).

### 9.3 Gateway verify `aud=api-gateway` nhưng service verify `aud=order-svc`

Nếu token chỉ có `aud=api-gateway`, service phía sau verify lại sẽ fail `aud`. Khắc phục: hoặc token có `aud` mảng gồm gateway + service, hoặc gateway dùng token-exchange phát token `aud` đúng service đích (xem [Microservices Auth](/implementation/microservices-auth/) mục 7).

### 9.4 `auth_request` của Nginx nuốt body

`auth_request` mặc định gửi cả body tới auth endpoint, gây chậm/lỗi với request lớn. Khắc phục: `proxy_pass_request_body off` + `Content-Length ""` ở location `_verify` (đã có trong mục 8.2).

### 9.5 CORS preflight bị 401

Trình duyệt gửi `OPTIONS` preflight *không* kèm `Authorization`. Nếu gateway verify cả OPTIONS → preflight 401 → request thật không bao giờ chạy. Khắc phục: cho `OPTIONS` đi qua không cần token (trả CORS headers), chỉ verify method thật.

---

## 10. Anti-patterns cần tránh

| Anti-pattern | Hậu quả | Khắc phục |
|--------------|---------|-----------|
| Tiêm header mà không strip header client | Leo quyền qua header giả | Strip trước, verify, tiêm sau |
| Verify cả OPTIONS preflight | CORS gãy, request thật 401 | Bỏ qua verify cho OPTIONS |
| Cache JWKS cứng, không refetch theo kid | Token mới 401 sau xoay khóa | Refetch theo kid + cooldown |
| Gọi JWKS mỗi request | Chậm, quá tải IdP | Cache TTL 5–10 phút |
| Chỉ rate limit theo IP | Chặn nhầm NAT / né bằng đổi IP | Limit theo sub sau verify |
| Service tin mù gateway (edge-only) | Lateral movement khi service thủng | Service verify lại (zero-trust) |
| Không đặt aud cho service phía sau | Service không verify aud được | Token aud gồm/đúng service đích |
| Lộ chi tiết lỗi verify ra client | Hỗ trợ kẻ tấn công dò | 401 chung, log nội bộ |
| Không có mTLS gateway↔service | Mạo danh kết nối nếu vào được mạng | mTLS / network policy |

---

## 11. Câu hỏi thường gặp

<Accordions>

<Accordion title="Verify ở gateway rồi, service phía sau có cần verify lại không?">
Tùy mức nhạy cảm. An toàn nhất là có (zero-trust): service verify lại token + kiểm aud của nó. Chỉ tin gateway khi service CHẮC CHẮN chỉ nhận traffic qua gateway (network policy + mTLS). Một service bị SSRF/RCE có thể giả header nếu service kia tin mù. Xem mục 7 và Microservices Auth.
</Accordion>

<Accordion title="Làm sao service biết header X-User-Id là thật, không phải client giả?">
Bằng cách gateway STRIP mọi header danh tính client gửi TRƯỚC khi verify, rồi mới tiêm từ claim. Kết hợp: service chỉ nhận traffic qua gateway (network policy), có mTLS, và lý tưởng là tự verify token thay vì chỉ tin header. Đừng bao giờ để service tin header danh tính mà không có một trong các đảm bảo trên.
</Accordion>

<Accordion title="Nên dùng JWT authorizer dựng sẵn hay Lambda authorizer trên AWS?">
JWT authorizer (HTTP API) cho trường hợp chuẩn: chỉ cần verify iss/aud/exp + JWKS, đơn giản và AWS tự xoay khóa. Lambda authorizer khi cần logic tùy biến: kiểm revocation (denylist), claim đặc thù, hoặc gọi service khác. Bật cache để không verify lại cùng token mỗi request.
</Accordion>

<Accordion title="Gateway nên trả 401 hay 403 khi token thiếu scope?">
Token hỏng/hết hạn/sai chữ ký → 401 (xác thực thất bại). Token hợp lệ nhưng thiếu scope cho route → 403. Nhiều hệ để gateway lo 401 (xác thực) còn 403 (phân quyền chi tiết) đẩy về service vì service hiểu rõ quyền theo tài nguyên hơn. Xem Backend API Auth mục 401 vs 403.
</Accordion>

</Accordions>

---

## 12. Checklist API gateway auth

```diagram
TIÊM HEADER AN TOÀN:
□ STRIP mọi header danh tính client (X-User-*, X-Auth-*, X-Tenant-*) TRƯỚC
□ VERIFY token (algorithms allowlist + iss + aud + exp + nbf)
□ TIÊM header từ claim ĐÃ verify (dùng tiền tố thống nhất, strip theo pattern)
□ Bỏ qua verify cho OPTIONS (CORS preflight)

KHÓA & HIỆU NĂNG:
□ Cache JWKS (TTL 5–10 phút) + refetch theo kid lạ (cooldown)
□ Timeout gọi JWKS; fallback cache còn hạn khi IdP lỗi
□ IdP overlap khóa cũ/mới khi xoay

RATE LIMIT & QUAN SÁT:
□ Rate limit theo IP cho traffic chưa verify (bảo vệ /login, /token)
□ Rate limit theo sub cho traffic đã verify; trả 429 + Retry-After
□ Log/metric xác thực tập trung; thông điệp lỗi chung (401), log nội bộ

PHÒNG THỦ CHIỀU SÂU:
□ Service chỉ nhận traffic qua gateway (network policy) + mTLS
□ Service vẫn tự verify token (zero-trust) cho hệ nhạy cảm
□ aud của token nhắm đúng service đích (hoặc token-exchange)
```

<Callout type="success" title="Một câu để nhớ">
<b>Strip header client → verify token → tiêm header từ claim đã verify → rate limit theo sub.</b> Gateway là biên lọc rác và chuẩn hóa, nhưng không thay thế việc mỗi service tự verify (zero-trust) cho hệ nhạy cảm — và tuyệt đối phải strip header danh tính client trước khi tiêm.
</Callout>

---

## Tài liệu tham khảo

- [Microservices Auth](/implementation/microservices-auth/) — zero-trust, verify ở mỗi service
- [Backend API Auth](/implementation/backend-api-auth/) — verify chi tiết, 401 vs 403
- [HTTP Transport & Storage](/implementation/http-transport-and-storage/) — đọc Bearer, không để token trên URL
- [Common Vulnerabilities](/security/common-vulnerabilities/) — giả mạo header, leo quyền
- [Zero-Trust API](/case-studies/zero-trust-api/) — vì sao không tin mạng nội bộ
- [Audience / Issuer / Subject](/internals/audience-issuer-subject/) — vai trò aud trong định tuyến tin cậy
- [Migration Strategy](/operations/migration-strategy/) — xoay khóa JWKS không gián đoạn
- [Observability & Audit](/operations/observability-and-audit/) — log/metric xác thực tập trung
- [Token Validation Deep Dive](/internals/token-validation-deep-dive/) — pipeline verify
