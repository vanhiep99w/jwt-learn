---
title: "Luồng xác thực JWT — Deep Dive"
description: "Mổ xẻ chi tiết từng bước server validate JWT: từ tách chuỗi, decode header, chọn key, verify signature, kiểm tra exp/nbf/iss/aud, đến quyết định accept hay reject. Kèm diagram từng bước, code minh họa, edge case thực tế, và checklist production."
---

## Mục lục

- [Bối cảnh: Token hợp lệ trên jwt.io nhưng server trả 401](#1-bối-cảnh-token-hợp-lệ-trên-jwtio-nhưng-server-trả-401)
- [Tổng quan: 7 bước validate — pipeline từ đầu đến cuối](#2-tổng-quan-7-bước-validate--pipeline-từ-đầu-đến-cuối)
- [Bước 1: Tách chuỗi — Split bằng dấu chấm](#3-bước-1-tách-chuỗi--split-bằng-dấu-chấm)
- [Bước 2: Decode Header — Đọc metadata](#4-bước-2-decode-header--đọc-metadata)
- [Bước 3: Chọn key — kid, JWKS, và bài toán "dùng key nào"](#5-bước-3-chọn-key--kid-jwks-và-bài-toán-dùng-key-nào)
- [Bước 4: Verify Signature — Bước quan trọng nhất](#6-bước-4-verify-signature--bước-quan-trọng-nhất)
- [Bước 5: Decode Payload — Đọc claims](#7-bước-5-decode-payload--đọc-claims)
- [Bước 6: Validate Claims — Kiểm tra logic nghiệp vụ](#8-bước-6-validate-claims--kiểm-tra-logic-nghiệp-vụ)
- [Bước 7: Kiểm tra bổ sung — Revocation, rate limit, context](#9-bước-7-kiểm-tra-bổ-sung--revocation-rate-limit-context)
- [Pipeline hoàn chỉnh — Flowchart quyết định](#10-pipeline-hoàn-chỉnh--flowchart-quyết-định)
- [Edge cases thực tế — Những lỗi khó debug](#11-edge-cases-thực-tế--những-lỗi-khó-debug)
- [So sánh: Validate ở API Gateway vs ở từng service](#12-so-sánh-validate-ở-api-gateway-vs-ở-từng-service)
- [Code minh họa: Validate từ đầu đến cuối](#13-code-minh-họa-validate-từ-đầu-đến-cuối)
- [Anti-patterns cần tránh](#14-anti-patterns-cần-tránh)
- [Tóm tắt — Cheat sheet & 3 nguyên tắc](#15-tóm-tắt--cheat-sheet--3-nguyên-tắc)

---

## 1. Bối cảnh: Token hợp lệ trên jwt.io nhưng server trả 401

Bạn vừa build xong tính năng login. Frontend nhận token từ auth server, paste lên jwt.io — mọi thứ "đẹp": header đúng, payload có đủ claims, signature verified. Nhưng gọi API:

```text
GET /api/orders
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0LVEzIn0...

HTTP/1.1 401 Unauthorized
{"error": "invalid_token", "message": "Token validation failed"}
```

Bạn bối rối: *"jwt.io bảo hợp lệ, sao server reject?"*

Lý do: jwt.io chỉ verify **signature**. Server phải kiểm tra **nhiều thứ hơn** — `exp` hết hạn chưa, `iss` có đúng auth server không, `aud` có dành cho service này không, token đã bị revoke chưa. Signature đúng ≠ token hợp lệ.

> [!IMPORTANT]
> Validate JWT **không phải chỉ verify signature**. Đó chỉ là 1 trong 7 bước. Token có signature hợp lệ vẫn bị reject vì: (1) hết hạn, (2) sai audience, (3) sai issuer, (4) đã bị revoke, (5) chưa tới thời điểm hiệu lực (`nbf`), (6) sai thuật toán. Mỗi bước bỏ qua = một lỗ hổng bảo mật.

Trong doc này, ta sẽ đi qua **từng bước** server validate JWT, từ lúc nhận chuỗi token đến lúc quyết định 200 hay 401. Mỗi bước giải thích: **tại sao** cần, **làm gì** cụ thể, và **lỗi gì xảy ra** nếu bỏ qua.

---

## 2. Tổng quan: 7 bước validate — pipeline từ đầu đến cuối

```diagram
╭─────────────────────────────────────────────────────────────────────────╮
│              JWT VALIDATION PIPELINE — 7 BƯỚC                           │
│                                                                         │
│  Token string từ client                                                 │
│       │                                                                 │
│       ▼                                                                 │
│  ┌─ Bước 1: TÁCH CHUỖI ────────────────────────────────────────────┐    │
│  │  Split bằng "." → phải ra đúng 3 phần                           │    │
│  │  Nếu không → 401 ngay (không phải JWT hợp lệ)                   │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│  ┌─ Bước 2: DECODE HEADER ──────────────────────────────────────────┐   │
│  │  Base64URL decode phần 1 → JSON                                  │   │
│  │  Đọc alg, kid, typ                                               │   │
│  │  Kiểm tra alg có nằm trong whitelist không                       │   │
│  └───────────────────────────────────────────────┬──────────────────┘   │
│                                                  ▼                      │
│  ┌─ Bước 3: CHỌN KEY ──────────────────────────────────────────────┐    │
│  │  Dựa vào alg + kid → tìm đúng key để verify                     │    │
│  │  HS256: lấy shared secret                                       │    │
│  │  RS256: lấy public key (từ config hoặc JWKS endpoint)           │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│  ┌─ Bước 4: VERIFY SIGNATURE ──────────────────────────────────────┐    │
│  │  Tính lại signature từ header + payload + key                   │    │
│  │  So với signature trong token                                   │    │
│  │  Không khớp → 401 (token bị giả mạo hoặc sai key)               │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│  ┌─ Bước 5: DECODE PAYLOAD ────────────────────────────────────────┐    │
│  │  Base64URL decode phần 2 → JSON claims                          │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│  ┌─ Bước 6: VALIDATE CLAIMS ───────────────────────────────────────┐    │
│  │  exp: hết hạn chưa?                                             │    │
│  │  nbf: đã tới thời điểm hiệu lực chưa?                           │    │
│  │  iss: đúng issuer?                                              │    │
│  │  aud: đúng audience?                                            │    │
│  │  Bất kỳ claim nào fail → 401                                    │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│  ┌─ Bước 7: KIỂM TRA BỔ SUNG ──────────────────────────────────────┐    │
│  │  Token đã bị revoke chưa? (blacklist check)                     │    │
│  │  IP/device context có khớp không?                               │    │
│  │  Rate limit per-token                                           │    │
│  └───────────────────────────────────────────────┬─────────────────┘    │
│                                                  ▼                      │
│                                           ✅ TOKEN HỢP LỆ               │
│                                           Tiếp tục xử lý request        │
╰─────────────────────────────────────────────────────────────────────────╯
```

Mỗi bước là một "cửa ải". Token phải qua **tất cả** — fail ở bất kỳ bước nào → reject ngay, không chạy các bước sau.

---

## 3. Bước 1: Tách chuỗi — Split bằng dấu chấm

### 3.1. Server nhận gì

Token thường đến qua HTTP header:

```text
Authorization: Bearer eyJhbGci...payload...signature
```

Server phải:

1. **Tách prefix** `Bearer ` (có dấu cách sau `Bearer`).
2. **Split** chuỗi còn lại bằng ký tự `.`.
3. **Kiểm tra** kết quả có đúng **3 phần** không.

```diagram
Input: "Bearer eyJhbGci.eyJzdWIi.SflKxw"

Bước 1a: Bỏ "Bearer " → "eyJhbGci.eyJzdWIi.SflKxw"

Bước 1b: Split bằng "."
   parts[0] = "eyJhbGci"   ← header  (Base64URL)
   parts[1] = "eyJzdWIi"   ← payload (Base64URL)
   parts[2] = "SflKxw"     ← signature (Base64URL)

Bước 1c: parts.length == 3?
   ✅ Có → tiếp tục
   ❌ Không → REJECT (không phải JWT compact)
```

### 3.2. Tại sao phải kiểm tra đúng 3 phần

| Số phần | Nghĩa là | Hành động |
|---------|----------|-----------|
| < 3 | Chuỗi không phải JWT, hoặc bị cắt (truncated) | Reject |
| = 3 | JWT compact (JWS) — bình thường | Tiếp tục |
| = 5 | JWE (encrypted JWT) — cấu trúc khác | Cần JWE handler riêng |
| > 5 | Không hợp lệ | Reject |

### 3.3. Lỗi thực tế ở bước này

- **Token bị cắt**: proxy/load balancer cắt header quá dài (>8KB) → token thiếu phần signature.
- **Thiếu `Bearer `**: client gửi token mà quên prefix → server parse sai.
- **Dấu cách thừa**: `Bearer  eyJ...` (2 dấu cách) → split ra phần đầu rỗng.

> [!TIP]
> Nên dùng thư viện JWT chuẩn thay vì tự split. Thư viện xử lý các edge case: whitespace, casing (`bearer` vs `Bearer`), encoding quirks.

---

## 4. Bước 2: Decode Header — Đọc metadata

### 4.1. Decode Base64URL

Phần 1 (header) được Base64URL decode thành JSON:

```diagram
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0In0"
                                │
                         Base64URL decode
                                │
                                ▼
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024"
}
```

### 4.2. Kiểm tra thuật toán — Bước bảo mật QUAN TRỌNG NHẤT

Đây là nơi hầu hết lỗ hổng JWT xảy ra. Server **phải** kiểm tra `alg` có nằm trong **whitelist** (danh sách cho phép) không.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  KIỂM TRA ALG — ĐÚNG CÁCH                                           │
│                                                                     │
│  Server config (CỨNG, không phụ thuộc token):                       │
│     allowed_algorithms = ["RS256"]                                  │
│                                                                     │
│  Token gửi lên:                                                     │
│     header.alg = ?                                                  │
│                                                                     │
│     "RS256"  → ✅ nằm trong whitelist → tiếp tục                    │
│     "HS256"  → ❌ KHÔNG cho phép → REJECT                           │
│     "none"   → ❌ KHÔNG cho phép → REJECT                           │
│     "RS512"  → ❌ KHÔNG cho phép → REJECT                           │
│                                                                     │
│  SAI CÁCH (tạo lỗ hổng):                                            │
│     Đọc alg từ header → dùng luôn alg đó để verify                  │
│     → Kẻ tấn công đổi alg → bypass signature!                       │
╰─────────────────────────────────────────────────────────────────────╯
```

Tại sao phải whitelist? Xem chi tiết cuộc tấn công tại [Algorithm Confusion](/docs/security/algorithm-confusion/).

### 4.3. Kiểm tra `typ`

`typ` thường là `"JWT"`. Một số hệ thống dùng `typ` để phân biệt loại token:

| `typ` | Ý nghĩa |
|-------|---------|
| `"JWT"` | JWT thông thường |
| `"at+jwt"` | Access Token (RFC 9068) |
| `"dpop+jwt"` | DPoP proof token |

Nếu server mong đợi access token, nên kiểm tra `typ == "at+jwt"` để tránh nhầm lẫn với ID token hay refresh token.

---

## 5. Bước 3: Chọn key — kid, JWKS, và bài toán "dùng key nào"

### 5.1. HS256 — Đơn giản: 1 secret

Nếu `alg = HS256`, server có **đúng 1 shared secret** (hoặc vài secret nếu rotate):

```diagram
alg = "HS256"
      │
      ▼
Server lấy secret từ config/env:
   JWT_SECRET = "my-256-bit-secret-key-dont-share"
      │
      ▼
Dùng secret này cho bước verify signature
```

### 5.2. RS256 / ES256 — Cần tìm đúng public key

Khi dùng thuật toán asymmetric, server cần **public key** tương ứng. Vấn đề: auth server có thể có nhiều key (key rotation), phải tìm đúng key.

Luồng tìm key qua **JWKS** (JSON Web Key Set):

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  1. Đọc header → kid = "key-2024-Q3"                                │
│                                                                     │
│  2. Server gọi JWKS endpoint (hoặc đọc từ cache):                   │
│     GET https://auth.example.com/.well-known/jwks.json              │
│                                                                     │
│  3. Response:                                                       │
│     {                                                               │
│       "keys": [                                                     │
│         {                                                           │
│           "kid": "key-2024-Q2",     ← key cũ, không khớp            │
│           "kty": "RSA",                                             │
│           "alg": "RS256",                                           │
│           "n": "0vx7agoebG...",                                     │
│           "e": "AQAB",                                              │
│           "use": "sig"                                              │
│         },                                                          │
│         {                                                           │
│           "kid": "key-2024-Q3",     ← ✅ KHỚP! Dùng key này         │
│           "kty": "RSA",                                             │
│           "alg": "RS256",                                           │
│           "n": "sXch3pQN5...",                                      │
│           "e": "AQAB",                                              │
│           "use": "sig"                                              │
│         }                                                           │
│       ]                                                             │
│     }                                                               │
│                                                                     │
│  4. Lấy key có kid = "key-2024-Q3" → chuyển thành RSA public key    │
╰─────────────────────────────────────────────────────────────────────╯
```

### 5.3. JWKS caching — Tại sao cần cache

Gọi JWKS endpoint cho **mỗi request** = bottleneck + single point of failure. Best practice:

```diagram
Request đến, cần verify JWT
      │
      ▼
kid có trong LOCAL CACHE không?
   ├── CÓ → dùng key từ cache                    ← fast path (~0ms)
   │
   └── KHÔNG → gọi JWKS endpoint
              │
              ▼
         kid có trong response?
           ├── CÓ → cache key + dùng key
           │        (cache TTL: 1-24 giờ)
           │
           └── KHÔNG → 401
                       (kid lạ, không biết key nào)
```

> [!IMPORTANT]
> Caching JWKS là **bắt buộc** trong production. Không cache = mỗi request gọi HTTP tới auth server = latency tăng + auth server quá tải + nếu auth server down thì toàn bộ hệ thống chết. Cache tối thiểu 5 phút, thường 1-24 giờ. Khi cache miss (kid không tìm thấy), fetch lại JWKS một lần — nếu vẫn không có kid, reject.

### 5.4. Khi không có `kid` trong header

Nếu token không có `kid` (header chỉ có `alg`), server phải dùng logic khác:

| Tình huống | Cách xử lý |
|-----------|-----------|
| Server chỉ có 1 key | Dùng key duy nhất đó |
| Server có nhiều key | Thử từng key — key nào verify thành công thì dùng (chậm, tốn CPU) |
| JWKS có nhiều key, không có kid | Lọc theo `alg` + `use`, thử từng key khớp |

> [!TIP]
> Luôn yêu cầu issuer đặt `kid` trong header. Không có `kid` = server phải brute-force thử key, vừa chậm vừa dễ sai.

---

## 6. Bước 4: Verify Signature — Bước quan trọng nhất

### 6.1. Verify HS256

HMAC-SHA256 là thuật toán **symmetric**: cùng 1 key để ký và verify.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Inputs:                                                            │
│     signing_input = header_b64 + "." + payload_b64                  │
│                   = "eyJhbGci...InR5cCI6IkpXVCJ9.eyJzdWIi...fQ"     │
│     key           = server's JWT_SECRET                             │
│     received_sig  = phần 3 của token (Base64URL decode → bytes)     │
│                                                                     │
│  Verify:                                                            │
│     expected_sig = HMAC-SHA256(key, signing_input)                  │
│                                                                     │
│     constant_time_compare(expected_sig, received_sig)               │
│        ├── BẰNG NHAU  → ✅ signature hợp lệ                         │
│        └── KHÁC NHAU  → ❌ REJECT                                   │
╰─────────────────────────────────────────────────────────────────────╯
```

### 6.2. Verify RS256

RSA-PKCS1-v1.5 + SHA-256 là thuật toán **asymmetric**: private key ký, public key verify.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Inputs:                                                            │
│     signing_input = header_b64 + "." + payload_b64                  │
│     public_key    = RSA public key (từ JWKS hoặc config)            │
│     received_sig  = phần 3 của token (Base64URL decode → bytes)     │
│                                                                     │
│  Verify:                                                            │
│     hash = SHA-256(signing_input)                                   │
│                                                                     │
│     RSA_VERIFY(public_key, hash, received_sig)                      │
│        ├── VALID   → ✅ signature hợp lệ                            │
│        └── INVALID → ❌ REJECT                                      │
│                                                                     │
│  Bên trong RSA_VERIFY:                                              │
│     1. "Giải mã" signature bằng public key → ra hash'               │
│     2. So sánh hash' với hash tính từ signing_input                 │
│     3. Khớp = token đúng là do người giữ private key ký             │
╰─────────────────────────────────────────────────────────────────────╯
```

### 6.3. Constant-time comparison — Chi tiết bảo mật bị bỏ qua

Khi so sánh `expected_sig` với `received_sig`, **phải dùng constant-time comparison** (so sánh mất cùng thời gian bất kể giống hay khác bao nhiêu byte).

Tại sao? Nếu dùng so sánh thông thường (`==`), nó dừng ngay khi gặp byte khác:

```diagram
So sánh thông thường (KHÔNG AN TOÀN):
   expected: a1 b2 c3 d4 e5 f6
   received: a1 b2 c3 XX ...
                       ↑ byte thứ 4 khác → dừng ngay, trả false

   Kẻ tấn công đo thời gian response:
   - Sai byte 1: response 0.5ms
   - Sai byte 2: response 0.6ms
   - Sai byte 3: response 0.7ms
   → Đoán từng byte signature! (timing attack)

Constant-time comparison (AN TOÀN):
   Luôn so sánh TẤT CẢ bytes, dù byte đầu đã sai
   → Thời gian luôn giống nhau → không leak thông tin
```

> [!IMPORTANT]
> Timing attack nghe có vẻ lý thuyết, nhưng đã được chứng minh khai thác thành công trên thực tế — đặc biệt trong mạng nội bộ (low latency, ít jitter). Mọi thư viện JWT nghiêm túc đều dùng constant-time comparison. Nếu bạn tự implement verify, **bắt buộc** phải dùng `hmac.compare_digest()` (Python), `crypto.timingSafeEqual()` (Node.js), `MessageDigest.isEqual()` (Java).

### 6.4. Verify `alg: none` — Nếu header nói "không cần ký"

Nếu server **không kiểm tra alg** mà chỉ đọc từ header:

```diagram
Token giả mạo:
   Header: {"alg":"none","typ":"JWT"}
   Payload: {"sub":"admin","role":"superadmin"}
   Signature: (rỗng)

   Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.

Server code tệ:
   alg = header.alg    // "none"
   if alg == "none":
       skip signature check   // ← LOL bỏ qua verify
   payload = decode(parts[1])
   user = payload.sub   // "admin" — kẻ tấn công giờ là admin!
```

Giải pháp: **LUÔN reject `alg: none`** trừ khi bạn có lý do cực kỳ đặc biệt (và thường là không).

---

## 7. Bước 5: Decode Payload — Đọc claims

### 7.1. Base64URL decode phần 2

Sau khi signature verified, decode payload:

```diagram
"eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzE5MzA2MDAwfQ"
                                │
                         Base64URL decode
                                │
                                ▼
{
  "sub": "user-42",
  "role": "admin",
  "exp": 1719306000,
  "iat": 1719302400,
  "iss": "https://auth.myapp.com",
  "aud": "https://api.myapp.com"
}
```

### 7.2. Tại sao decode payload SAU verify signature

Thứ tự rất quan trọng: **verify signature trước, rồi mới tin payload**.

```diagram
THỨ TỰ ĐÚNG:
   1. Verify signature → OK, data chưa bị sửa
   2. Decode payload → tin được nội dung
   3. Validate claims → logic nghiệp vụ

THỨ TỰ SAI (tạo lỗ hổng):
   1. Decode payload → đọc claims
   2. Dùng claims để quyết định nghiệp vụ    ← NGUY HIỂM! Chưa verify!
   3. Verify signature → (đã quá muộn)
```

Nếu bạn đọc và **dùng** payload trước khi verify, kẻ tấn công có thể sửa payload tùy ý — bạn đã hành động dựa trên dữ liệu giả mạo trước khi phát hiện.

> [!NOTE]
> Trong thực tế, một số thư viện decode header trước signature verification (để biết dùng alg/kid nào). Đây là chấp nhận được vì header chỉ dùng để chọn key, không dùng cho quyết định nghiệp vụ. Nhưng **payload** phải luôn được xử lý **sau** verify.

---

## 8. Bước 6: Validate Claims — Kiểm tra logic nghiệp vụ

Đây là bước mà jwt.io **không** làm cho bạn — và là nơi phần lớn bug 401 xảy ra.

### 8.1. Kiểm tra `exp` (Expiration Time)

```diagram
now = current_unix_timestamp()    // ví dụ: 1719305500
exp = payload.exp                 // ví dụ: 1719306000
clock_skew = 60                   // cho phép lệch 60 giây

if now > exp + clock_skew:
   → ❌ REJECT — token đã hết hạn

Timeline:
   ├──────────── iat ─────────── exp ──── exp+skew ──── now ────►
   │          (issued)        (hết hạn)  (grace)
   │                                                    │
   │  Token hợp lệ trong khoảng này  │  grace  │  HẾT HẠN  │
```

Tại sao cần **clock skew tolerance**:

| Tình huống | Vấn đề | Clock skew giúp |
|-----------|--------|----------------|
| Auth server (UTC) cấp token `exp=1000` | API server đồng hồ nhanh 5 giây → `now=1005 > 1000` → reject token mới cấp! | Cho phép lệch 60s → `1005 < 1000+60` → OK |
| Microservice A và B lệch đồng hồ | Token hợp lệ ở A nhưng bị B reject | Clock skew 30-60s giải quyết |

### 8.2. Kiểm tra `nbf` (Not Before)

```diagram
now = 1719300000
nbf = 1719302400     // token chỉ hiệu lực từ thời điểm này

if now < nbf - clock_skew:
   → ❌ REJECT — token chưa tới thời điểm hiệu lực

Use case:
   • Cấp token trước, hẹn hiệu lực sau (pre-issued token)
   • Batch job cấp token cho lần chạy tiếp theo
```

### 8.3. Kiểm tra `iss` (Issuer)

Server kiểm tra token có phải do **đúng** auth server cấp không:

```diagram
expected_issuer = "https://auth.myapp.com"    // config cứng
token_issuer    = payload.iss                  // từ token

if token_issuer != expected_issuer:
   → ❌ REJECT — token từ issuer lạ

Tại sao quan trọng:
   Kẻ tấn công có thể tự dựng auth server, ký token bằng key riêng,
   gửi token đến API của bạn. Nếu không kiểm tra iss:
   → Server có thể chấp nhận token từ auth server giả!

   (Tất nhiên, nếu kẻ tấn công dùng key khác thì signature fail.
    Nhưng nếu bạn fetch JWKS từ iss URL trong token...
    kẻ tấn công đặt iss = URL của họ → bạn fetch key từ HỌ → verify pass!)
```

> [!IMPORTANT]
> **KHÔNG BAO GIỜ** fetch JWKS dựa trên `iss` URL từ token gửi lên. Kẻ tấn công đặt `iss: "https://evil.com"`, server fetch `https://evil.com/.well-known/jwks.json` → lấy public key của kẻ tấn công → verify pass → bypass hoàn toàn! JWKS URL phải là config cứng phía server, không phụ thuộc vào nội dung token.

### 8.4. Kiểm tra `aud` (Audience)

```diagram
expected_audience = "https://api.myapp.com"    // API server này
token_audience    = payload.aud                 // từ token

if expected_audience NOT IN token_audience:
   → ❌ REJECT — token không dành cho service này

Tại sao quan trọng:
   Auth server cấp token cho service A:
      aud = "https://service-a.myapp.com"

   Nếu service B KHÔNG kiểm tra aud:
      → Token cho service A dùng được ở service B!
      → Privilege escalation nếu A có quyền thấp hơn B
```

`aud` có thể là **string** hoặc **array**:

```json
// Token cho 1 service
{ "aud": "https://api.myapp.com" }

// Token cho nhiều service
{ "aud": ["https://api.myapp.com", "https://admin.myapp.com"] }
```

### 8.5. Kiểm tra custom claims

Ngoài registered claims, server thường kiểm tra thêm:

| Claim | Kiểm tra | Ví dụ |
|-------|---------|-------|
| `role` / `roles` | User có quyền truy cập endpoint này? | `role == "admin"` cho `/api/admin/*` |
| `scope` | Token có scope cần thiết? | `scope` chứa `"read:orders"` |
| `tenant_id` | Đúng tenant? (multi-tenant SaaS) | `tenant_id == "acme-corp"` |
| `email_verified` | Email đã verify chưa? | `email_verified == true` |

### 8.6. Bảng tóm tắt validate claims

| Claim | Bắt buộc kiểm tra? | Logic | Nếu bỏ qua |
|-------|:---:|------|-----------|
| `exp` | ✅ | `now <= exp + skew` | Token hết hạn vẫn dùng được → security risk |
| `nbf` | ✅ (nếu có) | `now >= nbf - skew` | Token dùng trước giờ → ít nguy hiểm |
| `iss` | ✅ | `iss == expected_issuer` | Chấp nhận token từ issuer lạ |
| `aud` | ✅ | `aud contains this_service` | Token service A dùng ở service B |
| `iat` | Không bắt buộc | Kiểm tra tuổi token hợp lý | Ít ảnh hưởng |
| `jti` | Tùy | Chống replay (check đã dùng chưa) | Replay attack |

---

## 9. Bước 7: Kiểm tra bổ sung — Revocation, rate limit, context

Bước 1-6 là **stateless** — chỉ cần token + key, không cần database. Bước 7 là **stateful** — cần truy vấn external source.

### 9.1. Token revocation check (blacklist)

JWT là stateless, nhưng đôi khi cần vô hiệu hóa token trước khi hết hạn (user đổi mật khẩu, bị ban, v.v.):

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Revocation check:                                                  │
│                                                                     │
│  token.jti = "abc-123"                                              │
│                                                                     │
│  Kiểm tra blacklist (Redis / database):                             │
│     SISMEMBER revoked_tokens "abc-123"                              │
│        ├── 0 (không tìm thấy) → ✅ token chưa bị revoke             │
│        └── 1 (tìm thấy)       → ❌ REJECT — token đã bị thu hồi     │
│                                                                     │
│  TTL key trong Redis = token exp - now                              │
│  (tự cleanup khi token hết hạn)                                     │
╰─────────────────────────────────────────────────────────────────────╯
```

### 9.2. Context binding (nâng cao)

Một số hệ thống kiểm tra thêm **context** — token chỉ hợp lệ trong context tạo ra nó:

| Context | Kiểm tra | Mục đích |
|---------|---------|---------|
| IP address | Token tạo từ IP A, request từ IP B | Phát hiện token bị đánh cắp |
| User-Agent | Token tạo từ Chrome, request từ curl | Phát hiện bot/script dùng token lấy trộm |
| Device fingerprint | Token bind với device hash | Chống token theft |
| DPoP (RFC 9449) | Token bind với proof-of-possession | Mạnh nhất — kể cả leak token vẫn không dùng được |

### 9.3. Rate limiting per-token

```diagram
Mỗi token (jti) hoặc mỗi user (sub) có rate limit riêng:

   sub = "user-42"
   INCR rate:user-42    → 151
   if 151 > 150:
      → 429 Too Many Requests
      (token hợp lệ nhưng vượt rate limit)
```

---

## 10. Pipeline hoàn chỉnh — Flowchart quyết định

```mermaid
flowchart TD
    A[Nhận token từ Authorization header] --> B{Có prefix 'Bearer '?}
    B -- Không --> R1[❌ 401 - Missing token]
    B -- Có --> C[Tách chuỗi bằng dấu chấm]
    C --> D{Đúng 3 phần?}
    D -- Không --> R2[❌ 401 - Malformed token]
    D -- Có --> E[Base64URL decode header]
    E --> F{alg trong whitelist?}
    F -- Không --> R3[❌ 401 - Unsupported algorithm]
    F -- Có --> G[Tìm key dựa vào alg + kid]
    G --> H{Tìm được key?}
    H -- Không --> R4[❌ 401 - Unknown key]
    H -- Có --> I[Verify signature]
    I --> J{Signature hợp lệ?}
    J -- Không --> R5[❌ 401 - Invalid signature]
    J -- Có --> K[Decode payload claims]
    K --> L{exp còn hạn?}
    L -- Không --> R6[❌ 401 - Token expired]
    L -- Có --> M{iss đúng?}
    M -- Không --> R7[❌ 401 - Invalid issuer]
    M -- Có --> N{aud đúng?}
    N -- Không --> R8[❌ 401 - Invalid audience]
    N -- Có --> O{Token bị revoke?}
    O -- Có --> R9[❌ 401 - Token revoked]
    O -- Không --> P[✅ 200 - Token hợp lệ, tiếp tục xử lý]
```

---

## 11. Edge cases thực tế — Những lỗi khó debug

### 11.1. Clock skew giữa các server

```diagram
Tình huống:
   Auth server (đồng hồ đúng): cấp token lúc 10:00:00, exp = 10:05:00
   API server (đồng hồ nhanh 3 phút): now = 10:03:00

   Khi API server nhận token vừa cấp:
      now (10:03:00) vs exp (10:05:00) → OK, nhưng...
      Token thực tế chỉ có hiệu lực 2 phút thay vì 5 phút

   Khi đồng hồ nhanh hơn exp:
      API server now = 10:06:00 vs exp = 10:05:00 → REJECT!
      Mặc dù token mới cấp 1 phút trước

Giải pháp:
   1. Đồng bộ thời gian bằng NTP (Network Time Protocol)
   2. Clock skew tolerance 30-60 giây
   3. Monitor clock drift giữa các server
```

### 11.2. Token quá lớn bị proxy cắt

```diagram
Client gửi:
   Authorization: Bearer eyJhbGci...payload_rất_dài...signature

Nginx config:
   large_client_header_buffers 4 8k;   ← header > 8KB bị cắt

Server nhận:
   Authorization: Bearer eyJhbGci...payload_bị_cắt    ← thiếu signature!
   Split bằng "." → < 3 phần → 401

Debug khó vì:
   - Client log: "Đã gửi token đầy đủ"
   - Server log: "Token malformed"
   - Proxy log: "Header too large" (nếu bật log)
```

### 11.3. Base64URL padding mismatch

Một số thư viện thêm padding `=` vào cuối, một số không. Nếu issuer thêm mà verifier không chấp nhận (hoặc ngược lại) → decode fail:

```text
Với padding:    eyJhbGci...InR5cCI6IkpXVCJ9==
Không padding:  eyJhbGci...InR5cCI6IkpXVCJ9

Theo spec (RFC 7515): KHÔNG có padding
Nhưng thực tế: một số thư viện cũ thêm padding → cần strip trước khi decode
```

### 11.4. JSON key ordering

JWT spec **không** đảm bảo thứ tự key trong JSON. Hai JSON sau là **tương đương**:

```json
{"alg":"HS256","typ":"JWT"}
{"typ":"JWT","alg":"HS256"}
```

Nhưng Base64URL encode sẽ cho **chuỗi khác nhau**. Nếu signing dùng thứ tự A, verify dùng thứ tự B → signature mismatch!

Giải pháp: signing input là **chuỗi Base64URL nguyên bản**, không phải "decode rồi re-encode". Server lấy phần 1 và phần 2 của token **như nguyên bản** (đã encode) để verify — không decode thành JSON rồi encode lại.

---

## 12. So sánh: Validate ở API Gateway vs ở từng service

| | Validate ở API Gateway | Validate ở mỗi service |
|---|---|---|
| **Ai verify signature** | Gateway (1 chỗ) | Mỗi service tự verify |
| **Signature verification** | 1 lần | N lần (N service) |
| **Claims validation** | Cơ bản (exp, iss, aud) | Chi tiết (roles, permissions, business logic) |
| **Ưu điểm** | Tập trung, dễ quản lý key | Service tự chủ, defense-in-depth |
| **Nhược điểm** | Gateway = single point of failure | Mỗi service phải implement, key phải distribute |
| **Phổ biến** | AWS ALB, Kong, Envoy | Spring Security, Express middleware |

Best practice trong microservice:

```diagram
╭────────────────────────────────────────────────────────────────╮
│  Kiến trúc khuyến nghị: 2 lớp validate                         │
│                                                                │
│  ┌─────────────────┐                                           │
│  │   API Gateway   │  Bước 1-4: Tách, decode header,           │
│  │ (Kong / Envoy)  │  chọn key, verify signature               │
│  │                 │  + check exp, iss                         │
│  │  "Token hợp lệ" │                                           │
│  └────────┬────────┘                                           │
│           │ Forward request + claims (header/context)          │
│           ▼                                                    │
│  ┌─────────────────┐                                           │
│  │  Backend Service│  Bước 6: Validate claims chi tiết         │
│  │                 │  aud, roles, permissions, tenant          │
│  │                 │  Bước 7: Revocation check (nếu cần)       │
│  └─────────────────┘                                           │
╰────────────────────────────────────────────────────────────────╯
```

---

## 13. Code minh họa: Validate từ đầu đến cuối

### 13.1. Node.js (jsonwebtoken)

```javascript
const jwt = require('jsonwebtoken');

function validateToken(authHeader) {
  // Bước 1: Tách Bearer token
  if (!authHeader?.startsWith('Bearer ')) {
    throw new Error('Missing or malformed Authorization header');
  }
  const token = authHeader.slice(7);

  // Bước 2-6: Verify + validate (thư viện làm hết)
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],        // Whitelist alg (bước 2)
    issuer: 'https://auth.myapp.com',    // Check iss (bước 6)
    audience: 'https://api.myapp.com',   // Check aud (bước 6)
    clockTolerance: 60,           // Clock skew 60s (bước 6)
  });

  // Bước 7: Custom checks
  if (decoded.role !== 'admin') {
    throw new Error('Insufficient permissions');
  }

  return decoded;
}
```

### 13.2. Java (jjwt)

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

public Claims validateToken(String authHeader) {
    // Bước 1: Tách Bearer
    if (!authHeader.startsWith("Bearer ")) {
        throw new AuthException("Missing token");
    }
    String token = authHeader.substring(7);

    // Bước 2-6: Verify + validate
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(Keys.hmacShaKeyFor(secretBytes))  // Key (bước 3)
        .requireIssuer("https://auth.myapp.com")         // iss (bước 6)
        .requireAudience("https://api.myapp.com")        // aud (bước 6)
        .setAllowedClockSkewSeconds(60)                  // Clock skew
        .build()
        .parseClaimsJws(token)     // Verify + decode (bước 4-5)
        .getBody();

    return claims;
}
```

### 13.3. Python (PyJWT)

```python
import jwt

def validate_token(auth_header: str) -> dict:
    # Bước 1: Tách Bearer
    if not auth_header.startswith("Bearer "):
        raise ValueError("Missing token")
    token = auth_header[7:]

    # Bước 2-6: Verify + validate
    payload = jwt.decode(
        token,
        key=os.environ["JWT_SECRET"],
        algorithms=["HS256"],                     # Whitelist alg
        issuer="https://auth.myapp.com",          # Check iss
        audience="https://api.myapp.com",         # Check aud
        leeway=timedelta(seconds=60),             # Clock skew
    )

    return payload
```

---

## 14. Anti-patterns cần tránh

### 14.1. ❌ Tin `alg` từ header

```text
SAI:  alg = token.header.alg; verify(token, alg, key)
      → Kẻ tấn công đổi alg → bypass verify

ĐÚNG: alg = "RS256" (config cứng); verify(token, "RS256", key)
```

### 14.2. ❌ Chỉ verify signature mà bỏ qua claims

```text
SAI:  if signature_valid(token): allow()
      → Token hết hạn 3 năm trước vẫn dùng được

ĐÚNG: verify signature + check exp + check iss + check aud
```

### 14.3. ❌ Fetch JWKS từ URL trong token

```text
SAI:  jwks_url = token.header.jku; fetch(jwks_url)
      → Kẻ tấn công đặt jku = URL server của họ → lấy key giả

ĐÚNG: jwks_url = "https://auth.myapp.com/.well-known/jwks.json" (config cứng)
```

### 14.4. ❌ Dùng payload trước khi verify signature

```text
SAI:  user_id = decode(token).sub; query_db(user_id); then verify()
      → Kẻ tấn công inject user_id → query DB trước khi bị reject

ĐÚNG: verify() first → then decode → then use payload
```

### 14.5. ❌ Không kiểm tra `aud` trong multi-service

```text
SAI:  Mọi service đều accept mọi token (không check aud)
      → Token cho service "đọc blog" dùng để gọi service "chuyển tiền"

ĐÚNG: Mỗi service kiểm tra aud == service URL của chính nó
```

---

## 15. Tóm tắt — Cheat sheet & 3 nguyên tắc

### Cheat sheet — 7 bước validate

```diagram
╭────────────────────────────────────────────────────────────────────╮
│              JWT VALIDATION CHEAT SHEET                            │
│                                                                    │
│  1. TÁCH CHUỖI: Split "." → 3 phần (header, payload, signature)    │
│  2. DECODE HEADER: Base64URL → JSON, check alg ∈ whitelist         │
│  3. CHỌN KEY: alg + kid → tìm key (secret hoặc public key/JWKS)    │
│  4. VERIFY SIGNATURE: sign(header.payload, key) == sig?            │
│     → Dùng constant-time compare!                                  │
│  5. DECODE PAYLOAD: Base64URL → JSON claims                        │
│  6. VALIDATE CLAIMS:                                               │
│     • exp: now ≤ exp + skew?                                       │
│     • nbf: now ≥ nbf - skew? (nếu có)                              │
│     • iss: == expected_issuer?                                     │
│     • aud: contains this_service?                                  │
│  7. KIỂM TRA BỔ SUNG: revocation, context, rate limit              │
│                                                                    │
│  Bất kỳ bước nào FAIL → 401 ngay, không tiếp tục.                  │
╰────────────────────────────────────────────────────────────────────╯
```

### 3 nguyên tắc

| # | Nguyên tắc | Giải thích |
|---|-----------|-----------|
| 1 | **Verify signature ≠ token hợp lệ** | Signature chỉ chứng minh "chưa bị sửa". Vẫn phải check exp, iss, aud, revocation |
| 2 | **Config cứng phía server, không tin header** | `alg`, `jku`, `iss` từ token đều có thể bị sửa — server phải tự biết mình muốn gì |
| 3 | **Fail-fast, reject sớm** | Check rẻ trước (format, alg), check đắt sau (signature, DB lookup). Mỗi bước fail → dừng ngay |

---

## Tài liệu tham khảo

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
