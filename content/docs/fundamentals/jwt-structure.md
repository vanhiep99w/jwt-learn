---
title: "Cấu trúc JWT — Deep Dive"
description: "Mổ xẻ chi tiết cấu trúc JWT từ byte-level: Header, Payload, Signature — cách Base64URL encode hoạt động bên trong, compact serialization, vì sao dùng dấu chấm thay vì JSON, kèm ví dụ tách từng byte và decode thủ công."
---

## Mục lục

- [Bối cảnh: Token dài dằng dặc mà không ai giải thích từng phần](#1-bối-cảnh-token-dài-dằng-dặc-mà-không-ai-giải-thích-từng-phần)
- [Nhìn từ xa: 3 phần, 2 dấu chấm](#2-nhìn-từ-xa-3-phần-2-dấu-chấm)
- [Header — Phần đầu tiên: "Tôi là JWT, ký bằng thuật toán này"](#3-header--phần-đầu-tiên-tôi-là-jwt-ký-bằng-thuật-toán-này)
- [Payload — Phần giữa: "Đây là thông tin tôi mang theo"](#4-payload--phần-giữa-đây-là-thông-tin-tôi-mang-theo)
- [Signature — Phần cuối: "Bằng chứng tôi chưa bị sửa"](#5-signature--phần-cuối-bằng-chứng-tôi-chưa-bị-sửa)
- [Base64URL — Vì sao không phải Base64 thường](#6-base64url--vì-sao-không-phải-base64-thường)
- [Compact Serialization — Vì sao dùng dấu chấm](#7-compact-serialization--vì-sao-dùng-dấu-chấm)
- [Decode thủ công từng phần — Hands-on](#8-decode-thủ-công-từng-phần--hands-on)
- [Kích thước JWT — Token phình to như thế nào](#9-kích-thước-jwt--token-phình-to-như-thế-nào)
- [JWT vs JWS vs JWE vs JWK — Phân biệt các "J" trong hệ sinh thái JOSE](#10-jwt-vs-jws-vs-jwe-vs-jwk--phân-biệt-các-j-trong-hệ-sinh-thái-jose)
- [Sai lầm thường gặp khi hiểu cấu trúc JWT](#11-sai-lầm-thường-gặp-khi-hiểu-cấu-trúc-jwt)
- [Tóm tắt — Cheat sheet & 3 nguyên tắc](#12-tóm-tắt--cheat-sheet--3-nguyên-tắc)

---

## 1. Bối cảnh: Token dài dằng dặc mà không ai giải thích từng phần

Bạn đang debug một API. Trong header `Authorization`, bạn thấy thứ này:

```text
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Đọc xong bạn cảm thấy: *"Chuỗi ký tự ngẫu nhiên, không hiểu gì."* Paste lên jwt.io thì thấy JSON đẹp đẽ hiện ra, nhưng bạn vẫn không hiểu **tại sao** nó có dạng như vậy, **tại sao** dùng dấu chấm, **base64 ở đây là gì**, và quan trọng nhất: **phần nào bảo đảm token không bị giả mạo**.

Đồng nghiệp nói: *"JWT có 3 phần: header, payload, signature."* Nhưng câu đó giống nói "ô tô có động cơ, bánh xe, vô-lăng" — đúng nhưng không giúp bạn sửa xe.

> [!IMPORTANT]
> Phần lớn developer dùng JWT mỗi ngày nhưng chỉ biết nó là "chuỗi token dài". Hiểu cấu trúc ở tầng byte giúp bạn: (1) debug token lỗi trong 30 giây thay vì google 30 phút, (2) hiểu tại sao JWT không mã hóa mà chỉ ký — payload ai cũng đọc được, (3) biết chính xác phần nào quyết định JWT có bị giả mạo hay không, (4) tránh các lỗ hổng bảo mật kinh điển liên quan đến header.

Trong doc này, ta sẽ mổ xẻ từng byte:

1. Header chứa gì, vì sao nó nguy hiểm nếu bạn tin header mù quáng.
2. Payload mang thông tin gì, claim nào bắt buộc, claim nào tùy chọn.
3. Signature được tạo ra thế nào — từng bước, từng byte.
4. Base64URL khác Base64 thường ở đâu, vì sao phải dùng nó.
5. Compact Serialization là gì — vì sao JWT dùng dấu chấm `.` thay vì JSON.

---

## 2. Nhìn từ xa: 3 phần, 2 dấu chấm

Mọi JWT (dạng compact) đều có cấu trúc cố định:

```diagram
╭────────────────────────────────────────────────────────────────────────╮
│                        JWT Compact Serialization                       │
│                                                                        │
│   HEADER          .        PAYLOAD         .        SIGNATURE          │
│   (Base64URL)     │        (Base64URL)     │        (Base64URL)        │
│                   │                        │                           │
│   eyJhbGci...     .        eyJzdWIi...     .        SflKxwRJ...        │
│                                                                        │
│   ◄── Phần 1 ──►  ◄── Phần 2 ──────────►  ◄── Phần 3 ──────────►       │
│   Metadata         Data (claims)            Chữ ký số                  │
│   (thuật toán,     (user info,              (chứng minh                │
│    loại token)      thời hạn, ...)           không bị sửa)             │
╰────────────────────────────────────────────────────────────────────────╯
```

Quy tắc:

| # | Phần | Chức năng | Ai tạo | Ai đọc được |
|---|------|-----------|--------|-------------|
| 1 | **Header** | Khai báo thuật toán ký, loại token | Server (issuer) | Bất kỳ ai (chỉ encode, không encrypt) |
| 2 | **Payload** | Chứa claims — thông tin về user/session | Server (issuer) | Bất kỳ ai (chỉ encode, không encrypt) |
| 3 | **Signature** | Chứng minh Header + Payload chưa bị sửa | Server (issuer) | Server verify (cần secret/key) |

> [!NOTE]
> JWT **không mã hóa** (encrypt) payload. Nó chỉ **encode** (Base64URL) — bất kỳ ai có token đều đọc được payload. Muốn mã hóa nội dung, dùng **JWE** (JSON Web Encryption), không phải JWT thường.

---

## 3. Header — Phần đầu tiên: "Tôi là JWT, ký bằng thuật toán này"

### 3.1. Header chứa gì

Header là một JSON object nhỏ, chứa **metadata** về token. JSON này được Base64URL encode thành phần đầu tiên của chuỗi JWT.

Ví dụ header phổ biến nhất:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

| Trường | Bắt buộc | Ý nghĩa | Ví dụ |
|--------|----------|---------|-------|
| `alg` | ✅ Bắt buộc | Thuật toán ký (signing algorithm) | `HS256`, `RS256`, `ES256`, `none` |
| `typ` | Khuyến nghị | Loại token | `JWT` (hầu như luôn là `JWT`) |
| `kid` | Tùy chọn | Key ID — dùng khi server có nhiều key | `"key-2024-06"` |
| `jku` | Tùy chọn | URL tới JWKS (JSON Web Key Set) | `"https://auth.example.com/.well-known/jwks.json"` |
| `x5c` | Tùy chọn | Certificate chain (X.509) | Mảng certificate Base64 |

### 3.2. Trường `alg` — Trái tim (và cũng là điểm yếu) của header

`alg` cho server biết dùng thuật toán nào để **tạo** và **verify** signature.

Các giá trị phổ biến:

```diagram
╭───────────────────────────────────────────────────────────────────────╮
│  Symmetric (cùng 1 key ký + verify)                                   │
│  ─────────────────────────────────                                    │
│  HS256 = HMAC + SHA-256    ← phổ biến nhất cho monolith               │
│  HS384 = HMAC + SHA-384                                               │
│  HS512 = HMAC + SHA-512                                               │
│                                                                       │
│  Asymmetric (private key ký, public key verify)                       │
│  ──────────────────────────────────────────────                       │
│  RS256 = RSA-PKCS1-v1.5 + SHA-256   ← phổ biến nhất cho microservice  │
│  RS384 / RS512                                                        │
│  PS256 = RSA-PSS + SHA-256          ← an toàn hơn RS256               │
│  ES256 = ECDSA + P-256 + SHA-256    ← key nhỏ, nhanh                  │
│  ES384 / ES512                                                        │
│  EdDSA = Ed25519 / Ed448            ← mới nhất, nhanh nhất            │
│                                                                       │
│  Đặc biệt                                                             │
│  ────────                                                             │
│  none   = KHÔNG ký!                 ← nguy hiểm, xem mục bảo mật      │
╰───────────────────────────────────────────────────────────────────────╯
```

> [!IMPORTANT]
> **Đừng bao giờ tin `alg` trong header một cách mù quáng.** Kẻ tấn công có thể sửa `alg` thành `none` (bỏ ký) hoặc đổi `RS256` thành `HS256` (dùng public key làm HMAC secret) để bypass verification. Server **phải** cố định thuật toán ở phía server, không dùng giá trị `alg` từ token gửi lên. Xem chi tiết tại [Algorithm Confusion Attack](/docs/security/algorithm-confusion/).

### 3.3. Trường `kid` — Khi server có nhiều key

Trong hệ thống production, server thường có nhiều signing key (ví dụ: key rotation mỗi 90 ngày). `kid` (Key ID) giúp server biết dùng key nào để verify:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-Q3"
}
```

Luồng verify khi có `kid`:

```diagram
Client gửi JWT
      │
      ▼
Server đọc header → kid = "key-2024-Q3"
      │
      ▼
Tìm trong bộ key: {
  "key-2024-Q2": RSAPublicKey(...),   ← key cũ (đã rotate)
  "key-2024-Q3": RSAPublicKey(...),   ← key hiện tại ✅ dùng cái này
  "key-2024-Q4": RSAPublicKey(...)    ← key tương lai (pre-staged)
}
      │
      ▼
Verify signature bằng key "key-2024-Q3"
```

### 3.4. Header sau khi Base64URL encode

JSON header `{"alg":"HS256","typ":"JWT"}` đi qua các bước:

```diagram
Bước 1: JSON string (UTF-8 bytes)
   {"alg":"HS256","typ":"JWT"}

Bước 2: Chuyển thành byte array
   7b 22 61 6c 67 22 3a 22 48 53 32 35 36 22 2c 22 74 79 70 22 3a 22 4a 57 54 22 7d

Bước 3: Base64URL encode (KHÔNG padding)
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

Đó chính là phần đầu tiên bạn thấy trong token.

---

## 4. Payload — Phần giữa: "Đây là thông tin tôi mang theo"

### 4.1. Payload chứa gì

Payload cũng là một JSON object, chứa các **claims** — các cặp key-value mang thông tin về user, quyền, thời hạn token, v.v.

```json
{
  "sub": "user-42",
  "name": "Nguyễn Văn A",
  "email": "a@example.com",
  "role": "admin",
  "iat": 1719302400,
  "exp": 1719306000,
  "iss": "https://auth.myapp.com",
  "aud": "https://api.myapp.com"
}
```

### 4.2. Ba loại claims

JWT chia claims thành 3 nhóm:

```diagram
╭───────────────────────────────────────────────────────────────────────╮
│  1. REGISTERED CLAIMS (RFC 7519 định nghĩa)                           │
│     ──────────────────                                                │
│     Tên ngắn (3 ký tự) để tiết kiệm kích thước token.                 │
│     Không bắt buộc, nhưng KHUYẾN NGHỊ MẠNH.                           │
│                                                                       │
│  2. PUBLIC CLAIMS                                                     │
│     ──────────────                                                    │
│     Tên do cộng đồng/tổ chức đăng ký với IANA.                        │
│     Ví dụ: "email", "name", "picture" (OpenID Connect).               │
│                                                                       │
│  3. PRIVATE CLAIMS                                                    │
│     ───────────────                                                   │
│     Tên do BẠN tự đặt — thỏa thuận giữa producer và consumer.         │
│     Ví dụ: "tenant_id", "permissions", "plan".                        │
╰───────────────────────────────────────────────────────────────────────╯
```

### 4.3. Registered Claims chi tiết

Đây là 7 claim chuẩn theo RFC 7519. Tên **cố ý ngắn 3 ký tự** để giảm kích thước token (JWT thường đi kèm mọi HTTP request).

| Claim | Tên đầy đủ | Ý nghĩa | Kiểu dữ liệu | Ví dụ |
|-------|-----------|---------|---------------|-------|
| `iss` | Issuer | Ai đã phát hành token | String (thường là URL) | `"https://auth.myapp.com"` |
| `sub` | Subject | Token này đại diện cho ai | String | `"user-42"` |
| `aud` | Audience | Token này dùng cho service nào | String hoặc Array | `"https://api.myapp.com"` |
| `exp` | Expiration Time | Hết hạn lúc nào (UTC epoch) | Number | `1719306000` |
| `nbf` | Not Before | Chưa có hiệu lực trước thời điểm này | Number | `1719302400` |
| `iat` | Issued At | Token được tạo lúc nào | Number | `1719302400` |
| `jti` | JWT ID | ID duy nhất của token (chống replay) | String | `"a1b2c3d4-e5f6-..."` |

### 4.4. Thời gian trong JWT — Unix timestamp

Tất cả claim thời gian (`exp`, `nbf`, `iat`) dùng **Unix timestamp** — số giây kể từ 1970-01-01T00:00:00Z (UTC):

```diagram
exp = 1719306000

Chuyển sang thời gian người đọc:
   1719306000 giây kể từ 1970-01-01 00:00:00 UTC
   = 2024-06-25T14:00:00Z
   = 25/06/2024, 9:00 PM (giờ Việt Nam, UTC+7)

Khi verify, server so:
   NOW() = 1719305500  →  1719305500 < 1719306000  →  token còn hạn ✅
   NOW() = 1719306001  →  1719306001 > 1719306000  →  token HẾT HẠN ❌
```

> [!TIP]
> Hầu hết server cho phép **clock skew** (lệch đồng hồ) 30–60 giây. Nếu server A cấp token với `exp=1000` nhưng đồng hồ server B chậm 5 giây, server B thấy `now=995 < 1000` → vẫn chấp nhận. Không có clock skew tolerance, hệ thống distributed sẽ reject token hợp lệ liên tục.

### 4.5. Payload KHÔNG phải nơi chứa bí mật

Nhắc lại: payload chỉ được **encode** (Base64URL), không được **encrypt**. Bất kỳ ai có token đều decode được:

```bash
echo "eyJzdWIiOiJ1c2VyLTQyIiwibmFtZSI6Ik5ndXnhu4VuIFbEg24gQSJ9" | base64 -d
# → {"sub":"user-42","name":"Nguyễn Văn A"}
```

**Tuyệt đối không đặt** trong payload:

| ❌ Không đặt | Vì sao |
|-------------|--------|
| Password / secret | Ai cũng đọc được |
| Credit card number | Vi phạm PCI-DSS |
| Dữ liệu nhạy cảm (SSN, CMND) | Lộ thông tin cá nhân |
| Session data lớn | Token phình to, mỗi request gửi kèm → bandwidth |

**Nên đặt:**

| ✅ Nên đặt | Vì sao |
|-----------|--------|
| User ID (`sub`) | Cần để identify user |
| Roles / permissions | Cần để authorize |
| Tenant ID | Cần cho multi-tenant |
| Token metadata (`exp`, `iss`, `aud`) | Cần để validate |

---

## 5. Signature — Phần cuối: "Bằng chứng tôi chưa bị sửa"

### 5.1. Signature giải quyết vấn đề gì

Header và Payload ai cũng đọc được, ai cũng sửa được (chỉ cần decode, sửa JSON, encode lại). Vậy điều gì ngăn kẻ tấn công sửa `"role":"user"` thành `"role":"admin"`?

**Signature.**

Signature là kết quả của việc **ký số** (digital signing) lên nội dung Header + Payload. Nếu bất kỳ byte nào trong Header hoặc Payload thay đổi, signature sẽ **không khớp** khi verify → server reject token.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Kẻ tấn công muốn sửa role:                                         │
│                                                                     │
│  Token gốc (server ký):                                             │
│     Header.{"role":"user",...}.Signature_ĐÚNG                       │
│                                                                     │
│  Token giả mạo (kẻ tấn công sửa):                                   │
│     Header.{"role":"admin",...}.Signature_ĐÚNG    ← vẫn sig cũ!     │
│                                                                     │
│  Server verify:                                                     │
│     sign(Header + Payload_MỚI)  ≠  Signature_CŨ  →  ❌ REJECT       │
│                                                                     │
│  Kẻ tấn công KHÔNG THỂ tạo signature mới vì:                        │
│     → HS256: không biết secret key                                  │
│     → RS256: không có private key                                   │
╰─────────────────────────────────────────────────────────────────────╯
```

### 5.2. Cách tạo Signature — từng bước

Quá trình tạo signature cho thuật toán **HS256** (HMAC-SHA256):

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Input:                                                             │
│     header_b64  = Base64URL(header_json)   = "eyJhbGci..."          │
│     payload_b64 = Base64URL(payload_json)  = "eyJzdWIi..."          │
│     secret      = "my-super-secret-key-256-bit"                     │
│                                                                     │
│  Bước 1: Nối header + payload bằng dấu chấm                         │
│     signing_input = header_b64 + "." + payload_b64                  │
│                   = "eyJhbGci...eyJzdWIi..."                        │
│                                                                     │
│  Bước 2: HMAC-SHA256(secret, signing_input)                         │
│     → 32 bytes raw hash                                             │
│     = 49 f9 4a c7 04 49 48 c7 8a 28 5d 90 4f 87 f0 a4               │
│       c7 89 7f 7e 8f 3a 4e b2 25 5f da 75 0b 2c c3 97               │
│                                                                     │
│  Bước 3: Base64URL encode hash                                      │
│     = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"                 │
│                                                                     │
│  Output: Signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  │
╰─────────────────────────────────────────────────────────────────────╯
```

Bằng mã giả (pseudocode):

```text
signature = Base64URL(
    HMAC-SHA256(
        key    = secret,
        data   = Base64URL(header) + "." + Base64URL(payload)
    )
)
```

### 5.3. Signing input — Chi tiết quan trọng bị nhiều người bỏ qua

**Signing input** (dữ liệu đầu vào cho hàm ký) là chuỗi ASCII:

```text
Base64URL(header) + "." + Base64URL(payload)
```

Chú ý:
- Input là **chuỗi Base64URL đã encode**, không phải JSON gốc.
- Dấu chấm `.` nằm giữa cũng là **một phần** của signing input.
- Bất kỳ thay đổi nào — kể cả thêm/bớt 1 khoảng trắng trong JSON gốc — sẽ thay đổi Base64URL output → signing input khác → signature khác.

```diagram
Signing input (ký lên chuỗi NÀY):

  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
   ◄──────── header (Base64URL) ─────────►.◄── payload (Base64URL) ──►
                                          │
                                     dấu chấm là
                                     MỘT PHẦN của
                                     signing input
```

### 5.4. HS256 vs RS256 — Symmetric vs Asymmetric signing

| | HS256 (Symmetric) | RS256 (Asymmetric) |
|---|---|---|
| **Ký bằng** | Secret key (shared) | Private key |
| **Verify bằng** | **Cùng** secret key | Public key (khác key) |
| **Ai biết key** | Cả issuer lẫn verifier | Chỉ issuer biết private key |
| **Khi nào dùng** | Monolith (1 server ký + verify) | Microservice (1 issuer, nhiều verifier) |
| **Ưu điểm** | Nhanh, đơn giản | Verifier không cần biết secret |
| **Nhược điểm** | Mọi verifier đều biết secret → ai cũng ký được | Chậm hơn, key lớn hơn |

```diagram
HS256 (Symmetric):
   ┌─────────────┐                     ┌─────────────┐
   │ Auth Server │                     │ API Server  │
   │  secret=K   │────── JWT ────────▶ │  secret=K   │
   │  SIGN(K)    │                     │  VERIFY(K)  │
   └─────────────┘                     └─────────────┘
   Cả hai dùng CÙNG key K.
   Nếu API Server bị hack → kẻ tấn công có K → giả mạo token.

RS256 (Asymmetric):
   ┌─────────────┐                     ┌─────────────┐
   │ Auth Server │                     │ API Server  │
   │ private_key │────── JWT ────────▶ │ public_key  │
   │  SIGN(priv) │                     │ VERIFY(pub) │
   └─────────────┘                     └─────────────┘
   API Server chỉ có public key — không thể giả mạo token.
   Kể cả API Server bị hack, kẻ tấn công không ký được token mới.
```

> [!IMPORTANT]
> Trong kiến trúc microservice, **luôn dùng asymmetric** (RS256, ES256, EdDSA). Nếu dùng HS256, mọi service đều biết secret → bất kỳ service nào bị compromise đều có thể ký token giả mạo cho toàn hệ thống.

---

## 6. Base64URL — Vì sao không phải Base64 thường

### 6.1. Base64 là gì (nhắc nhanh)

Base64 biến binary data thành chuỗi ASCII, dùng 64 ký tự: `A-Z`, `a-z`, `0-9`, `+`, `/`, và `=` (padding).

Vấn đề: JWT thường nằm trong URL (query param) hoặc HTTP header. Ký tự `+`, `/`, `=` gây **xung đột**:

| Ký tự | Xung đột trong | Vì sao |
|-------|----------------|--------|
| `+` | URL | URL encode `+` thành `%2B` hoặc hiểu nhầm thành khoảng trắng |
| `/` | URL path | `/` là ký tự phân tách path segment |
| `=` | URL query | `=` là ký tự phân tách key=value |

### 6.2. Base64URL khác Base64 ở đâu

Base64URL (**RFC 4648 §5**) thay thế đúng 2 ký tự và bỏ padding:

| | Base64 thường | Base64URL |
|---|---|---|
| Ký tự thứ 62 | `+` | `-` (dấu gạch ngang) |
| Ký tự thứ 63 | `/` | `_` (dấu gạch dưới) |
| Padding | `=` (1 hoặc 2 cuối) | **Bỏ hết** (không có `=`) |

```diagram
Ví dụ cùng một dữ liệu:

   Base64 thường:  SGVsbG8rV29ybGQ/==
                                +     /   ==
                                │     │    │
                                ▼     ▼    ▼
   Base64URL:      SGVsbG8tV29ybGQ_
                                -     _   (không có ==)

JWT dùng Base64URL → an toàn trong URL, header, cookie mà không cần escape.
```

### 6.3. Vì sao bỏ padding

Padding `=` trong Base64 chỉ để cho chiều dài chuỗi chia hết cho 4. Nó **không mang thông tin** — khi decode, có thể tính lại padding từ chiều dài chuỗi:

```text
Chiều dài mod 4:
   0 → không cần padding
   2 → thêm 2 dấu "=="
   3 → thêm 1 dấu "="
   1 → lỗi (không hợp lệ)
```

JWT spec nói: bỏ padding khi encode, tự thêm lại khi decode. Tiết kiệm 0-2 byte mỗi phần — tưởng ít nhưng JWT đi kèm **mọi HTTP request**, tích lũy lại đáng kể.

---

## 7. Compact Serialization — Vì sao dùng dấu chấm

### 7.1. JWT có 2 dạng serialization

JWT (hay chính xác hơn, JWS — JSON Web Signature) hỗ trợ 2 cách biểu diễn:

| Dạng | Tên | Dùng khi |
|------|-----|---------|
| **Compact** | `header.payload.signature` | API, HTTP header, URL — phổ biến nhất |
| **JSON** | JSON object chứa `header`, `payload`, `signature` | Cần nhiều chữ ký hoặc header không bảo vệ |

Khi người ta nói "JWT", 99% là nói dạng **Compact Serialization**.

### 7.2. Vì sao dùng dấu chấm `.` làm separator

Dấu chấm được chọn vì:

1. **Không xuất hiện trong Base64URL** — bảng mã Base64URL chỉ có `A-Z`, `a-z`, `0-9`, `-`, `_`. Dấu chấm `.` nằm ngoài → không bao giờ bị nhầm với data.
2. **Không cần escape trong URL** — dấu chấm là ký tự hợp lệ trong URL (RFC 3986), không cần percent-encode.
3. **Không cần escape trong HTTP header** — dấu chấm không phải ký tự đặc biệt trong header value.
4. **Đơn giản** — split bằng `.` cho ra đúng 3 phần, không cần parser phức tạp.

```diagram
Tại sao KHÔNG dùng các ký tự khác?

   Dấu ","  → xung đột với JSON array, header value separator
   Dấu ":"  → xung đột với URL scheme (https:)
   Dấu ";"  → xung đột với cookie separator
   Dấu "|"  → một số hệ thống escape nó
   Dấu "."  → ✅ không xung đột đâu cả, hợp lệ trong URL, header, cookie path
```

### 7.3. Ghép lại thành token hoàn chỉnh

```text
final_token = Base64URL(header) + "." + Base64URL(payload) + "." + Base64URL(signature)

             ┌─── Header ────┐   ┌──── Payload ────┐   ┌──── Signature ────┐
             eyJhbGciOiJIUzI1N . eyJzdWIiOiIxMjM0NT . SflKxwRJSMeKKF2QT4f
             iIsInR5cCI6IkpXVC   Y3ODkwIiwibmFtZSI6   wpMeJf36POk6yJV_adQ
             J9                   IkpvaG4gRG9lIiwiaW   ssw5c
                                  F0IjoxNTE2MjM5MDIy
                                  fQ
```

---

## 8. Decode thủ công từng phần — Hands-on

Hãy decode token mẫu bằng tay (chỉ cần command line):

### 8.1. Token mẫu

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 8.2. Bước 1 — Split bằng dấu chấm

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

HEADER=$(echo $TOKEN | cut -d. -f1)
PAYLOAD=$(echo $TOKEN | cut -d. -f2)
SIGNATURE=$(echo $TOKEN | cut -d. -f3)
```

### 8.3. Bước 2 — Decode Header

```bash
echo "$HEADER" | tr '_-' '/+' | base64 -d 2>/dev/null
# Output: {"alg":"HS256","typ":"JWT"}
```

Giải thích lệnh:
- `tr '_-' '/+'` — chuyển Base64URL về Base64 thường (đảo lại 2 ký tự).
- `base64 -d` — decode Base64.
- Không cần thêm padding vì `base64` trên hầu hết hệ thống tự xử lý.

### 8.4. Bước 3 — Decode Payload

```bash
echo "$PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null
# Output: {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### 8.5. Bước 4 — Signature (không decode thành text)

```bash
echo "$SIGNATURE" | tr '_-' '/+' | base64 -d 2>/dev/null | xxd | head -3
# Output (hex dump):
# 00000000: 49f9 4ac7 0449 48c7 8a28 5d90 4f87 f0a4  I.J..IH..(].O...
# 00000010: c789 7f7e 8f3a 4eb2 255f da75 0b2c c397  ...~.:N.%_.u.,..
```

Signature là **binary data** (32 bytes với HS256), không phải JSON. Nó chỉ có nghĩa khi verify, không "đọc" được.

### 8.6. Decode bằng Python (1 lệnh)

```python
import base64, json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

for i, part in enumerate(token.split(".")):
    padded = part + "=" * (4 - len(part) % 4)  # thêm padding
    decoded = base64.urlsafe_b64decode(padded)
    if i < 2:  # header và payload là JSON
        print(f"Part {i}: {json.loads(decoded)}")
    else:       # signature là binary
        print(f"Part {i}: {decoded.hex()} ({len(decoded)} bytes)")

# Output:
# Part 0: {'alg': 'HS256', 'typ': 'JWT'}
# Part 1: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
# Part 2: 49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397 (32 bytes)
```

---

## 9. Kích thước JWT — Token phình to như thế nào

### 9.1. Tính kích thước

JWT đi kèm **mọi HTTP request** trong header `Authorization`. Kích thước token ảnh hưởng trực tiếp đến bandwidth và latency.

```diagram
Kích thước ước lượng từng phần:

   Header (tối thiểu):
      {"alg":"HS256","typ":"JWT"}  →  36 bytes JSON  →  ~48 chars Base64URL

   Payload (ví dụ nhỏ, 5 claims):
      {"sub":"u42","role":"admin","iat":...,"exp":...,"iss":"..."}
      →  ~120 bytes JSON  →  ~160 chars Base64URL

   Signature:
      HS256 → 32 bytes  →  43 chars Base64URL
      RS256 → 256 bytes →  342 chars Base64URL

   Tổng (HS256, payload nhỏ):   ~253 chars   ← chấp nhận được
   Tổng (RS256, payload nhỏ):   ~552 chars   ← vẫn OK
```

### 9.2. Token phình khi nào

| Nguyên nhân | Ảnh hưởng | Giải pháp |
|-------------|----------|-----------|
| Nhét quá nhiều claim | Payload lớn | Chỉ đặt những gì cần thiết, lookup DB cho phần còn lại |
| Dùng tên claim dài | `"user_permissions"` vs `"perm"` | Dùng tên ngắn cho private claim |
| Nhét array lớn | `"roles": ["a","b","c",..."z"]` | Dùng bitfield hoặc tham chiếu |
| Dùng RS256 thay HS256 | Signature 256 bytes vs 32 bytes | Trade-off: security vs size |
| Nested JWT | Token trong token | Tránh nếu có thể |

### 9.3. Giới hạn thực tế

| Nơi chứa JWT | Giới hạn kích thước | Ghi chú |
|--------------|-------------------:|---------|
| HTTP header (`Authorization`) | ~8 KB (tùy server) | Nginx default: 8KB; Apache: 8KB |
| Cookie | 4,096 bytes | Giới hạn per-cookie theo RFC 6265 |
| URL query parameter | ~2,048 chars (IE) → ~8,000 chars (modern) | Tránh nếu có thể |
| localStorage | 5–10 MB | Không phải giới hạn, nhưng XSS risk |

> [!TIP]
> Nếu token vượt quá **1 KB**, hãy xem xét lại payload — rất có thể bạn đang nhét quá nhiều thứ. Token lý tưởng nên dưới **500 bytes** cho hầu hết use case.

---

## 10. JWT vs JWS vs JWE vs JWK — Phân biệt các "J" trong hệ sinh thái JOSE

Nhiều người nhầm lẫn JWT với JWS, hoặc nghĩ JWT = mã hóa. Thực tế chúng là các spec khác nhau trong bộ tiêu chuẩn **JOSE** (JSON Object Signing and Encryption):

```diagram
╭──────────────────────────────────────────────────────────────────────╮
│                          JOSE Framework                              │
│                                                                      │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                 │
│  │     JWT     │   │     JWS     │   │     JWE     │                 │
│  │  RFC 7519   │   │  RFC 7515   │   │  RFC 7516   │                 │
│  │             │   │             │   │             │                 │
│  │ Định dạng   │   │ Ký số       │   │ Mã hóa      │                 │
│  │ claims      │   │ (signed)    │   │ (encrypted) │                 │
│  │             │   │             │   │             │                 │
│  │ "Phong bì"  │   │ "Con dấu"   │   │ "Két sắt"   │                 │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘                 │
│         │                 │                 │                        │
│         ▼                 ▼                 ▼                        │
│  JWT dùng JWS          JWS bảo vệ      JWE bảo vệ                    │
│  hoặc JWE để           tính toàn vẹn    tính bí mật                  │
│  truyền claims         (integrity)      (confidentiality)            │
│                                                                      │
│  ┌─────────────┐   ┌─────────────┐                                   │
│  │     JWK     │   │     JWA     │                                   │
│  │  RFC 7517   │   │  RFC 7518   │                                   │
│  │             │   │             │                                   │
│  │ Định dạng   │   │ Danh sách   │                                   │
│  │ key (JSON)  │   │ thuật toán  │                                   │
│  └─────────────┘   └─────────────┘                                   │
╰──────────────────────────────────────────────────────────────────────╯
```

| Spec | RFC | Một câu | Cấu trúc compact |
|------|-----|---------|-------------------|
| **JWT** | 7519 | Định dạng cho claims (ai, quyền gì, hết hạn khi nào) | Không tự có — dùng JWS hoặc JWE |
| **JWS** | 7515 | Cách ký token để chống giả mạo | `header.payload.signature` (3 phần) |
| **JWE** | 7516 | Cách mã hóa token để giấu nội dung | `header.enc_key.iv.ciphertext.tag` (5 phần) |
| **JWK** | 7517 | Cách biểu diễn cryptographic key dưới dạng JSON | JSON object |
| **JWA** | 7518 | Danh sách thuật toán được phép (HS256, RS256, ...) | — |

Khi bạn nói "JWT token có 3 phần" — thực chất bạn đang nói **JWS compact serialization**. JWT chỉ là "nội dung" (claims), JWS là "phong bì có con dấu".

---

## 11. Sai lầm thường gặp khi hiểu cấu trúc JWT

### 11.1. "JWT được mã hóa nên an toàn"

❌ **Sai.** JWT (JWS) chỉ **encode** (Base64URL), **không encrypt**. Bất kỳ ai có token đều đọc được payload. "Signature" chỉ chống **giả mạo** (tampering), không chống **đọc trộm** (eavesdropping).

Nếu cần ẩn nội dung → dùng **JWE**, hoặc đơn giản hơn: truyền JWT qua **HTTPS** (TLS mã hóa toàn bộ traffic).

### 11.2. "Signature chứng minh token hợp lệ"

⚠️ **Chưa đủ.** Signature chỉ chứng minh token **chưa bị sửa** kể từ lúc ký. Token vẫn có thể:
- **Hết hạn** (`exp` đã qua)
- **Bị thu hồi** (server đã revoke)
- **Sai audience** (token cho service A, gửi sang service B)
- **Replay attack** (token hợp lệ bị dùng lại)

Verify signature chỉ là **bước 1** trong quy trình validate. Xem [Luồng xác thực JWT](/docs/internals/token-validation-flow/) để hiểu toàn bộ quy trình.

### 11.3. "Base64 = mã hóa"

❌ **Sai.** Base64 là **encoding** (chuyển đổi biểu diễn), không phải **encryption** (mã hóa). Encoding có thể đảo ngược bởi bất kỳ ai mà không cần key. Encryption cần key để giải mã.

```diagram
Encoding (ai cũng decode được):
   "Hello" ──Base64──▶ "SGVsbG8=" ──Base64 decode──▶ "Hello"
   Không cần key. Không bảo mật gì cả.

Encryption (cần key để decrypt):
   "Hello" ──AES(key)──▶ "xK3j..." ──AES(key)──▶ "Hello"
   Không có key → không đọc được.
```

### 11.4. "Token ngắn hơn = an toàn hơn"

❌ **Không liên quan.** An toàn phụ thuộc vào thuật toán ký và độ mạnh của key, không phải chiều dài token. Token ngắn dùng HS256 với secret `"123"` vẫn cực kỳ yếu.

### 11.5. "Có thể sửa claim rồi gửi lại"

❌ **Không thể** (nếu server implement đúng). Sửa bất kỳ byte nào trong header hoặc payload → signature không khớp → server reject. Kẻ tấn công không thể tạo signature mới vì không có secret/private key.

---

## 12. Tóm tắt — Cheat sheet & 3 nguyên tắc

### Cheat sheet

```diagram
╭────────────────────────────────────────────────────────────────────╮
│                        JWT STRUCTURE CHEAT SHEET                   │
│                                                                    │
│  Token = Base64URL(Header) . Base64URL(Payload) . Base64URL(Sig)   │
│                                                                    │
│  HEADER:                                                           │
│    • JSON: {"alg":"HS256","typ":"JWT"}                             │
│    • alg: thuật toán ký (KHÔNG tin mù quáng!)                      │
│    • kid: key ID (khi có nhiều key)                                │
│                                                                    │
│  PAYLOAD:                                                          │
│    • JSON chứa claims (thông tin)                                  │
│    • Registered: iss, sub, aud, exp, nbf, iat, jti                 │
│    • Thời gian = Unix timestamp (giây)                             │
│    • KHÔNG được encrypt → KHÔNG chứa bí mật                        │
│                                                                    │
│  SIGNATURE:                                                        │
│    • = Sign(Base64URL(header) + "." + Base64URL(payload), key)     │
│    • Chống giả mạo, KHÔNG chống đọc trộm                           │
│    • HS256: 32 bytes | RS256: 256 bytes | ES256: 64 bytes          │
│                                                                    │
│  BASE64URL (không phải Base64):                                    │
│    • + → -    / → _    Bỏ padding (=)                              │
│    • An toàn trong URL, header, cookie                             │
╰────────────────────────────────────────────────────────────────────╯
```

### 3 nguyên tắc

| # | Nguyên tắc | Giải thích |
|---|-----------|-----------|
| 1 | **JWT encode, không encrypt** | Payload ai cũng đọc được — đừng đặt secret vào đó |
| 2 | **Signature chống sửa, không chống đọc** | Sửa 1 bit → signature vỡ → reject. Nhưng đọc thì thoải mái |
| 3 | **Đừng tin header, hãy cố định thuật toán phía server** | `alg` trong header có thể bị attacker sửa — server phải tự quyết dùng thuật toán nào |

---

## Tài liệu tham khảo

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 4648 §5 — Base64URL Encoding](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
- [jwt.io — JWT Debugger](https://jwt.io/)
