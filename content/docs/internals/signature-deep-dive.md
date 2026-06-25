---
title: "Chữ ký số JWT — Deep Dive"
description: "Mổ xẻ chi tiết cách JWT được ký và verify ở tầng byte — signing input, base64url, HMAC-SHA256 (ipad/opad), RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA (r, s), EdDSA. Kèm so sánh thuật toán, constant-time compare, code Node.js và anti-patterns."
---

# Chữ ký số JWT — Deep Dive

## Mục lục

- [Chữ ký JWT bảo vệ điều gì — và không bảo vệ điều gì](#1-chữ-ký-jwt-bảo-vệ-điều-gì--và-không-bảo-vệ-điều-gì)
- [Nhắc lại cấu trúc JWS Compact và Signing Input](#2-nhắc-lại-cấu-trúc-jws-compact-và-signing-input)
- [base64url — vì sao không phải base64 thường](#3-base64url--vì-sao-không-phải-base64-thường)
- [HS256 — HMAC-SHA256 mổ xẻ từng bước](#4-hs256--hmac-sha256-mổ-xẻ-từng-bước)
- [RS256 — RSA chữ ký bất đối xứng](#5-rs256--rsa-chữ-ký-bất-đối-xứng)
- [ES256 — ECDSA và chữ ký (r, s)](#6-es256--ecdsa-và-chữ-ký-r-s)
- [PS256 & EdDSA — hai lựa chọn hiện đại](#7-ps256--eddsa--hai-lựa-chọn-hiện-đại)
- [So sánh toàn bộ thuật toán ký](#8-so-sánh-toàn-bộ-thuật-toán-ký)
- [Verify — vì sao phải so sánh constant-time](#9-verify--vì-sao-phải-so-sánh-constant-time)
- [Code thực chiến — ký và verify trong Node.js](#10-code-thực-chiến--ký-và-verify-trong-nodejs)
- [Anti-patterns cần tránh](#11-anti-patterns-cần-tránh)
- [Tóm tắt — Cheat sheet](#12-tóm-tắt--cheat-sheet)

---

## 1. Chữ ký JWT bảo vệ điều gì — và không bảo vệ điều gì

Trước khi mổ xẻ thuật toán, cần gỡ ngay hiểu lầm phổ biến nhất về chữ ký JWT: **chữ ký không mã hóa gì cả.**

Payload của JWT chỉ là JSON được base64url — ai chặn được token cũng đọc được nội dung bằng mắt thường. Chữ ký (phần thứ ba) sinh ra để trả lời đúng **một** câu hỏi: *"token này có đúng do người giữ khóa tạo ra, và chưa bị sửa một bit nào không?"*

Thử nhanh để thấy ranh giới đó. Lấy một token đang dùng tốt, decode payload ra `{"sub":"123","role":"user"}`, đổi `user` thành `admin`, base64url lại rồi gửi lên server:

```text
401 Unauthorized — invalid signature
```

Chỉ đổi **đúng một từ** trong phần ai cũng đọc được, server phát hiện ngay — vì chữ ký được tính từ **chính xác từng byte** của header và payload, đổi 1 bit là hash đổi hoàn toàn → chữ ký không khớp. Bạn *đọc* được payload, nhưng *sửa* thì không qua mặt được ai.

Từ thí nghiệm nhỏ đó lộ ra ba câu hỏi mà cả doc này sẽ trả lời:

1. Server **tính** chữ ký đó như thế nào — từ byte nào, qua hàm gì?
2. Tại sao kẻ tấn công **không thể** tự tạo lại chữ ký dù biết thừa thuật toán?
3. `HS256`, `RS256`, `ES256` khác nhau ở đâu trong ruột — và vì sao chọn sai cái lại mở toang cửa hậu?

> [!IMPORTANT]
> Chữ ký JWT bảo vệ **tính toàn vẹn & nguồn gốc**, KHÔNG bảo vệ **bí mật**. Hiểu sai điều này dẫn tới hai lỗi chết người: (1) nhét secret/PII vào payload tưởng được giấu, (2) tin vào payload mà chưa verify chữ ký.

Trong doc này, ta mổ xẻ từng lớp: từ chuỗi byte đầu vào, qua HMAC/RSA/ECDSA, tới phép so sánh cuối cùng.

---

## 2. Nhắc lại cấu trúc JWS Compact và Signing Input

Một JWT ký (JWS — JSON Web Signature, dạng compact) gồm **3 phần** nối bằng dấu chấm:

```diagram
   header              payload                signature
┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ eyJhbG...VCJ9│ .│ eyJzdWIi...jJ9    │ .│ qFy...kZ4         │
└──────────────┘  └──────────────────┘  └──────────────────┘
       │                   │                     │
 base64url(JSON)     base64url(JSON)    base64url(raw signature bytes)
```

Điểm mấu chốt nhất của toàn bộ doc nằm ở đây — **Signing Input** (RFC 7515 gọi là *JWS Signing Input*):

```diagram
SigningInput = ASCII( base64url(header_json) + "." + base64url(payload_json) )
```

Tức là: lấy phần 1 và phần 2 **đã encode**, nối bằng dấu `.`, rồi coi **toàn bộ chuỗi đó như một mảng byte ASCII**. Chính mảng byte này được đưa vào hàm ký.

```diagram
header_json  = {"alg":"HS256","typ":"JWT"}
payload_json = {"sub":"123","role":"user"}

b64(header)  = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
b64(payload) = eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9

SigningInput = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9"
                └──────────────── đây là cái được ký ────────────────┘

signature    = base64url( SIGN( key, SigningInput ) )

token        = SigningInput + "." + signature
```

> [!NOTE]
> Chữ ký được tính trên **chuỗi base64url đã encode**, KHÔNG phải trên JSON gốc. Đây là lý do bạn không được "re-serialize" lại JSON khi verify — chỉ cần một khoảng trắng khác, thứ tự key khác, là bản encode khác → chữ ký lệch. Verify luôn làm trên đúng chuỗi byte nhận được.

---

## 3. base64url — vì sao không phải base64 thường

JWT đi trong URL, HTTP header (`Authorization: Bearer ...`), cookie. Base64 thường dùng 3 ký tự gây rắc rối ở những chỗ này:

| Ký tự base64 thường | Vấn đề | base64url thay bằng |
|---------------------|--------|---------------------|
| `+` | Trong query string `+` = dấu cách | `-` |
| `/` | Là dấu phân cách path URL | `_` |
| `=` (padding) | Phải percent-encode thành `%3D` | **Bỏ hẳn** |

base64url (RFC 4648 §5) chính là base64 với 3 thay đổi đó. Cơ chế encode bên dưới giống hệt: gom **3 byte (24 bit)** thành **4 nhóm 6 bit**, mỗi nhóm map sang 1 ký tự trong bảng 64 ký tự.

```diagram
3 byte đầu vào:   0x7B 0x22 0x73   ( "{ \" s" )
binary:           01111011 00100010 01110011
gom 6-bit:        011110 110010 001000 110011
chỉ số:           30     50     8      51
ký tự:            e      y      I      z     →  "eyIz"
```

Khi số byte không chia hết cho 3, base64 thường thêm `=` cho đủ bội số 4. base64url **bỏ** padding:

```diagram
1 byte  → 2 ký tự  (base64 thường: "xx==", base64url: "xx")
2 byte  → 3 ký tự  (base64 thường: "xxx=", base64url: "xxx")
3 byte  → 4 ký tự  (không cần padding)
```

> [!TIP]
> Khi tự decode bằng tay (vd. `Buffer.from(part, 'base64url')`), Node.js xử lý cả việc thiếu padding lẫn `-`/`_`. Nếu dùng thư viện chỉ hỗ trợ base64 chuẩn, bạn phải tự thay `-`→`+`, `_`→`/` và thêm lại `=` cho đủ bội số 4, nếu không sẽ lỗi "invalid base64".

---

## 4. HS256 — HMAC-SHA256 mổ xẻ từng bước

`HS256` = **HMAC** dùng hàm băm **SHA-256**. Đây là thuật toán **đối xứng**: cùng một `secret` vừa dùng để ký, vừa dùng để verify.

### 4.1. HMAC không phải là "hash của (key + message)"

Một hiểu lầm phổ biến: `HS256 = SHA256(secret + signingInput)`. **Sai**, và cái sai này từng gây ra *length-extension attack*. HMAC có công thức riêng (RFC 2104):

```diagram
HMAC(K, m) = H( (K' ⊕ opad)  ||  H( (K' ⊕ ipad) || m ) )

trong đó:
  H      = SHA-256
  K'     = key đã chuẩn hóa về đúng block size (64 byte với SHA-256)
  ipad   = byte 0x36 lặp lại 64 lần
  opad   = byte 0x5c lặp lại 64 lần
  ⊕      = XOR từng byte
  ||     = nối chuỗi byte
```

Tức là **hai lần băm lồng nhau**, mỗi lần trộn key theo một padding khác nhau. Chính cấu trúc lồng này chặn length-extension.

### 4.2. Các bước cụ thể

```diagram
╭──────────────────────────────────────────────────────────────╮
│ 1. Chuẩn hóa key K → K' (đúng 64 byte):                       │
│      • Nếu len(K) > 64  → K' = SHA256(K)  rồi pad 0 cho đủ 64  │
│      • Nếu len(K) ≤ 64  → pad thêm byte 0x00 cho đủ 64         │
│                                                                │
│ 2. Tính inner = SHA256( (K' ⊕ ipad) || SigningInput )         │
│      → ra 32 byte                                              │
│                                                                │
│ 3. Tính outer = SHA256( (K' ⊕ opad) || inner )                │
│      → ra 32 byte (256 bit) ← đây là chữ ký thô               │
│                                                                │
│ 4. signature = base64url(outer)  → ~43 ký tự                  │
╰──────────────────────────────────────────────────────────────╯
```

### 4.3. Hệ quả an toàn của tính đối xứng

Vì **ký và verify dùng chung secret**, bất kỳ ai verify được token cũng **tự tạo được** token:

```diagram
Service A (issuer)  ── secret S ──▶  ký token
Service B (verifier) ── secret S ──▶  verify token
                                      ⚠️ B cũng có thể GIẢ token của A
```

| Khi nào HS256 hợp lý | Khi nào KHÔNG nên |
|----------------------|-------------------|
| Một service tự ký, tự verify (monolith) | Nhiều service/bên thứ ba cần verify nhưng KHÔNG được phép tạo token |
| Secret giữ kín ở một nơi | Token phát ra cho client đọc + verify công khai |
| Cần tốc độ tối đa, không cần phân tách quyền | Kiến trúc cần "chỉ issuer ký được" (dùng RS256/ES256) |

> [!WARNING]
> Secret HS256 phải có **entropy đủ cao** (≥ 256 bit ngẫu nhiên). Đừng dùng `"secret"`, `"mykey123"` — chúng bị brute-force/dictionary offline trong vài giây vì kẻ tấn công có sẵn signingInput và signature để thử.

---

## 5. RS256 — RSA chữ ký bất đối xứng

`RS256` = **RSASSA-PKCS1-v1_5** trên hash **SHA-256**. Đây là thuật toán **bất đối xứng**: **private key ký**, **public key verify**. Đây là điểm khác biệt cốt lõi với HS256.

```diagram
                  ┌──────────────┐
   private key ──▶│   SIGN()     │──▶ signature   (chỉ issuer có private key)
                  └──────────────┘
                  ┌──────────────┐
   public key  ──▶│   VERIFY()   │──▶ ✓/✗         (ai cũng có thể có public key)
                  └──────────────┘
```

### 5.1. Bên trong phép ký RSA

```diagram
╭──────────────────────────────────────────────────────────────╮
│ 1. h = SHA256(SigningInput)            → 32 byte               │
│                                                                │
│ 2. Bọc h vào cấu trúc DigestInfo (DER) ghi rõ "đây là SHA-256":│
│      DigestInfo = AlgorithmIdentifier(sha256) || OCTET(h)      │
│                                                                │
│ 3. PKCS#1 v1.5 padding cho đủ độ dài modulus (vd 256 byte):    │
│      EM = 0x00 || 0x01 || 0xFF...0xFF || 0x00 || DigestInfo    │
│           └─ chuỗi 0xFF lấp đầy khoảng giữa ─┘                 │
│                                                                │
│ 4. m = số nguyên từ EM                                         │
│    signature = m^d mod n     (d = số mũ private, n = modulus)  │
│                                                                │
│ 5. base64url(signature)   → với RSA-2048: 256 byte → ~342 ký tự│
╰──────────────────────────────────────────────────────────────╯
```

### 5.2. Bên trong phép verify RSA

```diagram
1. s   = signature (số nguyên)
2. m'  = s^e mod n          (e = số mũ public, thường 65537)
3. Tách EM' từ m', kiểm tra padding 0x00 01 FF..00 đúng chuẩn
4. Lấy DigestInfo, rút ra h' (hash trong chữ ký)
5. Tính lại h = SHA256(SigningInput)
6. So sánh h == h'  → khớp thì chữ ký hợp lệ
```

Kẻ tấn công có public key `(n, e)` nhưng **không** có `d`. Không có `d` thì không tính được `m^d mod n` — bài toán phân tích thừa số nguyên tố của `n` là bất khả thi với số đủ lớn. Đó là lý do public key công khai vô tư mà vẫn an toàn.

> [!IMPORTANT]
> Chính vì public key **công khai**, RS256 hợp với hệ phân tán: Auth Server giữ private key (ký), hàng chục microservice/SPA chỉ cần public key (verify) — và **không** service nào trong số đó giả được token. Nhưng đây cũng là gốc rễ của lỗi *algorithm confusion* (xem doc [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/)).

---

## 6. ES256 — ECDSA và chữ ký (r, s)

`ES256` = **ECDSA** trên đường cong **P-256** (secp256r1) + **SHA-256**. Cũng bất đối xứng như RSA nhưng dựa trên **đường cong elliptic** — khóa nhỏ hơn nhiều mà độ an toàn tương đương.

```diagram
RSA-2048   ≈   ECDSA P-256   (cùng mức ~112-128 bit security)
private key ~1190 byte        private key 32 byte
signature   256 byte          signature   64 byte
```

### 6.1. Chữ ký là một cặp số (r, s)

ECDSA không trả về một con số như RSA mà trả về **hai số nguyên `r` và `s`**, mỗi số 32 byte với P-256:

```diagram
1. h = SHA256(SigningInput)           (lấy 256 bit trái nếu cần)
2. Chọn k ngẫu nhiên (hoặc deterministic theo RFC 6979)
3. Điểm R = k × G  (G = generator của đường cong)
   r = R.x mod n
4. s = k⁻¹ (h + r·privKey) mod n
5. signature = (r, s)
```

### 6.2. JWS encode (r, s) như thế nào — điểm hay nhầm

Khác với các thư viện crypto truyền thống trả `(r, s)` ở dạng **DER** (có độ dài thay đổi), JWS (RFC 7518 §3.4) bắt buộc encode bằng cách **nối thẳng `r || s`** dưới dạng số byte cố định:

```diagram
JWS ES256 signature = base64url( R_bytes(32) || S_bytes(32) )
                                  └──── đúng 64 byte ────┘

DER (KHÔNG dùng cho JWS):
   30 44 02 20 <r...> 02 20 <s...>   ← có tag/length, dài thay đổi
```

> [!WARNING]
> Đây là lỗi tích hợp kinh điển: dùng đầu ra ECDSA dạng DER của OpenSSL/Node `crypto.sign` rồi nhét thẳng vào JWT. Verifier mong đợi `r||s` 64 byte → **invalid signature**. Phải chuyển DER ↔ raw concat. Thư viện JWT tử tế (như `jose`) tự lo việc này.

### 6.3. Cảnh báo về `k`

`s` chứa `k⁻¹`. Nếu `k` bị lặp lại hoặc đoán được, **private key lộ** (vụ Sony PS3 2010 là ví dụ kinh điển: dùng `k` cố định). Vì vậy các thư viện hiện đại dùng **deterministic ECDSA (RFC 6979)** — sinh `k` từ chính `(privKey, h)` thay vì RNG, vừa an toàn vừa tái lập được.

---

## 7. PS256 & EdDSA — hai lựa chọn hiện đại

### 7.1. PS256 — RSA-PSS

`PS256` cũng dùng RSA + SHA-256 nhưng thay padding **PKCS#1 v1.5** (cố định, tất định) bằng **PSS** (Probabilistic Signature Scheme) — có **salt ngẫu nhiên**, nên ký cùng một message hai lần ra hai chữ ký khác nhau. PSS có chứng minh an toàn chặt chẽ hơn v1.5. Cùng key RSA có thể ký được cả RS256 lẫn PS256.

### 7.2. EdDSA — Ed25519

`EdDSA` (RFC 8037) dùng đường cong **Edwards25519**, được thiết kế để **tránh mọi cạm bẫy** của ECDSA:

| Đặc điểm | Lợi ích |
|----------|---------|
| `k` sinh **deterministic** sẵn trong thuật toán | Không bao giờ lộ key do RNG yếu |
| Không cần kiểm tra biên phức tạp | Ít chỗ để implement sai |
| Rất nhanh, signature 64 byte, key 32 byte | Nhẹ, hợp mobile/IoT |
| Không phụ thuộc cấu hình đường cong rối rắm | Chống side-channel tốt hơn |

> [!TIP]
> Nếu được chọn mới và mọi thư viện trong hệ thống đều hỗ trợ, **EdDSA (Ed25519)** thường là lựa chọn an toàn nhất hiện nay cho JWT bất đối xứng. Nếu cần tương thích rộng nhất, **RS256** vẫn là mặc định phổ biến.

---

## 8. So sánh toàn bộ thuật toán ký

| Thuật toán | Họ | Loại khóa | Ký bằng | Verify bằng | Kích thước chữ ký | Ghi chú |
|-----------|-----|-----------|---------|-------------|-------------------|---------|
| `HS256` | HMAC-SHA256 | Đối xứng | secret | **cùng** secret | 32 byte | Nhanh nhất; verifier giả được token |
| `RS256` | RSASSA-PKCS1-v1_5 | Bất đối xứng | private | public | 256 byte (RSA-2048) | Phổ biến nhất, tương thích rộng |
| `PS256` | RSA-PSS | Bất đối xứng | private | public | 256 byte | An toàn hơn RS256, có salt |
| `ES256` | ECDSA P-256 | Bất đối xứng | private | public | 64 byte (r‖s) | Khóa nhỏ, ký chậm nếu non-deterministic |
| `EdDSA` | Ed25519 | Bất đối xứng | private | public | 64 byte | Hiện đại, chống lỗi implement |
| `none` | (không ký) | — | — | — | rỗng | ⚠️ KHÔNG dùng — xem doc security |

```diagram
Tốc độ verify (tương đối, càng phải càng nhanh):
   RS256  ████████████████████   (verify RSA cực nhanh vì e nhỏ)
   ES256  ██████████
   EdDSA  ████████████
   HS256  ████████████████████████ (HMAC nhanh nhất tuyệt đối)

Tốc độ ký (tương đối):
   HS256  ████████████████████████
   ES256  ██████████████
   EdDSA  ████████████████
   RS256  ████                      (ký RSA chậm vì d lớn)
```

> [!NOTE]
> RSA **verify nhanh, ký chậm** (vì `e=65537` nhỏ còn `d` rất lớn). Hệ phát hành ít, verify nhiều (1 Auth Server, nghìn request verify/giây) → RSA hợp lý. ECDSA cân bằng hơn giữa ký và verify.

---

## 9. Verify — vì sao phải so sánh constant-time

Với **HS256**, verify = tính lại HMAC rồi **so sánh** với chữ ký nhận được. Phép so sánh này **không được** dùng `==` thông thường.

### 9.1. Timing attack

So sánh chuỗi kiểu thông thường **dừng ngay khi gặp byte đầu tiên khác nhau**:

```diagram
"abcdefgh" vs "abcXXXXX"   → khác ở vị trí 4 → return sau 4 bước
"aXXXXXXX" vs "abcdefgh"   → khác ở vị trí 2 → return sau 2 bước (nhanh hơn!)
```

Chênh lệch thời gian này rò rỉ "đoán đúng được bao nhiêu byte đầu". Kẻ tấn công đo thời gian phản hồi, dò từng byte chữ ký — về lý thuyết có thể ghép dần ra chữ ký hợp lệ mà không cần biết secret.

### 9.2. Constant-time compare

Phải so sánh **toàn bộ độ dài, luôn tốn cùng thời gian** dù khác ở đâu:

```diagram
diff = 0
for i in 0..len:
    diff |= a[i] XOR b[i]     ← luôn duyệt hết, không return sớm
return diff == 0
```

Node.js có `crypto.timingSafeEqual(a, b)` làm đúng việc này. Thư viện JWT tốt dùng nó bên trong khi verify HMAC.

> [!IMPORTANT]
> Với RS256/ES256/EdDSA, verify là phép toán đường cong/modular nên không có vấn đề so sánh chuỗi như HMAC. Nhưng nguyên tắc chung vẫn là: **đừng tự viết verify**, dùng thư viện đã được kiểm toán.

---

## 10. Code thực chiến — ký và verify trong Node.js

### 10.1. Tự tay tạo một JWT HS256 (để hiểu ruột)

```javascript
import crypto from 'node:crypto';

const b64url = (buf) =>
  Buffer.from(buf).toString('base64url'); // Node tự lo -, _, bỏ padding

const secret = crypto.randomBytes(32); // 256-bit, KHÔNG dùng chuỗi yếu

const header = { alg: 'HS256', typ: 'JWT' };
const payload = { sub: '123', role: 'user', exp: Math.floor(Date.now() / 1000) + 3600 };

const signingInput =
  b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));

const signature = b64url(
  crypto.createHmac('sha256', secret).update(signingInput).digest()
);

const token = signingInput + '.' + signature;
```

### 10.2. Verify đúng cách (constant-time)

```javascript
function verifyHS256(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const signingInput = parts[0] + '.' + parts[1];
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest(); // Buffer 32 byte

  const got = Buffer.from(parts[2], 'base64url');

  // Độ dài khác nhau → timingSafeEqual sẽ throw, chặn trước
  if (got.length !== expected.length) return false;

  return crypto.timingSafeEqual(got, expected); // constant-time
}
```

### 10.3. Thực tế: dùng thư viện, KHÔNG tự verify

```javascript
import jwt from 'jsonwebtoken';

// Ký
const token = jwt.sign(
  { sub: '123', role: 'user' },
  secret,
  { algorithm: 'HS256', expiresIn: '1h' }
);

// Verify — LUÔN khai báo algorithms tường minh (chống alg confusion)
const claims = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

> [!WARNING]
> Đoạn 10.1–10.2 chỉ để **học**. Production hãy dùng `jsonwebtoken`, `jose`, ... và **luôn truyền `algorithms`** vào hàm verify. Đừng để thư viện tự đọc `alg` từ header rồi tin theo — đó là cửa cho algorithm confusion.

---

## 11. Anti-patterns cần tránh

| Anti-pattern | Vì sao nguy hiểm | Làm đúng |
|--------------|------------------|----------|
| Tin payload khi **chưa** verify chữ ký | Payload bịa được tùy ý | Verify trước, đọc claim sau |
| Nhét secret/PII vào payload tưởng "được giấu" | Payload chỉ base64url, ai cũng đọc | Chỉ để claim không nhạy cảm; cần giấu → JWE |
| Secret HS256 ngắn/dễ đoán | Brute-force offline trong giây | ≥ 256-bit ngẫu nhiên |
| So sánh chữ ký bằng `===` | Timing attack | `crypto.timingSafeEqual` / thư viện |
| Verify không truyền `algorithms` | Mở cửa alg confusion & `none` | Khai báo allowlist tường minh |
| Trộn `r‖s` (JWS) với DER (OpenSSL) cho ES256 | invalid signature | Dùng thư viện JWT đúng chuẩn |
| Dùng RS256 nhưng public key bị đối xử như HMAC secret | Giả được token | Tách khóa & khóa alg (doc security) |

---

## 12. Tóm tắt — Cheat sheet

```diagram
╭──────────────────────────────────────────────────────────────╮
│  SigningInput = b64url(header) + "." + b64url(payload)        │
│  signature    = base64url( SIGN(key, SigningInput) )          │
│  token        = SigningInput + "." + signature                │
│                                                                │
│  HS256 → HMAC: H(K⊕opad || H(K⊕ipad || m))   [đối xứng]       │
│  RS256 → m^d mod n, padding PKCS#1 v1.5       [bất đối xứng]   │
│  PS256 → như RS256 nhưng padding PSS (có salt)                │
│  ES256 → ECDSA P-256, chữ ký = r‖s (64 byte)                 │
│  EdDSA → Ed25519, deterministic, chống lỗi implement          │
│                                                                │
│  Verify HMAC → so sánh CONSTANT-TIME                          │
│  Verify RSA  → s^e mod n, check padding + hash                │
╰──────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Chữ ký bảo vệ tính toàn vẹn, KHÔNG bảo vệ bí mật.** Payload luôn đọc được — đừng để gì nhạy cảm trong đó.
2. **Đối xứng (HS) = ai verify được thì giả được; bất đối xứng (RS/ES/EdDSA) = chỉ người giữ private key mới ký được.** Chọn theo "ai được phép tạo token".
3. **Luôn verify bằng thư viện + khai báo `algorithms` tường minh.** Tự viết verify hoặc tin `alg` từ header là con đường ngắn nhất tới sự cố bảo mật.

Đọc tiếp: [Token Validation Flow — Deep Dive](/internals/token-validation-deep-dive/) để xem chữ ký này được kiểm tra ở bước nào trong cả pipeline verify.
