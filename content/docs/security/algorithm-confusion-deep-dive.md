---
title: "Algorithm Confusion & alg:none — Deep Dive"
description: "Mổ xẻ chi tiết các đòn tấn công lợi dụng header alg của JWT — alg:none bypass, RS256→HS256 confusion (dùng public key làm HMAC secret), jku/x5u/jwk header injection, kid path traversal/SQLi. Kèm walkthrough từng byte, code khai thác, cách phòng thủ và threat model."
---

# Algorithm Confusion & alg:none — Deep Dive

## Mục lục

- [Góc nhìn kẻ tấn công: được tự chọn luật chơi](#1-góc-nhìn-kẻ-tấn-công-được-tự-chọn-luật-chơi)
- [Gốc rễ: alg nằm trong token do kẻ tấn công kiểm soát](#2-gốc-rễ-alg-nằm-trong-token-do-kẻ-tấn-công-kiểm-soát)
- [Đòn 1: alg:none — bỏ luôn chữ ký](#3-đòn-1-algnone--bỏ-luôn-chữ-ký)
- [Đòn 2: RS256 → HS256 confusion](#4-đòn-2-rs256--hs256-confusion)
- [Vì sao confusion hoạt động — mổ xẻ API verify](#5-vì-sao-confusion-hoạt-động--mổ-xẻ-api-verify)
- [Đòn 3: jku / x5u — trỏ server tới khóa của attacker](#6-đòn-3-jku--x5u--trỏ-server-tới-khóa-của-attacker)
- [Đòn 4: jwk header injection — tự nhúng khóa](#7-đòn-4-jwk-header-injection--tự-nhúng-khóa)
- [Đòn 5: kid injection — path traversal & SQLi](#8-đòn-5-kid-injection--path-traversal--sqli)
- [Phòng thủ — checklist từng tầng](#9-phòng-thủ--checklist-từng-tầng)
- [Code: vulnerable vs fixed](#10-code-vulnerable-vs-fixed)
- [Threat model & CVE lịch sử](#11-threat-model--cve-lịch-sử)
- [Tóm tắt — Cheat sheet](#12-tóm-tắt--cheat-sheet)

---

## 1. Góc nhìn kẻ tấn công: được tự chọn luật chơi

Mọi đòn trong doc này bắt đầu từ cùng một góc nhìn: kẻ tấn công **không** cần bẻ khóa mật mã. Họ chỉ cần để ý một sự thật: header của JWT — `alg`, `kid`, `jku`, `jwk` — đều do **bên gửi** điền, tức chính họ. Nếu server tin vào header để quyết định *cách verify*, thì kẻ tấn công đang được **tự chọn luật chơi** mà chính mình sẽ bị kiểm tra.

Để thấy hậu quả cụ thể, đặt mình vào vai pentester. Bạn đăng nhập tài khoản thường, nhận token:

```text
header  = {"alg":"RS256","kid":"prod-2024"}
payload = {"sub":"alice","role":"user","exp":1730000000}
```

Bạn lấy **public key** của họ (công khai ở `/.well-known/jwks.json` — đúng bản chất public key là để công khai). Rồi bạn làm điều "không nên hoạt động":

1. Đổi payload thành `{"sub":"alice","role":"admin",...}`.
2. Đổi header thành `{"alg":"HS256","kid":"prod-2024"}`.
3. Ký lại bằng **HMAC-SHA256**, dùng **chính chuỗi public key PEM** làm secret.
4. Gửi lên server.

```text
200 OK — Welcome, admin.
```

Token admin **tự chế**, ký bằng khóa **ai cũng có**, vậy mà server chấp nhận. Không có lỗi crypto nào ở đây cả — RSA vẫn an toàn, HMAC vẫn an toàn. Lỗ hổng nằm ở chỗ server để **kẻ tấn công chọn thuật toán verify**.

> [!IMPORTANT]
> Toàn bộ họ tấn công này **không bẻ khóa mật mã**. Chúng lợi dụng việc trường `alg` (và `kid`, `jku`, `jwk`) trong header JWT **do bên gửi điền** — tức kẻ tấn công kiểm soát — nhưng lại bị server *tin theo* khi quyết định verify như thế nào. Đây là lỗ hổng **logic**, không phải lỗ hổng **toán học**.

---

## 2. Gốc rễ: alg nằm trong token do kẻ tấn công kiểm soát

```diagram
   JWT header  = {"alg": "???", "kid": "...", "jku": "...", "jwk": {...}}
                          ▲          ▲          ▲          ▲
                          └──────────┴──────────┴──────────┘
                 TẤT CẢ do bên gửi điền → kẻ tấn công sửa được tùy ý
```

Sai lầm thiết kế dẫn tới mọi đòn dưới đây gói gọn trong một câu:

> *"Server đọc `alg` từ token rồi verify theo đúng thuật toán đó."*

Nghe có vẻ tiện (token tự mô tả nó được ký kiểu gì), nhưng nó trao cho kẻ tấn công quyền **quyết định cách chính mình bị kiểm tra**. Nguyên tắc đúng đã nêu ở [Token Validation — Deep Dive §4](/internals/token-validation-deep-dive/): **thuật toán verify do server quyết định, không phải token**.

---

## 3. Đòn 1: alg:none — bỏ luôn chữ ký

JWS có hỗ trợ thuật toán đặc biệt `"none"` — "JWS unsecured", **không có chữ ký**, dùng cho trường hợp tính toàn vẹn đã được đảm bảo ở tầng khác. Vấn đề: nếu verifier chấp nhận `alg:none`, kẻ tấn công bỏ luôn phần chữ ký.

```diagram
Token tấn công:
   header  = {"alg":"none","typ":"JWT"}
   payload = {"sub":"alice","role":"admin"}
   signature = (rỗng)

   token = base64url(header) + "." + base64url(payload) + "."
                                                          └─ phần chữ ký rỗng
```

```diagram
Thư viện cũ (lỗ hổng):
   alg = "none"  →  "à, token này không cần chữ ký"  →  return payload ✓✓✓
   → token admin giả lọt qua mà KHÔNG cần biết bất kỳ khóa nào
```

Biến thể né filter ngây thơ: nếu server chỉ chặn chuỗi `"none"` chính xác, thử `"None"`, `"NONE"`, `"nOnE"` — nhiều parser so sánh không phân biệt hoa thường.

> [!WARNING]
> `alg:none` chỉ an toàn khi **verifier biết trước** là sẽ nhận token unsecured (rất hiếm). Trong 99.9% hệ thống auth, verifier phải **từ chối thẳng** `none` ở mọi biến thể hoa/thường. Cách chặn gốc: allowlist thuật toán — `none` không nằm trong danh sách thì tự động bị loại.

---

## 4. Đòn 2: RS256 → HS256 confusion

Đây là đòn tinh vi và phổ biến nhất. Bối cảnh: hệ thống dùng **RS256** (bất đối xứng) — private key ký, **public key verify** và public key thì *công khai*.

```diagram
Hệ thống bình thường (RS256):
   issuer  ── private key ──▶ ký
   server  ── public key  ──▶ verify(token, PUBLIC_KEY)

Điểm yếu: server gọi verify(token, PUBLIC_KEY)
          và LẤY THUẬT TOÁN TỪ HEADER TOKEN.
```

Kẻ tấn công khai thác sự thật: **public key là thứ ai cũng lấy được**, và nếu server lấy `alg` từ header thì:

```diagram
╭──────────────────────────────────────────────────────────────╮
│ Bước khai thác:                                                │
│                                                                │
│ 1. Lấy PUBLIC_KEY của server (từ /jwks.json, /cert, ...)       │
│    dưới dạng chuỗi PEM:                                         │
│       -----BEGIN PUBLIC KEY-----\nMIIB...\n-----END...-----     │
│                                                                │
│ 2. Tạo token mới:                                              │
│       header  = {"alg":"HS256",...}   ← đổi RS256 thành HS256   │
│       payload = {"role":"admin",...}                           │
│                                                                │
│ 3. Ký HMAC-SHA256, dùng CHÍNH chuỗi PEM public key làm secret: │
│       sig = HMAC_SHA256(key = PUBLIC_KEY_PEM, signingInput)    │
│                                                                │
│ 4. Gửi token lên server.                                       │
╰──────────────────────────────────────────────────────────────╯
```

Phía server, nếu code đại loại `verify(token, publicKey)` mà **lấy alg = HS256 từ header**:

```diagram
server làm:  HMAC_SHA256(key = publicKey, signingInput) == sig ?
attacker đã: sig = HMAC_SHA256(key = publicKey, signingInput)
                                     ▲
                  CÙNG key (public key), CÙNG thuật toán → KHỚP ✓
```

Khóa "bí mật" của HMAC chính là **public key mà kẻ tấn công đã có**. Server vô tình dùng một thứ công khai làm secret đối xứng.

> [!IMPORTANT]
> Mấu chốt: với RS256, `publicKey` đáng lẽ chỉ dùng cho phép *verify bất đối xứng*. Khi server để token ép sang HS256, cũng `publicKey` đó bị dùng làm *HMAC secret đối xứng* — và bí mật đối xứng thì **không được phép công khai**. Hai vai trò bị lẫn lộn → "confusion".

---

## 5. Vì sao confusion hoạt động — mổ xẻ API verify

Lỗi nằm ở **thiết kế API** của nhiều thư viện JWT đời đầu: hàm verify nhận `key` **đa hình** và tự suy `alg` từ token.

```diagram
verify(token, key):
   alg = token.header.alg          ← ❌ tin header
   if alg startsWith "HS":  return hmacVerify(key as secret, ...)
   if alg startsWith "RS":  return rsaVerify(key as publicKey, ...)
```

`key` ở đây vừa có thể là "HMAC secret", vừa có thể là "RSA public key" — thư viện diễn giải tùy theo `alg`. Kẻ tấn công chỉ cần **đổi `alg`** là đổi luôn cách `key` được diễn giải.

```diagram
   key = PUBLIC_KEY
        │
        ├── alg=RS256 (ý định gốc) → dùng làm RSA public key  (an toàn)
        └── alg=HS256 (bị ép)      → dùng làm HMAC secret      (toang)
```

**Sửa gốc** = bịt cả hai chỗ:

1. **Khóa thuật toán**: server tự quy định `algorithms: ['RS256']`, không lấy từ header.
2. **Tách kiểu khóa**: API hiện đại (như `jose`) yêu cầu truyền đúng *loại* key object (KeyObject RSA) — không phải chuỗi PEM mơ hồ — nên public key không thể bị "ép" thành HMAC secret.

```diagram
verify(token, key, { algorithms: ['RS256'] }):
   alg = token.header.alg
   if alg not in ['RS256']:  reject     ← HS256 bị loại NGAY
   ... verify RSA bằng public key ...
```

> [!TIP]
> Quy tắc bền vững: **mỗi khóa chỉ phục vụ đúng một thuật toán**, và verifier luôn ghim `algorithms`. Ngay cả khi thư viện an toàn, đừng dùng chung một chuỗi key cho nhiều mục đích — tách HMAC secret và RSA key thành hai thực thể khác nhau hoàn toàn.

---

## 6. Đòn 3: jku / x5u — trỏ server tới khóa của attacker

JWS header có thể chứa:

| Header | Ý nghĩa |
|--------|---------|
| `jku` | URL trỏ tới **JWK Set** (các public key dạng JSON) |
| `x5u` | URL trỏ tới **X.509 certificate** chứa public key |

Ý đồ ban đầu: verifier tải khóa từ URL đó để verify. Nhưng URL nằm trong header → **kẻ tấn công điền**:

```diagram
   header = {"alg":"RS256","jku":"https://attacker.com/keys.json"}

   1. Attacker tự sinh cặp RSA của riêng mình.
   2. Đăng public key của mình tại https://attacker.com/keys.json
   3. Ký token bằng PRIVATE key của attacker.
   4. Server đọc jku → fetch keys.json của attacker → verify → ✓ KHỚP
      (vì token được ký bằng private key khớp với public key attacker đăng)
```

Server verify "thành công" — nhưng bằng **khóa của kẻ tấn công**, không phải khóa thật.

```diagram
Phòng thủ:
   ❌ KHÔNG fetch khóa từ jku/x5u tùy ý trong header
   ✅ Chỉ dùng JWKS URL CỐ ĐỊNH cấu hình sẵn phía server
   ✅ Nếu buộc dùng jku → allowlist domain/host chặt chẽ
```

> [!WARNING]
> `jku`/`x5u` bản chất là "để bên gửi tự khai báo khóa của mình". Trong ngữ cảnh verify token tin cậy, **đừng tin chúng**. Server phải biết trước khóa hợp lệ ở đâu (JWKS cố định), không để token dắt mũi.

---

## 7. Đòn 4: jwk header injection — tự nhúng khóa

Tệ hơn `jku` (còn phải host file), header `jwk` cho phép **nhúng thẳng public key vào trong chính token**:

```diagram
   header = {
     "alg":"RS256",
     "jwk": { "kty":"RSA", "n":"<n của attacker>", "e":"AQAB" }
   }
```

Nếu verifier ngây thơ dùng `header.jwk` làm khóa verify:

```diagram
   1. Attacker sinh cặp RSA của mình.
   2. Nhúng PUBLIC key của mình vào header.jwk
   3. Ký token bằng PRIVATE key của mình.
   4. Server lấy header.jwk làm khóa → verify → ✓ KHỚP

   → "self-signed" token: attacker vừa cấp khóa, vừa ký, vừa được tin.
```

Đây là dạng "BYOK — bring your own key" ngoài ý muốn. Phòng thủ: **bỏ qua hoàn toàn** `jwk` trong header khi verify token tin cậy; khóa luôn đến từ nguồn server kiểm soát.

---

## 8. Đòn 5: kid injection — path traversal & SQLi

`kid` (Key ID) dùng để tra cứu khóa. Nếu server **nối thẳng** `kid` vào đường dẫn file hoặc câu SQL, kid trở thành vector injection.

### 8.1. Path traversal

```diagram
   header.kid = "../../../../dev/null"

   server làm:  key = readFile("/keys/" + kid)
              = readFile("/keys/../../../../dev/null")
              = readFile("/dev/null")  → chuỗi RỖNG
```

Nếu khóa đọc ra là **rỗng**, kẻ tấn công chỉ cần ký HMAC bằng secret rỗng (`""`) — và server verify bằng đúng secret rỗng đó → khớp. Một số biến thể trỏ `kid` tới file tĩnh có nội dung biết trước (vd `/proc/sys/kernel/...`) để dùng làm secret.

### 8.2. SQL injection

```diagram
   header.kid = "x' UNION SELECT 'attacker_secret' -- "

   server làm:  query "SELECT key FROM keys WHERE id='" + kid + "'"
   → trả về 'attacker_secret' do attacker chèn
   → attacker ký HMAC bằng 'attacker_secret' → khớp
```

```diagram
Phòng thủ kid:
   ✅ Validate kid theo allowlist hoặc regex chặt (vd chỉ [A-Za-z0-9-_])
   ✅ Tra khóa bằng parameterized query / map tĩnh, KHÔNG nối chuỗi
   ✅ kid lạ → reject, không "đoán" / không fallback khóa mặc định
```

> [!IMPORTANT]
> `kid` cũng là **dữ liệu do kẻ tấn công kiểm soát**. Đối xử với nó như mọi input không tin cậy khác: validate, không nối thẳng vào path/SQL/command.

---

## 9. Phòng thủ — checklist từng tầng

```diagram
╭──────────────────────────────────────────────────────────────╮
│ TẦNG 1 — Khóa thuật toán (chặn alg:none & confusion)          │
│   ✅ verify(..., { algorithms: ['RS256'] })  tường minh        │
│   ✅ Reject mọi alg ngoài allowlist (kể cả "none"/"None")      │
│                                                                │
│ TẦNG 2 — Tách & ghim khóa                                     │
│   ✅ Mỗi khóa phục vụ đúng một thuật toán                      │
│   ✅ Public key KHÔNG bao giờ bị dùng làm HMAC secret          │
│   ✅ Dùng KeyObject đúng kiểu, không phải chuỗi PEM mơ hồ      │
│                                                                │
│ TẦNG 3 — Nguồn khóa                                           │
│   ✅ Chỉ dùng JWKS URL cố định cấu hình sẵn                    │
│   ✅ BỎ QUA header jku / x5u / jwk khi verify                  │
│                                                                │
│ TẦNG 4 — kid an toàn                                          │
│   ✅ Validate format kid; tra khóa bằng map/param query        │
│   ✅ kid lạ → reject, không fallback                           │
│                                                                │
│ TẦNG 5 — Vận hành                                             │
│   ✅ Cập nhật thư viện JWT (nhiều CVE đã vá)                    │
│   ✅ Log & alert khi gặp alg bất thường                        │
╰──────────────────────────────────────────────────────────────╯
```

---

## 10. Code: vulnerable vs fixed

### 10.1. Vulnerable — để token chọn thuật toán

```javascript
import jwt from 'jsonwebtoken';

// ❌ KHÔNG truyền algorithms → thư viện lấy alg từ header token
function verifyBad(token, publicKey) {
  return jwt.verify(token, publicKey);
  // attacker đổi alg=HS256, ký HMAC bằng publicKey → lọt
  // hoặc alg=none (với thư viện/cấu hình cũ) → lọt
}
```

### 10.2. Fixed — server ghim thuật toán

```javascript
import jwt from 'jsonwebtoken';

// ✅ Ghim algorithms; HS256/none đều bị loại trước khi verify
function verifyGood(token, publicKey) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: 'https://auth.example.com',
    audience: 'api.payments',
  });
}
```

### 10.3. Fixed mạnh hơn — `jose` với key đúng kiểu + JWKS cố định

```javascript
import { createRemoteJWKSet, jwtVerify } from 'jose';

// JWKS CỐ ĐỊNH — không bao giờ lấy từ jku/jwk trong header
const JWKS = createRemoteJWKSet(
  new URL('https://auth.example.com/.well-known/jwks.json')
);

async function verifyStrong(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    algorithms: ['RS256'], // none/HS256 bị loại
    issuer: 'https://auth.example.com',
    audience: 'api.payments',
  });
  // jose dùng KeyObject RSA → public key KHÔNG thể bị ép thành HMAC secret
  return payload;
}
```

---

## 11. Threat model & CVE lịch sử

| Đòn tấn công | Điều kiện cần | Tác hại | Phòng thủ chính |
|--------------|---------------|---------|-----------------|
| `alg:none` | Verifier chấp nhận `none` | Giả token tùy ý, không cần khóa | Allowlist alg, reject `none`/biến thể |
| RS256→HS256 | Verifier lấy alg từ header + dùng public key làm secret | Giả token bằng khóa công khai | Ghim `algorithms`, tách kiểu khóa |
| `jku`/`x5u` | Verifier fetch khóa từ URL trong header | Verify bằng khóa attacker | JWKS cố định, allowlist host |
| `jwk` inject | Verifier dùng `header.jwk` làm khóa | Token self-signed | Bỏ qua `jwk` header |
| `kid` injection | `kid` nối thẳng vào path/SQL | Ép secret biết trước/rỗng | Validate kid, param query |

**Vài CVE kinh điển (đáng đọc để hiểu mức phổ biến):**

```diagram
2015  — Báo cáo "Critical vulnerabilities in JSON Web Token libraries"
        → hàng loạt thư viện chấp nhận alg:none và RS256→HS256 confusion.
CVE-2015-9235  (jsonwebtoken)  — alg confusion / verification bypass
CVE-2016-5431  (python-jwt)    — liên quan xác thực thuật toán
CVE-2016-10555 (jsonwebtoken)  — chấp nhận khóa sai thuật toán
```

> [!NOTE]
> Những lỗ hổng này **không** phải lỗi của RSA hay HMAC. Chúng là lỗi *cách dùng* — API verify quá "thông minh" khi tự suy thuật toán từ token. Bài học còn nguyên giá trị: luôn cập nhật thư viện **và** tự ghim `algorithms`.

---

## 12. Tóm tắt — Cheat sheet

```diagram
╭──────────────────────────────────────────────────────────────╮
│  GỐC RỄ:  header (alg, kid, jku, x5u, jwk) do KẺ TẤN CÔNG điền│
│           → đừng để token quyết định cách nó được verify      │
│                                                                │
│  alg:none      → bỏ chữ ký        → allowlist, reject none     │
│  RS256→HS256   → public key thành → ghim algorithms,          │
│                  HMAC secret         tách kiểu khóa            │
│  jku / x5u     → khóa của attacker → JWKS cố định, bỏ header   │
│  jwk inject    → token self-signed → bỏ qua jwk header         │
│  kid injection → ép secret/rỗng    → validate + param query    │
╰──────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Server quyết định thuật toán, không phải token.** Luôn truyền `algorithms` tường minh; `none` không bao giờ nằm trong danh sách.
2. **Khóa có nguồn gốc do server kiểm soát.** Bỏ qua `jku`/`x5u`/`jwk` trong header; chỉ dùng JWKS cố định. Validate `kid` như input không tin cậy.
3. **Một khóa — một vai trò.** Public key chỉ để verify bất đối xứng, không bao giờ bị tái sử dụng làm HMAC secret. Cập nhật thư viện để hưởng các bản vá.

Đọc kèm: [Chữ ký số JWT — Deep Dive](/internals/signature-deep-dive/) (vì sao HMAC dùng public key lại khớp) và [Token Validation Flow — Deep Dive](/internals/token-validation-deep-dive/) (cổng allowlist & resolve key trong pipeline).
