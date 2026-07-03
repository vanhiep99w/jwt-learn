---
title: "Luồng Tạo JWT — Từ JSON Đến Chuỗi Token"
description: "Mổ xẻ đường ống cơ khí bên trong hàm sign(): từ JSON claims, dựng header, base64url encode, nối bằng dấu chấm, ký bằng HMAC/RSA, đến compact serialization ra chuỗi eyJ... Văn phong đời thường, ẩn dụ nhà máy đóng gói, kèm tính tay từng byte và code Node.js thuần."
---

# Luồng Tạo JWT — Từ JSON Đến Chuỗi Token

## Mục lục

- [Câu chuyện mở đầu: cái gì chạy bên trong `sign()`?](#1-câu-chuyện-mở-đầu-cái-gì-chạy-bên-trong-sign)
- [Nhà máy tạo token — 7 trạm trên một băng chuyền](#2-nhà-máy-tạo-token--7-trạm-trên-một-băng-chuyền)
- [Trạm 1: Nhập liệu — claims, key, thuật toán](#3-trạm-1-nhập-liệu--claims-key-thuật-toán)
- [Trạm 2: Dựng Header — chọn alg, kid, typ](#4-trạm-2-dựng-header--chọn-alg-kid-typ)
- [Trạm 3: Serialize JSON — quy tắc không gian trắng](#5-trạm-3-serialize-json--quy-tắc-không-gian-trắng)
- [Trạm 4: Base64URL encode — sao cho đi được trong URL](#6-trạm-4-base64url-encode--sao-cho-đi-được-trong-url)
- [Trạm 5: Nối Signing Input — phần được đưa vào máy ký](#7-trạm-5-nối-signing-input--phần-được-đưa-vào-máy-ký)
- [Trạm 6: Ký — HMAC, RSA, ECDSA làm gì bên trong](#8-trạm-6-ký--hmac-rsa-ecdsa-làm-gì-bên-trong)
- [Trạm 7: Ghép chuỗi cuối — compact serialization](#9-trạm-7-ghép-chuỗi-cuối--compact-serialization)
- [Tính tay một token từ đầu đến cuối](#10-tính-tay-một-token-từ-đầu-đến-cuối)
- [Code thực chiến — tự dựng token bằng crypto thuần](#11-code-thực-chiến--tự-dựng-token-bằng-crypto-thuần)
- [Anti-patterns khi tạo token](#12-anti-patterns-khi-tạo-token)
- [Tóm tắt — Cheat sheet](#13-tóm-tắt--cheat-sheet)

---

## 1. Câu chuyện mở đầu: cái gì chạy bên trong `sign()`?

Bạn gọi thư viện JWT như nhau:

```js
const token = jwt.sign({ sub: '123', role: 'user' }, SECRET, { algorithm: 'HS256' });
// → "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi...kqM"
```

Một dòng. Ra một chuỗi dài. Bạn *dùng* nó mỗi ngày nhưng có bao giờ tự hỏi: **bên trong cái hàm một dòng đó, máy tính đã làm chính xác những bước gì** để biến `{ sub: '123' }` thành mớ ký tự `eyJ...`?

Đó không phải ma thuật, cũng không phải mã hoá. Đó là một **băng chuyền 7 trạm** — hệt như một nhà máy đóng gói: nguyên liệu (JSON) đi vào, qua từng trạm (serialize → encode → nối → ký → ghép), ra thành phẩm (chuỗi token) ở cuối. Không trạm nào biến đổi dữ liệu theo cách khó hiểu — mỗi bước chỉ làm **đúng một việc cơ bản**, và ghép 7 việc lại thì ra token.

```diagram
   Nguyên liệu                          Thành phẩm
   ┌──────────────┐                     ┌──────────────────────────────┐
   │ { sub: "123" │  ──băng chuyền──▶   │ eyJhbG...J9.eyJzdWIi...J9    │
   │ role: "user" │      7 trạm         │ .kq3F...kM                   │
   │ }            │                     │                              │
   │ + SECRET     │                     │ (chuỗi token sẵn sàng gửi)   │
   │ + alg: HS256 │                     └──────────────────────────────┘
   └──────────────┘
```

> [!IMPORTANT]
> Hiểu băng chuyền này mang lại cho bạn hai thứ: (1) **debug được token hỏng** — biết từng trạm, biết chỗ nào hay hỏng để tìm ngay; (2) **hiểu vì sao token không phải mã hoá** — payload đi qua băng chuyền mà không có trạm nào "giấu" nội dung, chỉ có trạm cuối là *đóng dấu* chống sửa. Ai nói "JWT mã hoá dữ liệu" là chưa nhìn từng trạm.

Trong doc này, ta đi theo nguyên liệu từ trạm đầu vào tới trạm cuối, tính tay ra token thật. Đây là **lăng kính cơ khí** — muốn hiểu *tại sao cấp cho ai, TTL bao lâu* hãy đọc [issuing-token](/lifecycle/issuing-token/), muốn hiểu *bên trong thuật toán ký* hãy đọc [signature-deep-dive](/internals/signature-deep-dive/).

---

## 2. Nhà máy tạo token — 7 trạm trên một băng chuyền

Toàn bộ đường ống tạo token, nhìn từ trên xuống:

```diagram
╭──────────────────────────────────────────────────────────────────────────╮
│                  BĂNG CHUYỀN TẠO JWT — 7 TRẠM                            │
│                                                                          │
│  Nguyên liệu vào:                                                        │
│     claims (JSON)  +  key (secret/private)  +  options (alg, kid)        │
│              │                                                           │
│              ▼                                                           │
│  ┌─ Trạm 1: NHẬP LIỆU ───────────────────────────────────────────────┐   │
│  │  Thu thập claims, key, alg. Validate đầu vào không thiếu gì.      │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 2: DỰNG HEADER ─────────────────────────────────────────────┐   │
│  │  Tạo JSON { "alg": ..., "typ": "JWT", "kid": ... }                │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 3: SERIALIZE JSON ──────────────────────────────────────────┐   │
│  │  header_obj → chuỗi JSON chuẩn, payload → chuỗi JSON chuẩn        │   │
│  │  (KHÔNG có khoảng trắng thừa, key theo thứ tự cố định)            │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 4: BASE64URL ENCODE ────────────────────────────────────────┐   │
│  │  header_json → b64header                                          │   │
│  │  payload_json → b64payload                                        │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 5: NỐI SIGNING INPUT ───────────────────────────────────────┐   │
│  │  signingInput = b64header + "." + b64payload                      │   │
│  │  → đây là phần đưa vào máy ký                                     │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 6: KÝ ──────────────────────────────────────────────────────┐   │
│  │  signature = SIGN(key, signingInput)                              │   │
│  │  (HMAC / RSA-PKCS1 / ECDSA — tùy alg)                             │   │
│  │  → b64signature = base64url(signature)                            │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│  ┌─ Trạm 7: GHÉP CHUỖI CUỐI ─────────────────────────────────────────┐   │
│  │  token = signingInput + "." + b64signature                        │   │
│  │  → "eyJ...J9.eyJ...J9.kq3..."                                     │   │
│  └────────────────────────────────────┬──────────────────────────────┘   │
│                                       ▼                                  │
│                              ✅ TOKEN HOÀN CHỈNH                         │
╰──────────────────────────────────────────────────────────────────────────╯
```

Bảy trạm, đúng bảy việc. Đi từng trạm.

---

## 3. Trạm 1: Nhập liệu — claims, key, thuật toán

Băng chuyền không chạy nếu thiếu nguyên liệu. Trạm đầu chỉ làm việc nhà: **thu thập và kiểm tra** ba thứ.

### 3.1. Ba nguyên liệu bắt buộc

| Nguyên liệu | Là gì | Ví dụ |
|-------------|-------|-------|
| **Claims** | Lời tuyên bố bên trong token (payload) | `{ sub: '123', role: 'user', exp: 1735689600 }` |
| **Key** | Khóa để ký — secret (HMAC) hoặc private key (RSA/ECDSA) | chuỗi bí mật hoặc PEM key |
| **Options** | alg, kid (key ID), typ, expiresAt... | `{ algorithm: 'HS256', keyid: 'key-1' }` |

```diagram
   Nhập: claims  +  key  +  options
            │        │          │
            └────────┴──────────┘
                     │
                     ▼
        Validate: có đủ 3 thứ không?
        ├── thiếu key      → LỖI (không thể ký)
        ├── claims rỗng    → warning (token vô nghĩa)
        └── alg không rõ   → LỖI (không biết thuật toán nào)
```

### 3.2. Quyết định quan trọng nhất trạm này: chọn `alg`

Đây là lựa chọn một lần, định hình toàn bộ các trạm sau — đặc biệt **trạm 6 (ký)**. Bảng chọn nhanh:

| `alg` | Loại | Khi nào dùng |
|-------|------|--------------|
| `HS256` | Đối xứng (1 secret chung) | Đơn service, issuer = verifier |
| `RS256` | Bất đối xứng (RSA) | Nhiều service, verifier chỉ giữ public key |
| `ES256` | Bất đối xứng (ECDSA) | Khi cần token ngắn, mobile/IoT |

<Callout title="Issuer chọn alg, không phải client">
Thuật toán ký là quyết định của **issuer** (bên cấp), định hình cứng trong config — không phải giá trị client gửi lên. Đây là đối trọng của lỗ hổng Algorithm Confusion ở phía verify: bên cấp quyền chủ động, bên verify whitelist. Chi tiết: [hmac-vs-rsa-vs-ecdsa](/cryptography/hmac-vs-rsa-vs-ecdsa/).
</Callout>

---

## 4. Trạm 2: Dựng Header — chọn alg, kid, typ

Header là JSON nhỏ khai báo **metadata**. Trạm này dựng JSON đó từ options.

### 4.1. Mẫu Header sau khi dựng

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key-2024-Q3"
}
```

Ba trường thường gặp:

| Trường | Bắt buộc? | Ý nghĩa |
|--------|-----------|---------|
| `alg` | **Bắt buộc** | Thuật toán ký — đã chọn ở trạm 1 |
| `typ` | Tuỳ chọn (mặc định `JWT`) | Loại token |
| `kid` | Nên có khi rotate key | Key ID — để verifier biết dùng key nào |

### 4.2. Vì sao nên đặt `kid` khi có nhiều key

Khi issuer **xoay vòng key** (key rotation — đổi key theo quý/năm), cùng lúc có nhiều key "sống". Verifier cần biết token này ký bằng key nào. `kid` chính là nhãn dán trên mỗi key:

```diagram
   Issuer có 2 key đang sống:
      key-2024-Q2 (cũ, đang dần retire)
      key-2024-Q3 (mới, active)

   Token mới ký → ghi kid: "key-2024-Q3" vào header
                          │
                          ▼
   Verifier đọc kid → lấy đúng key-2024-Q3 để verify
                     (không phải thử mù quáng từng key)
```

> [!TIP]
> Không có `kid`, verifier phải **thử từng key** trong JWKS xem cái nào verify thành công — vừa chậm vừa nguy hiểm. Issuer đặt `kid` là tốt nghiệp cơ bản khi có từ 2 key trở lên. Xem chi tiết JWKS ở [jwk-and-jwks](/cryptography/jwk-and-jwks/).

---

## 5. Trạm 3: Serialize JSON — quy tắc không gian trắng

Đây là trạm **dễ bị bỏ qua nhất** nhưng lại là nguồn gốc của nhiều bug verify ngầm. Trạm này biến JSON object thành **chuỗi JSON** — và quy tắc định hình chữ ký là: **không khoảng trắng thừa**.

### 5.1. JSON object ≠ chuỗi JSON

Trong code, JSON object là cấu trúc dữ liệu (tree). Nhưng để ký, ta cần **chuỗi byte**. Quá trình serialize (đối tượng → chuỗi) có nhiều cách viết:

```diagram
   JSON object:        { alg: "HS256", typ: "JWT" }

   Serialize cách A (compact):   {"alg":"HS256","typ":"JWT"}        ← JWT dùng cái này
   Serialize cách B (đẹp):       { "alg": "HS256", "typ": "JWT" }   ← có khoảng trắng
   Serialize cách C (sort key):  {"alg":"HS256","typ":"JWT"}        ← key sorted alphabetically
```

Ba chuỗi này **đều hợp lệ về mặt JSON**, nhưng là **ba chuỗi byte khác nhau**. Mà chữ ký tính trên byte → ba chuỗi ra **ba chữ ký khác nhau**.

### 5.2. Quy tắc chuẩn JWT

RFC 7519 yêu cầu JWT serialize JSON theo quy tắc:

- **Không khoảng trắng** giữa key, giá trị, dấu phẩy, dấu hai chấm
- Chuỗi JSON rút gọn (compact): `{"alg":"HS256","typ":"JWT"}`
- Một số thư viện thêm quy tắc **sort key theo alphabet** để deterministic

```diagram
   ✅ ĐÚNG (JWT):    {"alg":"HS256","typ":"JWT"}
                    └ không có dấu cách nào

   ❌ SAI:           { "alg": "HS256", "typ": "JWT" }
                    └ có dấu cách → chuỗi khác → chữ ký khác
```

<Callout type="warn" title="Verifier không re-serialize JSON">
Đây là hệ quả quan trọng nhất: khi verify, server **không tự parse rồi serialize lại JSON** rồi tính chữ ký. Nó dùng **chính xác chuỗi byte** nhận được từ token. Vì nếu re-serialize, có thể ra chuỗi khác (thêm dấu cách, khác thứ tự key) → chữ ký lệch dù token gốc hoàn toàn hợp lệ. Nguyên tắc: **ký trên byte gốc, verify trên byte gốc**.
</Callout>

Đây là lý do trạm 3 quan trọng: quyết định **dạng byte** đi vào trạm 4, và byte đó sẽ đi thẳng vào máy ký ở trạm 6.

---

## 6. Trạm 4: Base64URL encode — sao cho đi được trong URL

Header và Payload sau khi serialize thành chuỗi JSON, phải được **encode** để đi được trong URL, HTTP header, cookie — những nơi có ký tự đặc biệt.

### 6.1. Vì sao không dùng Base64 thường

Base64 thường dùng 3 ký tự gây rắc rối:

| Ký tự Base64 thường | Vấn đề | Base64URL thay bằng |
|---------------------|--------|----------------------|
| `+` | Trong query string `+` = dấu cách | `-` |
| `/` | Là dấu phân cách path URL | `_` |
| `=` | Padding ở cuối — gây rối trong URL | Bỏ luôn |

JWT đi trong header `Authorization: Bearer ...` hoặc query string `?token=...`, nên **bắt buộc** dùng phiên bản URL-safe:

```diagram
   JSON:           {"alg":"HS256","typ":"JWT"}

   Base64 thường:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9=
                                                  ↑ ký tự = gây rối trong URL

   Base64URL:      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
                                                  ↑ bỏ padding, URL-safe
```

### 6.2. Encode ≠ Encrypt (nhắc lại lần thứ N)

Đây là điều quan trọng nhất trạm này: **base64url không phải mã hoá**. Nó chỉ là *cách viết lại* dữ liệu dùng bảng ký tự khác — hoàn toàn **đảo ngược được** trong 1 giây.

```diagram
   {"alg":"HS256"}   ◄──base64url──►   eyJhbGciOiJIUzI1NiJ9
        JSON                                token
   └── ai cũng decode ngược lại được ──┘
```

<Callout type="error" title="Encode không giấu gì cả">
Đừng nhầm base64url với mã hoá. Payload sau khi encode vẫn **ai cũng đọc được** — chỉ cần paste lên jwt.io hoặc gọi `atob()`. Đây là lý do payload JWT là **thông tin công khai**, không bao giờ nhét secret vào. Muốn thực sự giấu nội dung phải dùng [JWE](/cryptography/jwe-encrypted-token/) (encrypt thật), không phải JWT thường.
</Callout>

---

## 7. Trạm 5: Nối Signing Input — phần được đưa vào máy ký

Trạm này ngắn nhưng là **trái tim** của toàn bộ cơ chế chữ ký. Hai phần đã encode được nối bằng dấu chấm, tạo thành một chuỗi gọi là **Signing Input** — chính chuỗi này được đưa vào thuật toán ký.

### 7.1. Công thức Signing Input

```diagram
   signingInput = base64url(header_json) + "." + base64url(payload_json)

   Tức là:
   ┌─────────────┐  .  ┌──────────────┐
   │  b64header  │     │  b64payload  │   ← nối bằng dấu chấm
   └─────────────┘     └──────────────┘
                              │
                              ▼
                    đây là phần được KÝ
                    (không phải JSON gốc!)
```

```diagram
   header_json  = {"alg":"HS256","typ":"JWT"}
   payload_json = {"sub":"123","role":"user"}

   b64(header)  = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
   b64(payload) = eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9

   signingInput = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9"
                  └────────────── chính chuỗi này được đưa vào máy ký ──────────────┘
```

### 7.2. Hai đặc tính quan trọng của Signing Input

**Đặc tính 1 — ký trên byte đã encode, không phải JSON gốc.** Đây là chi tiết hay bị quên. Thuật toán ký không nhận JSON gốc `{"alg":...}`, mà nhận chuỗi base64url. Hệ quả: hai bên (issuer và verifier) đều thao tác trên **cùng một dạng byte**, không cần lo việc re-serialize.

**Đặc tính 2 — dấu chấm là một phần của Signing Input.** Dấu `.` giữa header và payload không chỉ là dấu phân cách để đẹp — nó nằm **trong** Signing Input, được đưa vào máy ký. Nên nếu bỏ dấu chấm hay thêm dấu chấm, chữ ký sẽ lệch.

> [!NOTE]
> Trạm 5 ngắn nhưng quan trọng: nó định nghĩa **chính xác byte nào được ký**. Sai một byte ở đây — một dấu chấm, một chữ trong base64 — là chữ ký đổi hoàn toàn. Đây là lý do verify phải thao tác trên **chính chuỗi byte nhận được**, không re-serialize.

---

## 8. Trạm 6: Ký — HMAC, RSA, ECDSA làm gì bên trong

Đây là trạm **phức tạp nhất** về mặt toán, nhưng ý tưởng đời thường rất đơn giản: **đổ con dấu sáp lên Signing Input, bằng khuôn dấu (key) chỉ issuer có**.

### 8.1. Ý tưởng chung — không cần hiểu toán

```diagram
   Đầu vào trạm 6:
      signingInput (chuỗi byte)
      key          (khóa bí mật)

   Máy ký làm gì:
      SIGN(key, signingInput) → signature (chuỗi byte ngẫu nhiên)

   Đặc tính:
      ✗ Không đảo ngược được:  có signature, không tìm ra key
      ✗ Không giả mạo được:    không có key, không tạo ra signature đúng cho input mới
      ✓ Verify được:           chỉ cần key phù hợp (HMAC: cùng secret; RSA: public key)
```

Giống như **đóng dấu sáp đỏ**: bạn cần **khuôn dấu** (key) để tạo hình in, và mỗi khuôn in ra một hình khác nhau. Không có khuôn, bạn không thể in ra hình giống hệt — dù bạn có nhìn thấy dấu đã in.

### 8.2. Ba dòng máy ký phổ biến

Chi tiết toán học nằm ở [signature-deep-dive](/internals/signature-deep-dive/), nhưng đây là ý tưởng mỗi dòng:

<TypeTable
  type={{
    HS256: {
      description: 'HMAC-SHA256 — dùng chung một secret để ký và verify',
      type: 'symmetric',
      keyForm: '1 chuỗi bí mật (shared secret)',
    },
    RS256: {
      description: 'RSA-PKCS1 — private key ký, public key verify',
      type: 'asymmetric',
      keyForm: 'cặp RSA: private (ký) + public (verify)',
    },
    ES256: {
      description: 'ECDSA — elliptic curve, token ngắn hơn RSA',
      type: 'asymmetric',
      keyForm: 'cặp EC: private (ký) + public (verify)',
    },
  }}
/>

```diagram
   HS256 (đối xứng):                 RS256 (bất đối xứng):
   ┌──────────────────────┐          ┌──────────────────────┐
   │ secret = "abc123..." │          │ private key ──ký──▶  │
   │       │              │          │ public key ──verify─▶│
   │       ├──ký──▶ sig   │          │   (ai cũng có)       │
   │       └──verify──▶ ✓ │          │                      │
   │ (cùng 1 chìa)        │          │ (2 chìa: 1 riêng 1   │
   └──────────────────────┘          │  chung)              │
                                     └──────────────────────┘
```

### 8.3. Sau khi ký — encode chữ ký luôn

Output của máy ký là **byte ngẫu nhiên** (không phải text). Trạm 6 luôn **kết thúc bằng việc base64url** chữ ký đó, để ghép vào chuỗi token ở trạm 7:

```diagram
   SIGN(key, signingInput) → <32 bytes ngẫu nhiên>      (raw signature)
                                    │
                                    ▼
                          base64url(...) → "kq3F...kM"   (b64signature)
```

<Callout title="Chữ ký trông 'ngẫu nhiên' nhưng không phải ngẫu nhiên">
Dù signature decode ra là mớ byte vô nghĩa, nó **hoàn toàn deterministic** — cùng key + cùng input luôn ra cùng signature. Bạn ký lại đúng token sẽ ra đúng chuỗi giống hệt. Tính "ngẫu nhiên" chỉ là do output của hàm băm trông loạn — nhưng nó xác định 100%.
</Callout>

---

## 9. Trạm 7: Ghép chuỗi cuối — compact serialization

Trạm cuối chỉ là công việc dán tem: ghép Signing Input và chữ ký, thêm một dấu chấm — ra token hoàn chỉnh.

### 9.1. Công thức cuối cùng

```diagram
   token = signingInput + "." + base64url(signature)

   Tức là:
   ┌─────────────┐  .  ┌──────────────┐  .  ┌──────────────┐
   │  b64header  │     │  b64payload  │     │  b64signature│
   └─────────────┘     └──────────────┘     └──────────────┘
   └──────── signingInput ────────┘         └─── con dấu ──┘

   = "eyJhbG...J9.eyJzdWIi...J9.kq3F...kM"
```

Hai dấu chấm, ba phần. Đó là token cuối cùng — sẵn sàng gửi đi qua HTTP header, query string, cookie, bất kỳ đâu.

### 9.2. Compact Serialization — vì sao chọn dạng này

Dạng `Header.Payload.Signature` được RFC 7519 gọi là **Compact Serialization** (tuần tự hoá gọn). JWT chọn dạng này thay vì nhét tất cả vào một JSON lớn vì ba lý do:

| Lý do | Giải thích |
|-------|-----------|
| **Ngắn gọn** | Không có key name lặp (`"header":`, `"payload":`) → token nhỏ hơn |
| **URL-safe** | Không cần thêm wrapper JSON, đi thẳng vào URL/header |
| **Phân tách nhanh** | Verifier tách bằng dấu chấm trong 1 phép split, không parse JSON |

```diagram
   Compact (JWT dùng):     eyJ...J9.eyJ...J9.kq3...kM        ← 3 phần, tách bằng dấu chấm
   JSON (không dùng):      {"header":"eyJ..","payload":"eyJ..","sig":"kq.."}  ← dài hơn, phải parse JSON
```

> [!NOTE]
> Dạng compact bắt buộc **không chứa khoảng trắng, không xuống dòng**. Đó là lý do token JWT thường là một chuỗi dài dằng dặc trên một dòng — không phải vì lười format, mà vì spec yêu cầu vậy để đi trong HTTP header.

---

## 10. Tính tay một token từ đầu đến cuối

Giờ áp dụng cả 7 trạm cho một ví dụ cụ thể, tính ra token thật. Cùng dùng ví dụ kinh điển trong RFC 7519.

### 10.1. Nguyên liệu

```json
// Header
{ "alg": "HS256", "typ": "JWT" }

// Payload
{ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }

// Key (secret, ví dụ)
"your-256-bit-secret"
```

### 10.2. Đi qua 7 trạm

```diagram
╭─ Trạm 2-3: Serialize JSON ──────────────────────────────────────────────╮
│  header_json  = {"alg":"HS256","typ":"JWT"}                             │
│  payload_json = {"sub":"1234567890","name":"John Doe","iat":1516239022} │
╰─────────────────────────────────────────────────────────────────────────╯
                              │
                              ▼
╭─ Trạm 4: Base64URL encode ─────────────────────────────────────────────╮
│  b64(header)  = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9                   │
│  b64(payload) = eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw    │
│                 ImlhdCI6MTUxNjIzOTAyMn0                                │
╰────────────────────────────────────────────────────────────────────────╯
                              │
                              ▼
╭─ Trạm 5: Nối Signing Input ────────────────────────────────────────────╮
│  signingInput = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9                   │
│                 .                                                      │
│                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw    │
│                 ImlhdCI6MTUxNjIzOTAyMn0                                │
╰────────────────────────────────────────────────────────────────────────╯
                              │
                              ▼
╭─ Trạm 6: Ký HMAC-SHA256 + encode ──────────────────────────────────────╮
│  signature     = HMAC-SHA256("your-256-bit-secret", signingInput)      │
│                = <32 bytes raw>                                        │
│  b64(signature)= SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c           │
╰────────────────────────────────────────────────────────────────────────╯
                              │
                              ▼
╭─ Trạm 7: Ghép chuỗi cuối ──────────────────────────────────────────────╮
│  token = signingInput + "." + b64(signature)                           │
│                                                                        │
│        = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9                          │
│          .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw          │
│            ImlhdCI6MTUxNjIzOTAyMn0                                     │
│          .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c                  │
╰────────────────────────────────────────────────────────────────────────╯
```

Token này chính là ví dụ mẫu trên jwt.io — bạn có thể paste lên đó để verify.

> [!TIP]
> Thử nghiệm: paste token trên vào jwt.io, đổi `"name":"John Doe"` thành `"name":"Jane Doe"` (chỉ 1 từ), base64url lại payload, giữ nguyên signature. Bạn sẽ thấy signature **invalid** ngay — đó là hiệu ứng avalanche của HMAC: đổi 1 ký tự trong input là hash đổi hoàn toàn. Trạm 6 bảo vệ token khỏi bị sửa.

---

## 11. Code thực chiến — tự dựng token bằng crypto thuần

Thư viện JWT giấu đi cả 7 trạm trong một hàm `sign()`. Để hiểu rõ, dưới đây là code Node.js **tự dựng token từ đầu** — không dùng thư viện JWT, chỉ dùng `crypto` và `Buffer`. Đây là cách tốt nhất để thấy từng trạm chạy ra sao.

### 11.1. HS256 thuần — 7 trạm bằng tay

```typescript
import { createHmac, randomBytes } from 'crypto';

function base64url(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input) : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signJWT_HS256(payload: object, secret: string, kid?: string): string {
  // ── Trạm 1-2: Dựng header
  const header: Record<string, string> = { alg: 'HS256', typ: 'JWT' };
  if (kid) header.kid = kid;

  // ── Trạm 3: Serialize JSON (compact, không dấu cách)
  const headerJson  = JSON.stringify(header);   // {"alg":"HS256","typ":"JWT"}
  const payloadJson = JSON.stringify(payload);  // {"sub":"123",...}

  // ── Trạm 4: Base64URL encode
  const b64Header  = base64url(headerJson);
  const b64Payload = base64url(payloadJson);

  // ── Trạm 5: Nối Signing Input
  const signingInput = `${b64Header}.${b64Payload}`;

  // ── Trạm 6: Ký HMAC-SHA256 + base64url
  const signature = createHmac('sha256', secret).update(signingInput).digest();
  const b64Signature = base64url(signature);

  // ── Trạm 7: Ghép chuỗi cuối
  return `${signingInput}.${b64Signature}`;
}

// Dùng:
const token = signJWT_HS256(
  { sub: '123', role: 'user', iat: 1516239022 },
  'your-256-bit-secret',
);
console.log(token);
// → eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi...
```

### 11.2. RS256 thuần — bất đối xứng

```typescript
import { sign, constants } from 'crypto';
import { readFileSync } from 'fs';

const { RSA_PKCS1_PADDING } = constants;

function signJWT_RS256(payload: object, privateKeyPem: string, kid?: string): string {
  const header: Record<string, string> = { alg: 'RS256', typ: 'JWT' };
  if (kid) header.kid = kid;

  const b64Header  = base64url(JSON.stringify(header));
  const b64Payload = base64url(JSON.stringify(payload));
  const signingInput = `${b64Header}.${b64Payload}`;

  // Khác HS256: dùng RSA private key thay vì HMAC
  // crypto.sign trả về Buffer raw → tự base64url (dsaEncoding chỉ dành cho DSA/ECDSA)
  const sigBuffer = sign(null, Buffer.from(signingInput), {
    key: privateKeyPem,
    padding: RSA_PKCS1_PADDING,         // RS256 = PKCS#1 v1.5
  });
  const signature = base64url(sigBuffer);

  return `${signingInput}.${signature}`;
}

// Dùng:
const privateKey = readFileSync('private.pem', 'utf8');
const token = signJWT_RS256(
  { sub: '123', role: 'admin' },
  privateKey,
  'key-2024-Q3',
);
```

<Callout type="warn" title="Code minh hoạ — production dùng thư viện">
Code trên là để **hiểu từng trạm**, không dùng cho production. Thư viện JWT (`jsonwebtoken`, `jose`) xử lý thêm: validate đầu vào, edge case encoding, constant-time compare, rotation key, các claim chuẩn. Tự viết ký dễ sai ở các chi tiết nhỏ (padding, encoding variant) → tạo ra token mà verifier khác reject. Nguyên tắc: **hiểu ruột máy, nhưng dùng máy có sẵn**.
</Callout>

---

## 12. Anti-patterns khi tạo token

### 12.1. ❌ Nhét thông tin nhạy cảm vào payload

```text
SAI:  jwt.sign({ password: 'mật-khẩu', credit_card: '4242...' }, secret)
      → payload ai cũng decode ra → lộ toàn bộ

ĐÚNG: chỉ nhét thông tin định danh (sub, role, scope). Lấy dữ liệu nhạy cảm từ DB khi cần.
```

### 12.2. ❌ Dùng thuật toán `none`

```text
SAI:  jwt.sign(payload, secret, { algorithm: 'none' })
      → token không có chữ ký, ai cũng giả được

ĐÚNG: luôn ký bằng HS256/RS256/ES256. Cấm 'none' ở config issuer.
```

### 12.3. ❌ Serialize JSON có khoảng trắng

```text
SAI:  JSON.stringify(payload, null, 2)   ← đẹp nhưng ra chuỗi khác
      → chữ ký lệch, verifier (dùng thư viện) reject

ĐÚNG: JSON.stringify(payload)            ← compact, không dấu cách
```

### 12.4. ❌ Không đặt `kid` khi có nhiều key

```text
SAI:  ký bằng key mới nhưng header không ghi kid
      → verifier không biết dùng key nào, phải thử từng key (chậm, nguy hiểm)

ĐÚNG: luôn ghi kid vào header khi issuer có > 1 key đang sống
```

### 12.5. ❌ Re-serialize lại khi verify

```text
SAI:  parse(token).decode → JSON.stringify lại → tính chữ ký
      → có thể ra chuỗi khác (thêm dấu cách) → reject oan token hợp lệ

ĐÚNG: verify trên CHÍNH XÁC chuỗi byte nhận được từ token, không re-serialize
```

### 12.6. ❌ Đặt TTL quá dài

```text
SAI:  access token exp = 30 ngày
      → token bị lộ nằm ở đâu bao lâu thì kẻ tấn công dùng được bấy lâu

ĐÚNG: access token 5-15 phút, refresh token lâu hơn nhưng có rotation
```

---

## 13. Tóm tắt — Cheat sheet

**Luồng tạo JWT = băng chuyền 7 trạm:**

```diagram
╭────────────────────────────────────────────────────────────────────╮
│              JWT CREATION CHEAT SHEET — 7 TRẠM                     │
│                                                                    │
│  1. NHẬP LIỆU:    thu thập claims + key + options (alg, kid)       │
│  2. DỰNG HEADER:  { "alg":..., "typ":"JWT", "kid":... }            │
│  3. SERIALIZE:    JSON compact — KHÔNG khoảng trắng                │
│  4. BASE64URL:    b64(header), b64(payload) — URL-safe             │
│  5. NỐI:          signingInput = b64header + "." + b64payload      │
│  6. KÝ:           signature = SIGN(key, signingInput)              │
│                  → b64(signature)                                  │
│  7. GHÉP:         token = signingInput + "." + b64(signature)      │
│                                                                    │
│  Kết quả: "eyJ...J9.eyJ...J9.kq3..."                               │
╰────────────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc cốt lõi:**

| # | Nguyên tắc | Vì sao |
|---|-----------|--------|
| 1 | **Ký trên base64url, không phải JSON gốc** | Hai bên cùng thao tác trên một dạng byte → không lo re-serialize |
| 2 | **JSON serialize compact, không khoảng trắng** | Sai 1 dấu cách → chuỗi khác → chữ ký khác |
| 3 | **Signature không mã hoá, chỉ đóng dấu** | Payload vẫn ai cũng đọc; muốn giấu phải dùng JWE |

**Bảng tra nhanh từng trạm:**

| Trạm | Việc | Input → Output | Dễ sai chỗ nào |
|------|------|----------------|----------------|
| 1 | Nhập liệu | (thu thập) → claims+key+alg | Thiếu key, alg không rõ |
| 2 | Dựng header | options → header JSON | Quên `kid` khi nhiều key |
| 3 | Serialize | JSON obj → chuỗi | Thêm dấu cách |
| 4 | Base64URL | JSON → b64 | Dùng base64 thường (có `+/=`) |
| 5 | Nối signing input | b64h + "." + b64p | Quên dấu chấm |
| 6 | Ký | SIGN(key, input) → sig | Dùng thuật toán sai/none |
| 7 | Ghép chuỗi | input + "." + b64sig | Thêm khoảng trắng/xuống dòng |

**Bốn câu hỏi thường gặp:**

- **Token JWT được mã hoá không?** — KHÔNG. Chỉ base64url (encode) + ký. Payload ai cũng đọc.
- **Vì sao đổi 1 ký tự payload là token hỏng?** — Vì chữ ký tính trên toàn bộ signing input, đổi 1 bit → HMAC/hash đổi hoàn toàn (avalanche).
- **Issuer và verifier có cần cùng thuật toán không?** — Có. Header ghi `alg`, verifier phải dùng đúng alg đó (trong whitelist).
- **Có thể tạo token mà không cần key không?** — Có, nếu `alg:none`, nhưng đó là token "trần" — bất kỳ ai cũng giả được, **cấm dùng production**.

---

## Tài liệu tham khảo

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — định nghĩa compact serialization.
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) — định nghĩa Signing Input và quá trình ký.
- [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) — định dạng key và `kid`.
- Trong repo: [issuing-token](/lifecycle/issuing-token/) (quyết định cấp), [signature-deep-dive](/internals/signature-deep-dive/) (toán ký), [token-validation-flow](/internals/token-validation-flow/) (đầu bên kia — verify).
