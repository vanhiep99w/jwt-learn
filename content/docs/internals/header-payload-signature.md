---
title: "Header, Payload, Signature — Ba Phần, Ba Vai Trò"
description: "Hiểu cấu trúc JWT qua lăng kính niềm tin: Header khai báo thuật toán, Payload tuyên bố thông tin, Signature đóng dấu chứng minh không bị giả. Văn phong đời thường, analogy phong bì & con dấu sáp, kèm bảng phân quyền ai đọc được phần nào và hai sai lầm chết người khi đọc JWT."
---

# Header, Payload, Signature — Ba Phần, Ba Vai Trò

## Mục lục

- [Câu chuyện mở đầu: một phong bì và ba câu hỏi](#1-câu-chuyện-mở-đầu-một-phong-bì-và-ba-câu-hỏi)
- [Nhìn từ xa: ba phần, hai dấu chấm, một niềm tin](#2-nhìn-từ-xa-ba-phần-hai-dấu-chấm-một-niềm-tin)
- [Header — phần đầu: "Tôi được đóng dấu kiểu này"](#3-header--phần-đầu-tôi-được-đóng-dấu-kiểu-này)
- [Payload — phần giữa: "Đây là lời tôi tuyên bố"](#4-payload--phần-giữa-đây-là-lời-tôi-tuyên-bố)
- [Signature — phần cuối: "Con dấu chứng minh tôi chưa bị ai sửa"](#5-signature--phần-cuối-con-dấu-chứng-minh-tôi-chưa-bị-ai-sửa)
- [Ba phần buộc chặt nhau — rút một phần là hỏng cả](#6-ba-phần-buộc-chặt-nhau--rút-một-phần-là-hỏng-cả)
- [Ai đọc được phần nào — bảng phân quyền](#7-ai-đọc-được-phần-nào--bảng-phân-quyền)
- [Hai sai lầm chết người khi hiểu cấu trúc JWT](#8-hai-sai-lầm-chết-người-khi-hiểu-cấu-trúc-jwt)
- [Khi nào cần đi sâu hơn](#9-khi-nào-cần-đi-sâu-hơn)
- [Tóm tắt — Cheat sheet](#10-tóm-tắt--cheat-sheet)

---

## 1. Câu chuyện mở đầu: một phong bì và ba câu hỏi

Bạn vừa đăng nhập vào một trang web. Server trả về một chuỗi token dài ngoằng, bạn paste nó vào header `Authorization` của mọi request sau đó. Một ngày, bạn mở DevTools lên, thấy nó nằm đó:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciIsImV4cCI6MTczNTY4OTYwMH0.kq3F...w5c
```

Trông như một mớ ký tự vô nghĩa. Nhưng thực ra nó giống **một phong bì thư được đóng dấu sáp** — và cả phong bì đó chỉ trả lời **ba câu hỏi**:

```diagram
   ┌─────────────────────────────────────────────────────────┐
   │                  MỘT JWT = MỘT PHONG BÌ                 │
   │                                                         │
   │   ① Phong bì ghi:    "Đóng dấu bằng sáp đỏ (HS256)"    │  ← HEADER
   │   ② Bên trong:       "Tôi là user 123, quyền user"     │  ← PAYLOAD
   │   ③ Nắp phong bì:    dấu sáp đỏ của người gửi          │  ← SIGNATURE
   │                                                         │
   │   Câu hỏi 1: Phong bì này được đóng kiểu gì?            │
   │   Câu hỏi 2: Nội dung bên trong nói gì?                 │
   │   Câu hỏi 3: Có ai đã lén mở và sửa bên trong không?    │
   └─────────────────────────────────────────────────────────┘
```

Đó chính là Header, Payload và Signature — ba phần của JWT, chia bằng **hai dấu chấm**. Mỗi phần trả lời đúng **một** trong ba câu hỏi trên. Bạn chỉ cần nhớ ánh xạ này là hiểu được mọi JWT trên đời:

| Câu hỏi | Phần JWT | Ẩn dụ phong bì |
|---------|----------|----------------|
| Đóng dấu kiểu gì? | **Header** | Dòng chữ ngoài phong bì |
| Nội dung là gì? | **Payload** | Lá thư bên trong |
| Có bị giả không? | **Signature** | Con dấu sáp trên nắp |

> [!IMPORTANT]
> Toàn bộ sự an toàn của JWT nằm ở chỗ **ba phần này phải khớp nhau**. Header khai báo đóng dấu thế nào, signature phải thật sự đóng đúng kiểu đó, và phải được tính từ đúng nội dung payload. Kẻ tấn công có thể đọc cả ba phần — nhưng **không thể sửa một phần mà không làm vỡ hai phần còn lại**. Đó là toàn bộ cái "ma thuật" của JWT.

Trong doc này, ta sẽ đi từng phần: nó chứa gì, ai tạo ra nó, ai đọc được nó, và vì sao hiểu sai vai trò của nó dẫn tới những lỗ hổng bảo mật kinh điển. Đây là **lăng kính vai trò & niềm tin** — muốn mổ xẻ từng byte (base64url, signing input) hãy đọc [jwt-structure](/fundamentals/jwt-structure/), muốn hiểu thuật toán ký bên trong con dấu hãy đọc [signature-deep-dive](/internals/signature-deep-dive/).

---

## 2. Nhìn từ xa: ba phần, hai dấu chấm, một niềm tin

Mọi JWT (dạng compact — dạng phổ biến nhất) đều có đúng một hình thái:

```text
Header.Payload.Signature
   │      │        │
   │      │        └── Con dấu: chứng minh token không bị giả
   │      └─────────── Lời tuyên bố: user là ai, quyền gì, hết hạn khi nào
   └────────────────── Khai báo: đây là JWT, ký bằng thuật toán nào
```

Hai dấu chấm `.` chia chuỗi thành đúng ba mảnh. Quy tắc này cố định — không phải quy ước đẹp đẽ mà là **yêu cầu kỹ thuật** cứng trong RFC 7519:

```diagram
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Phần 1 (Header)
  .
   eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9   ← Phần 2 (Payload)
  .
   kq3F...w5c                             ← Phần 3 (Signature)
```

<Callout title="Đếm dấu chấm để nhận biết JWT">
Mẹo nhanh khi debug: **một JWT hợp lệ luôn có đúng 2 dấu chấm, chia ra 3 phần**. Nhìn thấy 1 dấu chấm → không phải JWT compact. Nhìn thấy 3 dấu chấm → có thể là JWT dạng khác (JWE có 5 phần, 4 dấu chấm). Đếm dấu chấm là cách phân biệt JWS (token thường) và JWE (token mã hoá) nhanh nhất bằng mắt thường.
</Callout>

### 2.1. Mỗi phần là một "JSON đã được đóng gói", không phải text ngẫu nhiên

Đừng bị mớ ký tự `eyJ...` đánh lừa. Hai phần đầu (Header và Payload) thực chất chỉ là **JSON bình thường, được encode base64url** để an toàn khi truyền trong URL/header:

```diagram
   Header (JSON gốc)                        Payload (JSON gốc)
   ┌─────────────────────────┐              ┌─────────────────────────────────┐
   │ {                       │              │ {                               │
   │   "alg": "HS256",       │  ──encode──▶ │   "sub": "123",                 │
   │   "typ": "JWT"          │   base64url  │   "role": "user",               │
   │ }                       │              │   "exp": 1735689600             │
   └─────────────────────────┘              │ }                               │
        = eyJhbGci...IkpXVCJ9               └─────────────────────────────────┘
                                                  = eyJzdWIi...J9
```

Bạn có thể decode ngược lại JSON trong 1 giây — paste lên jwt.io là thấy ngay. Encode **không phải mã hoá**. Encode chỉ là cách viết lại dữ liệu sao cho **không chứa ký tự gây rối** (`+`, `/`, `=`) khi đi trong URL hoặc HTTP header.

> [!NOTE]
> Phần Signature khác hai phần đầu: nó **không phải JSON**, mà là chuỗi byte ngẫu nhiên (output của thuật toán ký) được base64url lại. Decode nó ra bạn chỉ thấy một mớ byte vô nghĩa — đó là dấu hiệu của chữ ký: không có ý nghĩa để "đọc", chỉ có ý nghĩa để "kiểm tra".

---

## 3. Header — phần đầu: "Tôi được đóng dấu kiểu này"

Header là phần **ngắn nhất**, nhưng lại **nguy hiểm nhất nếu bị hiểu sai**. Nó là một JSON nhỏ chỉ khai báo **hai thứ chính**: đây là loại token gì, và được ký bằng thuật toán nào.

### 3.1. Mẫu Header phổ biến nhất

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Hiểu bằng lời đời thường: *"Tôi là một JWT, và tôi được ký bằng HMAC-SHA256."*

Đó là 99% Header bạn gặp trong thực tế. Hai trường:

| Trường | Ý nghĩa | Giá trị hay gặp |
|--------|---------|-----------------|
| `alg` | Thuật toán ký — **kiểu con dấu** | `HS256`, `RS256`, `ES256`, `none` |
| `typ` | Loại token | `JWT` (đôi khi bỏ qua, mặc định JWT) |

Đôi khi có thêm `kid` (key ID — *"đóng bằng cái dấu số mấy"*):

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-Q3"
}
```

### 3.2. Vì sao Header nguy hiểm: nó tự khai báo thuật toán

Đây là điểm **rất dễ bỏ qua** và là nguồn gốc của cả họ lỗ hổng JWT: **thuật toán ghi trong Header do người tạo token tự khai**. Tức là cái phong bì **tự viết ngoài vỏ** *"tôi được đóng dấu bằng sáp đỏ"* — và nếu server **tin lời phong bì nói** mà không kiểm tra thật, kẻ tấn công chỉ cần đổi chữ trên vỏ phong bì.

```diagram
   Kẻ tấn công đổi Header:
   ┌────────────────────────┐        ┌────────────────────────┐
   │ { "alg": "RS256" }     │  ───▶  │ { "alg": "none" }      │
   │ ("tôi ký bằng RSA")    │        │ ("tôi KHÔNG ký đâu")   │
   └────────────────────────┘        └────────────────────────┘
            │                                  │
            ▼                                  ▼
   Server: "À RSA, lấy public           Server (BUG): "À alg:none,
   key ra verify..."                     bỏ qua chữ ký nhé..."  ← 💀
```

Lỗi kinh điển `alg: none` chính là vậy: kẻ tấn công sửa Header thành *"không cần kiểm tra chữ ký"*, xoá luôn phần Signature, và nếu server tin Header mù quáng → chấp nhận mọi token giả. Toàn bộ family lỗi **Algorithm Confusion** đều bắt nguồn từ việc tin Header.

<Callout type="warn" title="Header KHÔNG phải lời tuyên bố đáng tin">
Header là **dữ liệu do client gửi**, giống mọi thứ client gửi khác. Nguyên tắc sống còn: server phải có **danh sách thuật toán cho phép (whitelist)** riêng, không bao giờ tin `alg` trong Header. Nếu Header nói `alg: none` mà server chỉ chấp nhận `RS256` → reject ngay. Xem chi tiết: [algorithm-confusion](/security/algorithm-confusion/).
</Callout>

### 3.3. Header trong ẩn dụ phong bì

> Phong bì có một dòng ghi ngoài vỏ: *"Đã đóng dấu sáp HS256"*. Dòng chữ đó **không phải con dấu** — nó chỉ là lời *tự khai*. Kẻ nào cũng có thể viết dòng chữ gì cũng được ngoài vỏ. Con dấu thật nằm ở phần 3, và chỉ nó mới đáng tin.

---

## 4. Payload — phần giữa: "Đây là lời tôi tuyên bố"

Payload là **phần dài nhất** và là phần bạn quan tâm nhất khi debug — vì nó chứa **thông tin thật sự**: user là ai, có quyền gì, token sống bao lâu.

### 4.1. Payload chứa gì

Payload là một JSON chứa các **claim** — từng cặp key-value là một "lời tuyên bố" về session này:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "user",
  "iat": 1516239022,
  "exp": 1735689600
}
```

Đọc bằng lời đời thường: *"Tôi tuyên bố: tôi là user ID 1234567890, tên John Doe, quyền user, phát hành lúc mốc 1516239022, hết hạn lúc mốc 1735689600."*

Mỗi dòng là một tuyên bố. Có ba loại claim:

| Loại | Nghĩa | Ví dụ |
|------|-------|-------|
| **Registered** | Chuẩn RFC, ai cũng hiểu | `sub` (subject), `exp` (hết hạn), `iat` (phát hành), `iss`, `aud` |
| **Public** | Đặt tên do bạn, đăng ký tránh trùng | `https://myapp.com/role` |
| **Private** | Đặt tên tuỳ thích, dùng nội bộ | `role`, `tenant_id`, `plan` |

Chi tiết từng claim nằm ở [time-based-claims](/internals/time-based-claims/) và [audience-issuer-subject](/internals/audience-issuer-subject/). Ở đây chỉ cần nắm vai trò.

### 4.2. Nguyên tắc vàng của Payload: ai cũng đọc được

Đây là điều **nhiều developer không biết** và là nguyên nhân của rất nhiều lộ dữ liệu:

<Callout type="error" title="Payload KHÔNG được mã hoá">
Payload chỉ được **encode** (base64url), không được **encrypt**. Bất kỳ ai cầm token — dù là kẻ tấn công bắt được trên đường truyền — đều decode ra JSON rõ ràng trong 1 giây. **Tuyệt đối không nhét secret, mật khẩu, thông tin nhạy cảm (PII) vào payload.**
</Callout>

```diagram
   Bạn tưởng:                          Thực tế:
   ┌────────────────────┐              ┌────────────────────┐
   │ Payload đã "giấu"  │              │ Payload ai cũng    │
   │ thông tin rồi!     │     ≠        │ đọc được bằng mắt  │
   │ (giống mã hoá)     │              │ thường, chỉ cần    │
   └────────────────────┘              │ paste lên jwt.io   │
                                       └────────────────────┘
```

Hãy nghĩ payload như **mặt trước của phong bì** — dòng địa chỉ ghi rõ ràng ngoài vỏ, không giấu giếm gì cả. Bất kỳ ai cầm phong bì đều đọc được. Nếu muốn **giấu** nội dung bên trong (mã hoá thật), phải dùng **JWE** (JSON Web Encryption) — dạng token 5 phần, không phải JWT thường. Xem: [jwe-encrypted-token](/cryptography/jwe-encrypted-token/).

### 4.3. Payload chỉ đáng tin SAU KHI chữ ký xác nhận

Đây là sự phân biệt quan trọng nhất về **thứ tự niềm tin**:

```diagram
   SAI:                           ĐÚNG:
   ┌───────────────────┐          ┌───────────────────┐
   │ 1. Đọc payload    │          │ 1. Verify chữ ký  │
   │ 2. Tin payload    │   ──▶    │ 2. Nếu OK,        │
   │ 3. (quên chữ ký)  │          │    MỚI tin payload│
   └───────────────────┘          └───────────────────┘
   → kẻ tấn công sửa            → token giả bị reject
     role: admin, vào thẳng       ngay từ bước 1
     admin panel  💀
```

Payload nói gì cũng được — cho đến khi **con dấu (Signature) xác nhận** rằng chưa ai sửa payload, thì payload mới đáng tin. Đó là lý do trong luồng validate, bước verify chữ ký luôn chạy **trước** bước đọc claims.

> [!TIP]
> Khi debug, jwt.io verify chữ ký cho bạn nên payload đẹp đẽ hiện ra — nhưng đừng quên đó là vì **chữ ký đã khớp**. Trên server thật, nếu chữ ký không khớp thì payload (dù bạn có decode ra) **phải bị vứt bỏ**, không được dùng để ra quyết định.

---

## 5. Signature — phần cuối: "Con dấu chứng minh tôi chưa bị ai sửa"

Signature là phần **quan trọng nhất** nhưng lại là phần **khó hiểu nhất** — vì nó không phải text bạn "đọc" được mà là một mớ byte chỉ để "kiểm tra".

### 5.1. Signature giải quyết đúng một câu hỏi

Trong ba câu hỏi của phong bì:

```diagram
   ① Đóng dấu kiểu gì?     → Header trả lời
   ② Nội dung là gì?       → Payload trả lời
   ③ Có bị giả không?      → Signature trả lời  ★ CỐT LÕI
```

Signature trả lời câu hỏi số 3, và **chỉ câu hỏi số 3**. Nó không mã hoá, không giấu nội dung, không mang thông tin user — nó chỉ là **bằng chứng toán học** rằng Header và Payload đi kèm chính là bản gốc do người giữ khóa tạo ra, chưa bị thay đổi dù chỉ một bit.

### 5.2. Con dấu sáp hoạt động thế nào (nguyên lý)

Bạn không cần hiểu toán để nắm ý. Hãy nghĩ Signature như **con dấu sáp** được đổ lên nắp phong bì:

```diagram
   Bước 1: Người gửi bóp lá thư (Header + Payload) thành một mảnh
   Bước 2: Nhúng vào sáp đặc (khóa bí mật K)
   Bước 3: Đổ sáp đó lên nắp phong bì  →  tạo thành con dấu

   ┌──────────────────────────────────────────────────┐
   │  Phong bì:    [Header][Payload]                  │
   │  Nắp phong bì:  ●●● (con dấu sáp đỏ = Signature) │
   └──────────────────────────────────────────────────┘

   Người nhận kiểm tra:
   - Bóp lại lá thư cùng cách  →  ra cùng một mảnh
   - So sánh với con dấu trên nắp
   - Khớp  →  thư chưa bị ai đụng vào  ✅
   - Khác  →  ai đó đã lén mở và sửa  ❌
```

Điểm mấu chốt: **khóa bí mật K** là thứ duy nhất có thể tạo ra con dấu đúng. Kẻ tấn công biết hết thuật toán, biết cả Header và Payload, nhưng **không có K** thì không thể đúc lại được con dấu giống hệt. Đó là toàn bộ cơ chế an toàn.

<Callout title="Hai loại con dấu: đối xứng và bất đối xứng">
Tùy `alg` trong Header, có hai kiểu đóng dấu:

- **Đối xứng (HS256)** — cùng một **mật mã** dùng để đóng lẫn kiểm. Giống ổ khoá nhà: chìa khoá mở cũng là chìa khoá khoá. Đơn giản nhưng cả hai bên phải giữ chung một bí mật.
- **Bất đối xứng (RS256, ES256)** — có **khóa riêng** để đóng và **khóa công khai** để kiểm. Giống chữ ký: chỉ bạn mới ký được, nhưng ai cũng có thể kiểm tra chữ ký của bạn bằng bản mẫu công khai.

So sánh chi tiết từng thuật toán: [hmac-vs-rsa-vs-ecdsa](/cryptography/hmac-vs-rsa-vs-ecdsa/).
</Callout>

### 5.3. Vì sao đổi 1 chữ cái trong Payload làm Signature "bét"

Con dấu sáp có một đặc tính toán học: nó được tính từ **toàn bộ** nội dung Header + Payload. Đổi đúng một ký tự — ví dụ `"role":"user"` thành `"role":"admin"` — là con dấu cũ lập tức **không khớp nữa**.

```diagram
   Payload gốc:        { "role": "user" }
   Con dấu (sig):      kq3F...w5c   ✅ khớp

   Kẻ tấn công sửa:    { "role": "admin" }
   Đóng lại dấu cũ:    kq3F...w5c   ❌ KHÔNG khớp nữa
                       └─ server bóp lại ra chữ khác → reject
```

Đó là hiệu ứng **avalanche** của hàm băm: đổi 1 bit đầu vào, đầu ra đổi hoàn toàn. Đây là lý do payload **đọc được nhưng không sửa được** — và là ranh giới sống còn giữa "JWT an toàn" và "JWT vô dụng".

> [!IMPORTANT]
> Signature bảo vệ **tính toàn vẹn** (integrity) — *"không ai sửa"* — và **nguồn gốc** (authenticity) — *"chỉ người giữ khóa mới tạo được"*. Nó **không** bảo vệ **bí mật** (confidentiality). Đây là ba khái niệm an ninh khác nhau, đừng đánh đồng. Muốn giấu nội dung phải **encrypt** (JWE), ký chỉ chứng minh *"chưa bị đụng chạm"*.

### 5.4. Signature trong ẩn dụ phong bì

> Signature là **con dấu sáp đỏ** trên nắp phong bì. Kẻ trộm có thể đọc lá thư bên trong (payload), có thể đọc dòng chữ ngoài vỏ (header), nhưng **không thể mở phong bì ra sửa rồi đóng lại** mà dấu sáp vẫn y nguyên — vì chỉ người giữ khuôn dấu (khóa bí mật) mới đổ được dấu giống hệt.

---

## 6. Ba phần buộc chặt nhau — rút một phần là hỏng cả

Hiểu từng phần thôi chưa đủ. Sức mạnh của JWT nằm ở chỗ **ba phần liên kết toán học** với nhau — rút một phần, hai phần kia mất ý nghĩa.

### 6.1. Signature được tính từ Header + Payload

Công thức (đã đơn giản hoá):

```diagram
   SigningInput = base64url(Header) + "." + base64url(Payload)
   Signature    = SIGN( khóa bí mật, SigningInput )
   Token        = SigningInput + "." + base64url(Signature)
```

Đọc đời thường: con dấu sáp được đổ lên **chính cái phong bì đã đóng gói sẵn** (Header + Payload đã encode), chứ không đổ lên JSON gốc. Nghĩa là:

- Đổi Header → Signature phải tính lại
- Đổi Payload → Signature phải tính lại
- Signature chỉ đúng cho **đúng cặp Header-Payload đi kèm**

### 6.2. Hệ quả: không thể "đắp" phần này sang phần khác

Một hệ quả rất quan trọng khi hiểu sâu: bạn **không thể** lấy Signature của token A rồi ghép vào Header+Payload của token B. Mỗi Signature chỉ "khớp" đúng một cặp Header-Payload duy nhất.

```diagram
   Token A (user thường):
   HeaderA . PayloadA . SigA   ← SigA chỉ hợp lệ cho (HeaderA, PayloadA)

   Token B (admin):
   HeaderB . PayloadB . SigB   ← SigB chỉ hợp lệ cho (HeaderB, PayloadB)

   Kẻ tấn công cố ghép:  HeaderB . PayloadB . SigA   ← ❌ SigA không khớp (HeaderB, PayloadB)
```

Đây là lý do JWT chống được kiểu tấn công "đắp chữ ký" — và cũng là lý do **phải verify trên đúng chuỗi byte nhận được**, không re-serialize JSON khi kiểm tra (chỉ một khoảng trắng khác là base64url khác → chữ ký lệch).

### 6.3. Vì sao thiếu Signature (alg: none) là thảm hoạ

Bảng tổng kết "rút một phần":

| Phần bị thiếu/đổi | Hệ quả | Ai gánh |
|-------------------|--------|---------|
| Đổi Header (sửa `alg`) | Server có thể bị lừa dùng thuật toán sai | Server (phải whitelist `alg`) |
| Đổi Payload (sửa claim) | Signature không khớp → reject (nếu verify đúng) | Chữ ký tự bảo vệ |
| Bỏ Signature (`alg:none`) | **Không còn gì chứng minh nguồn** → tin_payload = tự sát | Server (phải cấm `none`) |

<Callout type="error" title="alg:none = phong bì KHÔNG có con dấu">
`alg: none` nghĩa là token tự khai *"tôi không có chữ ký"*. RFC cho phép tồn tại để test, nhưng **mọi production phải cấm tuyệt đối**. Một token `alg:none` chính là phong bì không có con dấu — bất kỳ ai cũng có thể in ra, ghi bên trong `"role":"admin"`, gửi đi. Nếu server chấp nhận → hệ thống bị chiếm quyền ngay. Đây là lỗi top-1 trong [common-vulnerabilities](/security/common-vulnerabilities/).
</Callout>

---

## 7. Ai đọc được phần nào — bảng phân quyền

Một câu hỏi thực tế: trong ba phần, **ai có quyền gì**? Bảng này là bản đồ niềm tin mà bạn nên nhớ:

| Phần | Client (gửi token) | Kẻ tấn công (bắt được token) | Server (verify) |
|------|--------------------|------------------------------|-----------------|
| **Header** | Đọc được (chỉ encode) | Đọc được | Đọc + **kiểm tra alg có trong whitelist** |
| **Payload** | Đọc được (chỉ encode) | **Đọc được** ⚠️ | Đọc **chỉ sau khi** chữ ký khớp |
| **Signature** | Không "đọc" được (byte ngẫu nhiên) | Không tạo lại được nếu thiếu khóa | **Verify** (cần khóa) |

Hai cột đầu giống nhau: **ai cầm token cũng đọc được Header và Payload**. Điểm khác biệt nằm ở cột cuối — server có khóa, nên **kiểm chứng được** chứ không chỉ đọc.

```diagram
   Kẻ tấn công có thể:                 Kẻ tấn công KHÔNG thể:
   ┌────────────────────────┐          ┌────────────────────────┐
   │ ✓ Đọc payload          │          │ ✗ Sửa payload mà chữ   │
   │ ✓ Đọc header           │          │   ký vẫn khớp          │
   │ ✓ Sửa payload (bằng    │          │ ✗ Tạo token mới hợp lệ │
   │   tay, jwt.io)         │          │   mà không có khóa     │
   │ ✗ Nhưng sửa xong gửi   │          │ ✗ Giả mạo nguồn phát   │
   │   → chữ ký lệch → 401  │          │   hành                 │
   └────────────────────────┘          └────────────────────────┘
```

> [!TIP]
> Từ bảng này rút ra **hai nguyên tắc viết code** bất di bất dịch: (1) Payload là **thông tin công khai** — đừng nhét bí mật vào; (2) Signature là **cửa ải duy nhất** — phải verify trước khi tin bất kỳ điều gì trong payload. Hai nguyên tắc này vi phạm một là mở lỗ hổng.

---

## 8. Hai sai lầm chết người khi hiểu cấu trúc JWT

Gom lại, toàn bộ sự hiểu lầm về cấu trúc JWT dẫn tới bảo mật kém đều xoay quanh **hai sai lầm**. Nếu tránh được hai điều này, bạn đã vô hiệu hoá phần lớn lỗ hổng JWT kinh điển.

### 8.1. Sai lầm 1: tưởng Payload được mã hoá

```diagram
   Tưởng:                         Thực tế:
   Payload = "mã hoá"              Payload = "encode" (base64url)
   → nhét secret vào yên tâm       → ai cũng decode ra JSON rõ
   → tin payload chưa verify       → phải verify chữ ký TRƯỚC
```

Triệu chứng: code đọc `req.user.role` trực tiếp từ token **chưa verify**, hoặc nhét `password`, `credit_card` vào payload. Hậu quả: lộ dữ liệu, hoặc kẻ tấn công tự sửa payload.

**Khắc phục:**

- Payload = **phong bì mặt trước**, thông tin công khai.
- Cần giấu → dùng **JWE** (encrypt), không phải JWT thường.
- Verify chữ ký **xong** mới tin payload.

### 8.2. Sai lầm 2: tin Header quyết định thuật toán

```diagram
   Tưởng:                          Thực tế:
   alg trong Header = sự thật       alg trong Header = lời TỰ KHAI
   → server theo alg đó verify      → server phải whitelist alg riêng
   → alg:none thì bỏ qua chữ ký     → alg:none → reject tuyệt đối
```

Triệu chứng: server đọc `alg` từ Header rồi dispatch theo đúng thuật toán đó, không có whitelist. Hậu quả: kẻ tấn công đổi `alg` để lừa server bỏ qua chữ ký (Algorithm Confusion, `alg:none`, RS256→HS256 confusion).

**Khắc phục:**

- Server giữ danh sách thuật toán cho phép (vd chỉ `RS256`).
- `alg` trong Header chỉ dùng để **xác nhận**, nếu không khớp whitelist → reject.
- Cấm tuyệt đối `none` ở tầng config, không tin cờ báo từ token.

<Callout type="warn" title="Quy tắc chung: dữ liệu trong token đều là lời tuyên bố, chỉ chữ ký là bằng chứng">
Cả Header lẫn Payload đều là **lời tuyên bố** do người tạo token viết ra — giống mọi input từ client, đều phải bị nghi ngờ. **Chữ ký là bằng chứng toán học duy nhất** xác nhận lời tuyên bố đó là thật. Tạm bỏ qua chữ ký = tin mọi lời tuyên bố = tự sát bảo mật.
</Callout>

---

## 9. Khi nào cần đi sâu hơn

Doc này giải thích cấu trúc JWT ở **lăng kính vai trò & niềm tin** — đủ để bạn hiểu ba phần là gì, ai đọc được gì, vì sao hiểu sai là nguy hiểm. Khi cần độ sâu kỹ thuật hơn, vào các doc chuyên biệt:

<Cards>
  <Card href="/fundamentals/jwt-structure/" title="Cấu trúc JWT — Deep Dive">
    Mổ xẻ từng byte: base64url encode hoạt động thế nào, compact serialization, decode thủ công, vì sao dùng dấu chấm.
  </Card>
  <Card href="/internals/signature-deep-dive/" title="Chữ ký số JWT — Deep Dive">
    Bên trong con dấu: HMAC-SHA256 (ipad/opad), RSA, ECDSA, EdDSA, constant-time compare, code Node.js.
  </Card>
  <Card href="/internals/token-validation-flow/" title="Luồng xác thực JWT">
    Server validate token qua 7 bước: split → decode header → chọn key → verify → claims → revocation.
  </Card>
  <Card href="/security/algorithm-confusion/" title="Algorithm Confusion">
    Cả họ lỗ hổng do tin Header: alg:none, RS256→HS256, vì sao whitelist thuật toán là bắt buộc.
  </Card>
</Cards>

---

## 10. Tóm tắt — Cheat sheet

**Cấu trúc:** `Header.Payload.Signature` — hai dấu chấm, ba phần.

| Phần | Vai trò | Là gì bên trong | Ai đọc được | Đáng tin lúc nào |
|------|---------|-----------------|-------------|------------------|
| **Header** | Khai báo thuật toán | JSON (base64url) | Ai cũng đọc | Chỉ tham khảo — phải check whitelist |
| **Payload** | Lời tuyên bố (claims) | JSON (base64url) | **Ai cũng đọc** ⚠️ | Chỉ sau khi chữ ký khớp |
| **Signature** | Con dấu chống giả | Byte ngẫu nhiên (base64url) | Không "đọc", chỉ verify | Đây mới là bằng chứng |

**Ẩn dụ phong bì để nhớ cả đời:**

```diagram
   Header    = dòng chữ ngoài vỏ phong bì  (tự khai thuật toán)
   Payload   = mặt trước phong bì          (ai cũng đọc được)
   Signature = con dấu sáp trên nắp        (chống mở ra sửa)
```

**Ba nguyên tắc bất di bất dịch:**

1. **Payload là công khai** — đừng nhét secret/PII vào. Cần giấu → JWE.
2. **Chữ ký là cửa ải duy nhất** — verify xong mới tin payload, luôn verify trước.
3. **Header là lời tự khai** — thuật toán phải do server quyết định (whitelist), cấm `none`.

**Hai sai lầm chết người (và cách tránh):**

- Tưởng payload mã hoá → **không**, nó chỉ encode. Xem: [encoding-vs-encryption](/fundamentals/encoding-vs-encryption/).
- Tin `alg` trong Header → **không**, server phải whitelist. Xem: [algorithm-confusion](/security/algorithm-confusion/).

---

## Tài liệu tham khảo

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — định nghĩa ba phần và vai trò.
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) — định nghĩa Signing Input và Signature.
- Trong repo: [jwt-structure](/fundamentals/jwt-structure/) (byte-level), [signature-deep-dive](/internals/signature-deep-dive/) (crypto), [token-validation-flow](/internals/token-validation-flow/) (luồng verify 7 bước).
