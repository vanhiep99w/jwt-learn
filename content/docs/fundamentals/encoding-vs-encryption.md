---
title: "Encoding vs Encryption trong JWT — Deep Dive"
description: "Vì sao payload JWT đọc được dù trông như mã hoá: mổ base64url từng bit, phân biệt encoding/encryption/hashing/signing, khi nào thật sự cần JWE, và lỗ hổng kinh điển 'tưởng JWT mã hoá'."
---

## Mục lục

- [1. Hiểu lầm chết người: "JWT trông mã hoá nên an toàn"](#1-hiểu-lầm-chết-người-jwt-trông-mã-hoá-nên-an-toàn)
- [2. Bốn khái niệm hay bị nhập nhằng](#2-bốn-khái-niệm-hay-bị-nhập-nhằng)
- [3. Base64URL là gì — và KHÔNG là gì](#3-base64url-là-gì--và-không-là-gì)
- [4. Mổ base64url từng bit](#4-mổ-base64url-từng-bit)
- [5. Vì sao base64url, không phải base64 thường](#5-vì-sao-base64url-không-phải-base64-thường)
- [6. Tự decode payload trong 5 giây](#6-tự-decode-payload-trong-5-giây)
- [7. JWS bảo vệ gì: toàn vẹn, không bí mật](#7-jws-bảo-vệ-gì-toàn-vẹn-không-bí-mật)
- [8. JWE — khi thật sự cần bí mật](#8-jwe--khi-thật-sự-cần-bí-mật)
- [9. Hệ quả bảo mật của hiểu lầm](#9-hệ-quả-bảo-mật-của-hiểu-lầm)
- [10. Anti-patterns cần tránh](#10-anti-patterns-cần-tránh)
- [11. Tóm tắt — Cheat sheet](#11-tóm-tắt--cheat-sheet)

---

## 1. Hiểu lầm chết người: "JWT trông mã hoá nên an toàn"

Nhìn một JWT, ai mới học cũng tưởng đó là chuỗi mã hoá:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiJ9.zDX8...
```

Trông "loằng ngoằng khó đọc" nên nhiều người kết luận: *"nội dung được mã hoá, an toàn để nhét dữ liệu nhạy cảm"*. Đây là **sai lầm bảo mật phổ biến nhất** liên quan tới JWT.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  SỰ THẬT: phần header và payload chỉ được ENCODE bằng base64url.            │
│     base64url = ĐỔI CÁCH BIỂU DIỄN, KHÔNG có khoá, KHÔNG giấu gì.           │
│  → bất kỳ ai cũng decode ngược ra JSON gốc trong vài mili-giây (jwt.io).    │
│  "khó đọc bằng mắt" ≠ "được bảo mật".                                      │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!WARNING]
> Nếu bạn chỉ lấy đi một điều từ doc này: **JWT (loại JWS bạn dùng hằng ngày) KHÔNG mã hoá payload.** Mọi claim trong token đọc được bởi bất kỳ ai cầm token. Đừng bao giờ đặt mật khẩu, số thẻ, secret, hay PII nhạy cảm vào payload. Doc này giải thích chính xác *vì sao* để bạn không bao giờ quên.

---

## 2. Bốn khái niệm hay bị nhập nhằng

Gốc rễ hiểu lầm là trộn lẫn bốn thứ khác nhau hoàn toàn:

```
┌──────────────┬──────────────────────────┬─────────┬──────────────────────────┐
│ Khái niệm    │ Mục đích                 │ Có khoá?│ Đảo ngược được?          │
├──────────────┼──────────────────────────┼─────────┼──────────────────────────┤
│ ENCODING     │ đổi cách biểu diễn       │ KHÔNG   │ CÓ (ai cũng decode)       │
│ (base64url)  │ (bytes ↔ text an toàn)   │         │                          │
│ ENCRYPTION   │ GIẤU nội dung (bí mật)   │ CÓ      │ chỉ với khoá đúng        │
│ (AES, JWE)   │                          │         │                          │
│ HASHING      │ dấu vân tay 1 chiều      │ KHÔNG*  │ KHÔNG (1 chiều)          │
│ (SHA-256)    │                          │         │                          │
│ SIGNING      │ chứng minh toàn vẹn+nguồn│ CÓ      │ verify được (không "giải")│
│ (HMAC, RSA)  │                          │         │                          │
└──────────────┴──────────────────────────┴─────────┴──────────────────────────┘
   * HMAC = hashing CÓ khoá; dùng cho signing.
```

```
JWT (JWS) DÙNG:  ENCODING (base64url) + SIGNING (chữ ký)
   → KHÔNG dùng ENCRYPTION → payload KHÔNG bí mật.
JWT (JWE) DÙNG:  ENCODING + ENCRYPTION (+ toàn vẹn)
   → payload BÍ MẬT (đọc không ra nếu thiếu khoá).
```

> [!IMPORTANT]
> Hai cặp dễ lẫn nhất: (1) **encoding vs encryption** — encoding chỉ đổi biểu diễn, ai cũng đảo ngược; encryption cần khoá để đọc. (2) **hashing vs signing** — hashing một chiều (không lấy lại input), signing chứng minh "ai ký + chưa sửa". JWT (JWS) đứng ở *encoding + signing*: đọc được nhưng không sửa được. Chi tiết signing ở [Chữ ký số — Deep Dive](/internals/signature-deep-dive/).

---

## 3. Base64URL là gì — và KHÔNG là gì

```
BASE64URL LÀ:
   • một cách biểu diễn dữ liệu nhị phân (bytes) thành text dùng 64 ký tự an toàn.
   • mục đích: nhét JSON (có thể chứa ký tự lạ) vào URL/header HTTP mà không vỡ.
   • hoàn toàn CÔNG KHAI: bảng 64 ký tự ai cũng biết, không có bí mật nào.

BASE64URL KHÔNG LÀ:
   • KHÔNG phải mã hoá (không có khoá, không giấu gì).
   • KHÔNG phải nén (thực ra còn PHÌNH ~33%: 3 byte → 4 ký tự).
   • KHÔNG bảo vệ gì cả — chống sửa là việc của CHỮ KÝ, không phải base64url.
```

```
64 KÝ TỰ CỦA BASE64URL:
   A–Z (0–25)  a–z (26–51)  0–9 (52–61)  - (62)  _ (63)
   → mỗi ký tự mã hoá đúng 6 bit (2^6 = 64).
```

> [!NOTE]
> Vì base64url phình ~33%, JWT luôn lớn hơn dữ liệu JSON gốc. Đây là một lý do nữa để giữ payload nhỏ (xem [Claims](/fundamentals/claims/)). Base64url được chọn (thay vì hex hay base64 thường) vì cân bằng giữa gọn và "an toàn cho URL".

---

## 4. Mổ base64url từng bit

Hãy mã hoá chuỗi `Hi!` để thấy base64url chỉ là **gom bit lại theo nhóm 6**.

```
BƯỚC 1 — ký tự sang byte (ASCII):
   'H' = 72   'i' = 105   '!' = 33

BƯỚC 2 — byte sang nhị phân (8 bit mỗi byte):
   72  = 01001000
   105 = 01101001
   33  = 00100001
   ghép lại (24 bit): 0100 1000 0110 1001 0010 0001

BƯỚC 3 — chia lại thành nhóm 6 BIT (thay vì 8):
   010010  000110  100100  100001
      18      6       36      33     ← giá trị thập phân mỗi nhóm

BƯỚC 4 — tra bảng 64 ký tự:
   18 → 'S'    6 → 'G'    36 → 'k'    33 → 'h'
   ⇒ "Hi!"  →  "SGkh"
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Ý TƯỞNG CỐT LÕI: base64url chỉ GOM 24 bit dữ liệu thành 4 NHÓM 6 BIT,     │
│  rồi tra mỗi nhóm ra một ký tự. Không có khoá, không phép toán bí mật.     │
│  Đảo ngược = làm ngược: ký tự → 6 bit → gộp lại 8 bit → byte → ký tự gốc.  │
│  ⇒ AI CŨNG đảo ngược được. Đây là vì sao payload JWT đọc được.            │
└───────────────────────────────────────────────────────────────────────────┘
```

```
KHI ĐỘ DÀI KHÔNG CHIA HẾT CHO 3 byte:
   base64 thường thêm '=' để chèn cho đủ bội số 4 ký tự.
   base64URL trong JWT BỎ '=' (padding) đi → token gọn hơn, hợp URL hơn.
```

> [!TIP]
> Hiểu base64url ở mức bit giúp bạn debug nhanh: thấy chuỗi bắt đầu `eyJ` là gần như chắc chắn một JSON base64url (vì `{"` → `eyJ`). Nhận ra điều này là biết ngay "đây là phần đọc được, không phải mã hoá".

---

## 5. Vì sao base64url, không phải base64 thường

JWT đi trong URL và header HTTP, nên không thể dùng base64 chuẩn nguyên bản.

```
KHÁC BIỆT base64 thường ↔ base64url:
   base64 thường dùng:  + , / , =   → 3 ký tự này GÂY VẤN ĐỀ trong URL:
      '+' → bị hiểu thành dấu cách khi decode URL
      '/' → ký tự phân path
      '=' → ký tự query/padding, hay bị encode thành %3D
   base64URL thay:
      '+' → '-'      '/' → '_'      bỏ luôn '='
```

```
VÍ DỤ THẬT — encode {"a":1}:
   base64 thường:  eyJhIjoxfQ==      (có == ở cuối)
   base64URL    :  eyJhIjoxfQ        (bỏ ==, không có +/ nên giống phần còn lại)
   → cùng dữ liệu, base64url an toàn để nhét thẳng vào URL/header.
```

> [!NOTE]
> Đây thuần tuý là chuyện *vận chuyển an toàn qua URL/HTTP*, không liên quan bảo mật. RFC 7515 (JWS) quy định JWT dùng base64url chính vì token thường xuất hiện trong header `Authorization`, query string, và cookie — những nơi mà `+`, `/`, `=` gây rắc rối.

---

## 6. Tự decode payload trong 5 giây

Để tự chứng minh "payload đọc được", bất kỳ ai cũng làm được không cần thư viện:

```javascript
// Trình duyệt / Node — decode payload của một JWT BẤT KỲ, KHÔNG cần khoá:
const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiJ9.zDX8...";
const payload = token.split(".")[1];                 // lấy phần giữa
const json = atob(payload.replace(/-/g,"+").replace(/_/g,"/")); // base64url→base64→bytes
console.log(JSON.parse(json));                        // { sub: "42", role: "admin" }
```

```bash
# Dòng lệnh — cũng chẳng cần khoá:
echo 'eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiJ9' | base64 -d
# → {"sub":"42","role":"admin"}
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  KHÔNG có bước nào cần khoá, mật khẩu, hay secret.                         │
│  → bất kỳ ai chặn/thấy token đều đọc được mọi claim trong payload.         │
│  Chữ ký (phần 3) KHÔNG ngăn đọc — nó chỉ ngăn SỬA mà không bị phát hiện.   │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> `atob`/`base64 -d` chỉ **decode** (đảo ngược encoding) — khác hẳn `verify` (kiểm chữ ký). Decode không cần khoá và *không* chứng minh gì về tính hợp lệ; nó chỉ cho bạn đọc nội dung. Đừng bao giờ dùng dữ liệu decode-mà-chưa-verify để phân quyền (xem [Common Vulnerabilities](/security/common-vulnerabilities/)).

---

## 7. JWS bảo vệ gì: toàn vẹn, không bí mật

```
JWT (JWS) CHO BẠN:
   ✓ TOÀN VẸN (integrity): sửa 1 ký tự payload → chữ ký không khớp → verify fail.
   ✓ XÁC THỰC NGUỒN (authenticity): chỉ bên có khoá ký mới tạo được chữ ký hợp lệ.
   ✗ BÍ MẬT (confidentiality): KHÔNG — payload đọc được bởi mọi người.

   ┌──────────────────────────────────────────────────────────────┐
   │  CHỮ KÝ giống NIÊM PHONG trên phong bì TRONG SUỐT:            │
   │     ai cũng đọc thư bên trong (không bí mật)...               │
   │     ...nhưng không sửa được mà không làm rách niêm phong.     │
   └──────────────────────────────────────────────────────────────┘
```

```
THÍ NGHIỆM: đổi "role":"user" → "role":"admin" trong payload rồi gửi lại
   → base64url của payload đổi → chuỗi ký (header.payload) đổi
   → chữ ký cũ KHÔNG còn khớp → verifier TỪ CHỐI.
   ⇒ đọc được (không bí mật) NHƯNG không giả mạo được (có toàn vẹn).
```

> [!IMPORTANT]
> Phân biệt rạch ròi: **integrity ≠ confidentiality**. JWS cho integrity + authenticity (không sửa lén, biết ai ký) nhưng *không* confidentiality (không giấu). Khi ai đó nói "JWT an toàn", hãy hỏi "an toàn theo nghĩa nào?" — an toàn *chống sửa* thì có; an toàn *giấu nội dung* thì không (trừ khi dùng JWE).

---

## 8. JWE — khi thật sự cần bí mật

Nếu thật sự cần payload bí mật, JOSE có **JWE** (JSON Web Encryption).

```
JWS (ký):       header . payload . signature              → 3 phần, ĐỌC ĐƯỢC
JWE (mã hoá):   header . encKey . iv . ciphertext . tag   → 5 phần, ĐỌC KHÔNG RA
                                       └── nội dung đã mã hoá AES ──┘
```

```
KHI NÀO DÙNG JWE:
   • token BẮT BUỘC chứa dữ liệu nhạy cảm mà bên trung gian không được đọc.
   • thường gặp ở: id_token chứa thuộc tính nhạy cảm, token đi qua bên thứ ba.

KHI NÀO KHÔNG CẦN (phần lớn trường hợp):
   • auth thông thường chỉ cần "không bị giả" → JWS đủ.
   • cách tốt hơn mã hoá token: ĐỪNG đặt dữ liệu nhạy cảm vào token.
     đặt một định danh (sub) trong token, tra chi tiết nhạy cảm từ DB khi cần.
```

> [!TIP]
> Quy tắc thực dụng: **mặc định dùng JWS; chỉ leo lên JWE khi có yêu cầu cụ thể về bí mật mà không thể tránh bằng cách bỏ dữ liệu ra khỏi token.** JWE phức tạp hơn (quản lý khoá mã hoá riêng, nhiều thành phần hơn) nên đừng dùng "cho chắc". Chi tiết ở [JWE — Token mã hoá](/cryptography/jwe-encrypted-token/).

---

## 9. Hệ quả bảo mật của hiểu lầm

```
HỆ QUẢ 1 — lộ dữ liệu nhạy cảm:
   dev tưởng payload mã hoá → nhét số CMND, số thẻ, email, "internal_notes".
   → bất kỳ ai có token (kể cả lưu ở localStorage bị XSS) đọc sạch.

HỆ QUẢ 2 — nhét secret/khoá vào claim:
   "api_secret":"sk_live_..." trong payload → lộ ngay, ai có token là có secret.

HỆ QUẢ 3 — tin "không ai đọc được nên không cần ký cẩn thận":
   bỏ qua verify chữ ký vì "đằng nào cũng mã hoá rồi" → mở cửa giả token.
   (lẫn lộn: integrity và confidentiality là HAI việc khác nhau, cần riêng.)
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  PHÒNG TRÁNH — ghim một câu:                                               │
│     "Mọi thứ trong payload JWT coi như CÔNG KHAI."                         │
│  Thiết kế token với giả định kẻ địch đọc được toàn bộ payload → bạn sẽ     │
│  không bao giờ đặt nhầm dữ liệu nhạy cảm vào đó.                           │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!WARNING]
> Hệ quả 3 đặc biệt nguy hiểm vì nó trộn hai khái niệm: ngay cả khi token được mã hoá (JWE), bạn **vẫn phải verify** tính toàn vẹn/chữ ký. Mã hoá giấu nội dung; chữ ký chống giả mạo — cần cả hai cho đúng mục đích, không cái nào thay được cái nào.

---

## 10. Anti-patterns cần tránh

| Anti-pattern | Hậu quả | Thay bằng |
|--------------|---------|-----------|
| Coi base64url là "mã hoá" | Nhét dữ liệu nhạy cảm vào payload | Hiểu JWS đọc được; coi payload là công khai |
| Đặt mật khẩu/secret/khoá trong claim | Lộ ngay cho bất kỳ ai có token | Không đặt; tra từ nguồn an toàn |
| Đặt PII nhạy cảm (CMND, thẻ, sức khoẻ) | Lộ + vi phạm quy định dữ liệu | Để ngoài token; JWE nếu bắt buộc |
| Dùng `decode` thay `verify` để phân quyền | Tin dữ liệu chưa kiểm → giả token | Luôn verify chữ ký trước |
| "Đã mã hoá nên khỏi ký cẩn thận" | Lẫn integrity với confidentiality | Mã hoá & ký là hai việc, cần cả hai |
| Dùng JWE "cho chắc" khi chỉ cần ký | Phức tạp vô ích | JWS + bỏ dữ liệu nhạy cảm ra khỏi token |
| Tưởng base64url để "nén" token | Hiểu sai (base64url phình ~33%) | Giữ payload nhỏ để token gọn |

---

## 11. Tóm tắt — Cheat sheet

```
┌────────────────────── ENCODING vs ENCRYPTION ───────────────────────────┐
│                                                                          │
│  ENCODING (base64url)   đổi biểu diễn · KHÔNG khoá · AI CŨNG đảo ngược    │
│  ENCRYPTION (JWE/AES)   giấu nội dung · CÓ khoá · cần khoá mới đọc        │
│  HASHING (SHA-256)      vân tay 1 chiều · không lấy lại input            │
│  SIGNING (HMAC/RSA)     chống sửa + biết ai ký · verify được             │
│                                                                          │
│  JWT (JWS) = ENCODING + SIGNING                                          │
│     → payload ĐỌC ĐƯỢC (không bí mật) NHƯNG không sửa được lén           │
│     → "phong bì trong suốt có niêm phong"                                │
│                                                                          │
│  CẦN BÍ MẬT? → JWE (mã hoá) HOẶC tốt hơn: đừng đặt dữ liệu nhạy cảm vào   │
└────────────────────────────────────────────────────────────────────────────┘
```

```
3 NGUYÊN TẮC GHIM:
   ① PAYLOAD = CÔNG KHAI — thiết kế token với giả định ai cũng đọc được.
   ② DECODE ≠ VERIFY — decode không cần khoá & không chứng minh gì; luôn verify.
   ③ INTEGRITY ≠ CONFIDENTIALITY — JWS chống sửa, KHÔNG giấu; cần giấu thì JWE.
```

> [!NOTE]
> Đọc tiếp: [Cấu trúc JWT — Deep Dive](/fundamentals/jwt-structure/) (base64url trong bối cảnh 3 phần), [Chữ ký số — Deep Dive](/internals/signature-deep-dive/) (signing hoạt động ra sao), [Claims](/fundamentals/claims/) (đặt gì vào payload công khai), và [Secure Storage](/security/secure-storage/) (lưu token đọc-được ở đâu cho an toàn).
