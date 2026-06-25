---
title: "Common JWT Vulnerabilities — Deep Dive"
description: "Mục lục lỗ hổng JWT thực chiến, mổ từng loại với cơ chế tấn công từng bước và cách vá: alg:none, HMAC secret yếu (kèm tốc độ brute-force thật), không verify chữ ký (chỉ decode), bỏ kiểm exp/nbf/aud/iss, kid injection (path traversal/SQLi), jku/x5u/jwk header injection, claim & type confusion, replay, lộ dữ liệu trong payload, JWT bomb/DoS. Kèm bảng đối chiếu lỗ hổng↔phòng thủ, PoC định lượng và checklist verifier an toàn."
---

# Common JWT Vulnerabilities — Deep Dive

## Mục lục

- [1. Lỗ hổng JWT đến từ đâu](#1-lỗ-hổng-jwt-đến-từ-đâu)
- [2. alg:none — token "không cần chữ ký"](#2-algnone--token-không-cần-chữ-ký)
- [3. HMAC secret yếu — brute-force offline](#3-hmac-secret-yếu--brute-force-offline)
- [4. Không verify chữ ký — chỉ decode](#4-không-verify-chữ-ký--chỉ-decode)
- [5. Bỏ kiểm exp / nbf — token sống mãi](#5-bỏ-kiểm-exp--nbf--token-sống-mãi)
- [6. Bỏ kiểm aud / iss — token dùng nhầm chỗ](#6-bỏ-kiểm-aud--iss--token-dùng-nhầm-chỗ)
- [7. kid injection — path traversal & SQLi](#7-kid-injection--path-traversal--sqli)
- [8. jku / x5u / jwk header injection](#8-jku--x5u--jwk-header-injection)
- [9. Claim confusion & type confusion](#9-claim-confusion--type-confusion)
- [10. Replay & lộ dữ liệu trong payload](#10-replay--lộ-dữ-liệu-trong-payload)
- [11. JWT bomb & DoS](#11-jwt-bomb--dos)
- [12. Lab — tự dò lỗ hổng token của bạn](#12-lab--tự-dò-lỗ-hổng-token-của-bạn)
- [13. CVE thực tế & bài học](#13-cve-thực-tế--bài-học)
- [14. Bảng đối chiếu lỗ hổng ↔ phòng thủ](#14-bảng-đối-chiếu-lỗ-hổng--phòng-thủ)
- [15. Checklist verifier an toàn](#15-checklist-verifier-an-toàn)
- [16. Tóm tắt — Cheat sheet](#16-tóm-tắt--cheat-sheet)

---

## 1. Lỗ hổng JWT đến từ đâu

Gần như mọi lỗ hổng JWT rơi vào hai nhóm, ánh xạ trực tiếp từ [threat model](/security/jwt-threat-model/):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  NHÓM A — GIẢ TOKEN (phá tính toàn vẹn chữ ký)                               │
│     verifier bị lừa CHẤP NHẬN token mà attacker tự dựng:                     │
│     alg:none, secret yếu, alg confusion, kid/jku injection, không verify     │
│                                                                               │
│  NHÓM B — DÙNG SAI TOKEN HỢP LỆ (logic verify thiếu)                         │
│     chữ ký đúng nhưng verifier quên kiểm ngữ cảnh:                            │
│     bỏ exp/nbf (sống mãi), bỏ aud/iss (nhầm chỗ), replay, claim confusion     │
└─────────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Quy luật chung: **verify JWT không phải một bước (kiểm chữ ký) mà là nhiều cổng** — chữ ký, thuật toán, thời gian, đối tượng, người cấp. Bỏ bất kỳ cổng nào là một lỗ hổng. Bài này mổ từng lỗ hổng; pipeline verify đầy đủ ở [Token Validation — Deep Dive](/internals/token-validation-deep-dive/), còn họ "confusion" ở [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/).

---

## 2. alg:none — token "không cần chữ ký"

RFC cho phép `alg: "none"` (token không chữ ký, phần signature rỗng) — dành cho trường hợp toàn vẹn đã được đảm bảo ở tầng khác. Nhưng nếu verifier **chấp nhận** `none`, ai cũng dựng được token hợp lệ.

```
Token attacker dựng (KHÔNG chữ ký):
   header  = {"alg":"none","typ":"JWT"}
   payload = {"sub":"victim","role":"admin"}
   token   = base64url(header) ‖ "." ‖ base64url(payload) ‖ "."    ← signature RỖNG

Nếu verifier "tin alg trong header" và thấy none → BỎ QUA kiểm chữ ký → CHẤP NHẬN
   ⇒ attacker giả bất kỳ ai, bất kỳ role nào, không cần khóa.
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  GỐC RỄ: verifier để HEADER (do attacker điền) quyết định CÓ verify hay không│
│     "alg do bên gửi chọn" = "để kẻ tấn công tự chọn luật chơi"              │
│                                                                             │
│  VÁ:                                                                        │
│   • allowlist thuật toán phía verifier: chỉ chấp nhận vd ['RS256']          │
│   • KHÔNG bao giờ để alg=none qua (trừ khi bạn THỰC SỰ hiểu vì sao cần)      │
│   • truyền key + alg kỳ vọng vào hàm verify, không đọc alg từ token để quyết │
└───────────────────────────────────────────────────────────────────────────┘
```

```javascript
// SAI — để token tự khai alg
jwt.verify(token, key);                    // một số lib cũ tin alg trong header

// ĐÚNG — ghim alg phía verifier
jwt.verify(token, key, { algorithms: ['RS256'] });   // none/HS256 đều bị từ chối
```

> [!WARNING]
> Biến thể: `"None"`, `"nOnE"`, `"NONE"` — vài lib so sánh không phân biệt hoa thường hoặc bỏ sót case. Allowlist (chỉ cho qua đúng tên thuật toán mong đợi) miễn nhiễm với mọi biến thể vì nó **từ chối mọi thứ không nằm trong danh sách**.

---

## 3. HMAC secret yếu — brute-force offline

Với HS256, chữ ký = `HMAC-SHA256(secret, signingInput)`. Nếu `secret` yếu (từ điển/ngắn), attacker **crack offline** chỉ từ một token chặn được — không cần chạm server.

```
Token nạn nhân (ký bằng secret = "secret"):
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4i
   LCJpYXQiOjE3MTkzMTIwMDB9.b72497nGvoK3l-fjLcJEJ-77VMrS6yLI_TVa98pG6Lo

Dictionary attack OFFLINE (attacker chỉ cần token này):
   với mỗi từ w trong wordlist:
       nếu base64url(HMAC-SHA256(w, signingInput)) == signature của token:
           → w CHÍNH LÀ secret
   thử ['123456','password','admin','letmein','secret',...]
       → khớp "secret" sau 6 lần thử, 0.14 ms.

Tốc độ thực:  1 core Node ≈ 477.000 HMAC/s
              1 GPU (hashcat -m 16500) ≈ HÀNG TỶ HMAC/s
   ⇒ secret là từ điển → vỡ tức thì; secret ngắn (≤ 8 ký tự) → vỡ trong phút–giờ
```

```
SAU KHI có secret, attacker tự ký token tùy ý:
   payload = {"sub":"1234","role":"admin"}  → ký bằng secret vừa crack
   → token HỢP LỆ hoàn toàn với verifier → leo quyền/mạo danh
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  VÁ secret yếu:                                                            │
│   • secret ≥ 256-bit NGẪU NHIÊN (vd randomBytes(32)), KHÔNG phải từ/cụm từ  │
│   • không commit secret vào code/repo; nạp từ secret manager               │
│   • cân nhắc chuyển sang RS256/ES256 (bất đối xứng) cho hệ phân tán:        │
│     verifier chỉ có PUBLIC key → dù lộ cũng không ký giả được               │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!NOTE]
> Brute-force HMAC là **offline** — không rate-limit nào ở server chặn được, vì attacker thử trên máy mình. Phòng thủ duy nhất là entropy của secret: 256-bit ngẫu nhiên khiến không gian khóa (2²⁵⁶) lớn tới mức brute-force bất khả thi. Chi tiết HMAC ở [Chữ ký số — Deep Dive](/internals/signature-deep-dive/).

---

## 4. Không verify chữ ký — chỉ decode

Lỗi sơ đẳng nhưng phổ biến đáng kinh ngạc: code **decode** payload (đọc claim) nhưng **không verify** chữ ký.

```
SAI — decode KHÔNG verify:
   const payload = jwt.decode(token);        // chỉ base64url-decode, KHÔNG kiểm ký!
   if (payload.role === 'admin') { ... }      // attacker sửa role tùy ý → bypass

   → jwt.decode() / jwtDecode() KHÔNG kiểm chữ ký, exp, gì cả. Nó chỉ "đọc".

ĐÚNG — verify (kiểm chữ ký + claim):
   const payload = jwt.verify(token, key, { algorithms: ['RS256'] });
```

```
Dấu hiệu nhận biết trong codebase (cần soát):
   • gọi jwt.decode / jwtDecode / atob(token.split('.')[1]) rồi TIN payload
   • "đọc nhanh" claim ở client để hiển thị → OK; nhưng dùng để PHÂN QUYỀN server → SAI
   • copy token vào jwt.io xem rồi nghĩ "thế là verify" → KHÔNG, đó chỉ là decode
```

> [!WARNING]
> Decode ≠ verify. `decode` chỉ tách base64url (ai cũng làm được, kể cả attacker). Mọi quyết định **phân quyền** phải dựa trên `verify` (đã kiểm chữ ký + alg + exp + aud/iss). Đọc-để-hiển-thị ở client thì decode được, nhưng server không bao giờ tin payload chưa verify.

---

## 5. Bỏ kiểm exp / nbf — token sống mãi

Chữ ký đúng nhưng quên kiểm thời gian = token không bao giờ hết hạn dưới góc nhìn verifier.

```
Hệ quả:
   • token bị trộm dùng được VĨNH VIỄN (không chờ exp)
   • thu hồi bằng TTL ngắn (xem Revocation & Logout) MẤT TÁC DỤNG hoàn toàn
   • nbf bỏ qua → token "chưa hiệu lực" vẫn dùng được sớm

exp/nbf là NumericDate = GIÂY epoch (KHÔNG mili-giây). Bẫy kinh điển:
   exp = Date.now()           // SAI: mili-giây → exp ở năm ~56000 → sống ~1700 năm
   exp = Math.floor(Date.now()/1000) + 900   // ĐÚNG: giây
```

```
Verifier đúng (có leeway cho clock skew):
   now < exp + leeway   (chưa hết hạn, cho lệch ~30–60s)
   now >= nbf - leeway   (đã tới hiệu lực)
   → xem chi tiết clock skew/leeway ở Expiration & Renewal
```

> [!TIP]
> Nhiều thư viện kiểm `exp`/`nbf` **mặc định** khi gọi `verify` — nhưng chỉ khi token *có* các claim đó. Token thiếu `exp` thường được coi là "không hết hạn". Vì vậy: (1) issuer LUÔN set `exp`; (2) verifier nên **bắt buộc** có `exp` (từ chối token thiếu exp) cho các API nhạy cảm.

---

## 6. Bỏ kiểm aud / iss — token dùng nhầm chỗ

`aud` (audience) và `iss` (issuer) chống token hợp lệ bị dùng sai ngữ cảnh.

```
Kịch bản không kiểm aud:
   Auth server cấp token cho NHIỀU dịch vụ (aud=api.A, aud=api.B...).
   api.B KHÔNG kiểm aud → chấp nhận cả token vốn cấp cho api.A.
   → token "đọc-only cho service A" dùng được ở "service B quyền cao" → leo quyền.

Kịch bản không kiểm iss:
   Verifier chấp nhận token từ BẤT KỲ issuer nào (miễn chữ ký đúng theo key nó có).
   → nếu nhiều issuer / nhiều tenant → token tenant này dùng nhầm tenant khác.
```

```
Verifier đúng — ghim cả hai:
   jwt.verify(token, key, {
     algorithms: ['RS256'],
     issuer:   'https://auth.example.com',   // chỉ chấp nhận issuer này
     audience: 'api.payments',               // token PHẢI nhắm tới chính tôi
   });
```

> [!NOTE]
> Trong kiến trúc microservices, mỗi resource server nên kiểm `aud` = chính nó. Đây là biện pháp rẻ chặn cả lớp "token rò chéo dịch vụ". Bỏ `aud` đặc biệt nguy hiểm khi một auth server phục vụ nhiều API có mức quyền khác nhau.

---

## 7. kid injection — path traversal & SQLi

`kid` (key id) trong header trỏ verifier tới khóa cần dùng. Nếu verifier **dùng kid để tra cứu mà không khử trùng**, attacker tiêm payload độc vào kid.

```
(a) PATH TRAVERSAL — kid dùng để đọc file khóa:
    kid = "../../../../dev/null"
    → verifier đọc /dev/null làm "khóa" (chuỗi rỗng)
    → attacker ký HMAC bằng khóa = "" (rỗng) → token khớp → bypass
    kid = "../../public/css/main.css"  → dùng file tĩnh ĐOÁN ĐƯỢC làm khóa HMAC

(b) SQL INJECTION — kid tra DB lấy khóa:
    kid = "x' UNION SELECT 'attacker-known-key' -- "
    → query trả về khóa attacker tự chọn → ký token khớp → bypass

(c) COMMAND INJECTION — hiếm, nếu kid nhét vào lệnh shell.
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  VÁ kid injection:                                                         │
│   • coi kid là DỮ LIỆU KHÔNG TIN CẬY (attacker điền) → KHÔNG dùng trực tiếp │
│     làm đường dẫn file / chuỗi SQL / lệnh                                   │
│   • allowlist: kid phải khớp tập id khóa ĐÃ BIẾT (vd map cứng kid→key)      │
│   • tra khóa qua truy vấn THAM SỐ HÓA (prepared statement), không nối chuỗi │
│   • chuẩn hóa & ràng buộc định dạng kid (vd chỉ [A-Za-z0-9._-])             │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!WARNING]
> `kid` là **đầu vào do kẻ tấn công kiểm soát** (nằm trong header token). Mọi nguyên tắc chống injection (đừng tin input, tham số hóa, allowlist) áp dụng y như với input người dùng khác. Đừng bao giờ `readFile(kid)` hay `"... WHERE kid='" + kid + "'"`.

---

## 8. jku / x5u / jwk header injection

Các header `jku` (JWK Set URL), `x5u` (X.509 URL), `jwk` (khóa nhúng thẳng) cho phép token *chỉ ra* khóa verify. Nếu verifier tin chúng vô điều kiện, attacker tự cấp khóa.

```
(a) jwk injection — token nhúng LUÔN public key của attacker:
    header = {"alg":"RS256","jwk":{...public key của ATTACKER...}}
    → verifier dùng key trong header để verify → attacker ký bằng private key
      tương ứng (của chính hắn) → token "hợp lệ" → bypass hoàn toàn

(b) jku injection — token trỏ tới JWKS của attacker:
    header = {"alg":"RS256","kid":"k1","jku":"https://attacker.com/jwks.json"}
    → verifier fetch key từ URL attacker → verify pass với key attacker.

(c) x5u — tương tự, trỏ tới chứng chỉ X.509 của attacker.
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  VÁ:                                                                        │
│   • KHÔNG tin jwk/jku/x5u trong header để chọn khóa verify                  │
│   • khóa verify phải đến từ NGUỒN TIN CẬY cấu hình sẵn phía server          │
│     (JWKS endpoint của ĐÚNG issuer, ghim cứng), không từ token              │
│   • nếu buộc dùng jku: allowlist domain (chỉ host issuer hợp lệ)            │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Nguyên tắc chung của cả §7–§8: **token KHÔNG được tự quyết định nó verify bằng khóa nào.** Verifier giữ quyền chọn khóa (từ cấu hình/JWKS tin cậy). Cho token tự chỉ khóa = cho kẻ tấn công mang khóa của chính mình. Chi tiết và CVE thực tế ở [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/).

---

## 9. Claim confusion & type confusion

```
(a) CLAIM CONFUSION — verifier đọc nhầm claim:
    • coi sub là duy nhất nhưng issuer cho phép trùng sub giữa các provider
    • dùng email trong token làm khóa định danh, nhưng email đổi được / không verified
    • nhầm "aud" (mảng) — token có aud=["api.A","api.B"], verifier chỉ kiểm phần tử đầu

(b) TYPE CONFUSION — kiểu dữ liệu claim không như mong đợi:
    • exp là string "9999999999" thay vì number → so sánh sai → token sống lâu
    • aud là string vs mảng → kiểm bằng === thất bại hoặc bỏ qua
    • roles là "admin" (string) vs ["admin"] (mảng) → kiểm includes() sai
```

```
VÁ:
   • dùng thư viện verify chuẩn (xử lý đúng aud mảng/string, exp number)
   • validate KIỂU và GIÁ TRỊ claim sau verify (schema: exp:number, aud:string|array)
   • định danh bằng claim ỔN ĐỊNH + đã-verify (sub của đúng issuer), không email thô
   • với aud mảng: kiểm "chính tôi CÓ trong mảng", không chỉ phần tử đầu
```

> [!TIP]
> Sau khi `verify` thành công, vẫn nên **validate schema** của payload (kiểu + ràng buộc) trước khi dùng. `verify` đảm bảo *token không bị giả*, nhưng không đảm bảo *claim có hình dạng bạn giả định*. Đặc biệt với `aud` (có thể là string hoặc array theo RFC).

---

## 10. Replay & lộ dữ liệu trong payload

```
REPLAY — dùng lại token đã chặn được:
   attacker bắt được 1 token hợp lệ (qua HTTP trần, log) → gửi lại để mạo danh.
   Phòng thủ:
      • TLS (chặn bắt token trên đường truyền)
      • exp NGẮN (cửa sổ replay hẹp)
      • jti + chống dùng-lại cho thao tác one-time (vd thanh toán)
      • binding token với client (DPoP / mTLS) cho hệ yêu cầu cao

LỘ DỮ LIỆU — payload đọc được:
   JWT thường KHÔNG mã hóa → ai có token đều base64url-decode đọc claim.
   nhét PII (email, sđt, CMND), secret, token khác → tự lộ.
   Phòng thủ: tối thiểu claim; cần bí mật thật → JWE (mã hóa). Xem
   Encoding vs Encryption.
```

> [!WARNING]
> "base64url là encoding, không phải mã hóa" — lặp lại vì đây là nguồn lỗ hổng lộ dữ liệu phổ biến nhất. Bất cứ ai chặn được token (hoặc thấy nó trong log/URL) đều đọc trọn payload. Coi payload như **bưu thiếp**: ký tên (chữ ký) nhưng ai cũng đọc nội dung.

---

## 11. JWT bomb & DoS

```
(a) TOKEN KHỔNG LỒ — payload vài MB → tốn CPU/mem khi parse + verify mỗi request
(b) JWKS REFETCH STORM — token toàn kid lạ → verifier liên tục fetch JWKS → quá tải
    cả verifier lẫn JWKS endpoint
(c) KEY/PARAM ĐẮT — ép dùng RSA key cực lớn / vòng lặp băm nhiều → verify chậm

VÁ:
   • giới hạn KÍCH THƯỚC token (vd từ chối > 8 KB) trước khi parse
   • cache JWKS + COOLDOWN giữa các lần refetch + giới hạn số kid lạ/giây (xem JWK & JWKS)
   • allowlist alg + giới hạn tham số (không nhận key/alg bất thường)
```

> [!NOTE]
> DoS thường bị bỏ quên khi nghĩ về JWT (ta lo giả mạo nhiều hơn). Nhưng "JWKS refetch storm" rất thực: chỉ cần spam token với `kid` ngẫu nhiên, nếu verifier fetch JWKS cho mỗi kid mới mà không cache/cooldown, cả hệ xác thực có thể sập. Chi tiết cache JWKS ở [JWK & JWKS — Deep Dive](/cryptography/jwk-and-jwks/).

---

## 12. Lab — tự dò lỗ hổng token của bạn

Lý thuyết là một chuyện; tự tay kiểm token của hệ thống mình là chuyện khác. Dưới đây là quy trình dò nhanh các lỗ hổng phổ biến — chỉ cần một token thật và vài lệnh.

### Test 1 — verifier có chấp nhận alg:none không?

```
Dựng token alg:none (sub=admin, role=admin), chữ ký RỖNG:
   header  {"alg":"none","typ":"JWT"}
   payload {"sub":"admin","role":"admin"}
   token:
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
                                                                              ↑ rỗng

Gửi token này tới API:
   curl -H "Authorization: Bearer eyJhbGciOiJub25l...J9." https://api.example.com/me
   • 401/403 → TỐT (verifier từ chối none)
   • 200     → LỖ HỔNG NGHIÊM TRỌNG (chấp nhận token không chữ ký)
Thử thêm biến thể: "None", "NONE", "nOnE" (vài lib bỏ sót case).
```

### Test 2 — token có dùng HMAC secret yếu không?

```
Nếu token là HS256 (header alg=HS256), thử crack offline bằng hashcat/jwt_tool:
   hashcat -a 0 -m 16500 token.txt wordlist.txt
   (-m 16500 = JWT HMAC; wordlist = rockyou.txt v.v.)
   • crack ra secret → secret YẾU → phải đổi sang ≥256-bit ngẫu nhiên / RS256
   • không crack sau toàn wordlist lớn → secret có vẻ đủ mạnh (chưa chắc, nhưng tốt)
Nhắc lại §3: secret từ điển vỡ trong mili-giây; secret ≤8 ký tự vỡ trong phút–giờ.
```

### Test 3 — verifier có kiểm exp / aud / iss không?

```
• exp:  lấy token thật đã HẾT HẠN, gửi lại → còn 200 = KHÔNG kiểm exp (lỗ hổng)
• aud:  lấy token cấp cho service A, gửi tới service B → 200 = B KHÔNG kiểm aud
• iss:  (nếu có nhiều issuer) token issuer X gửi nơi chỉ nên nhận issuer Y → 200 = lỗ
Mẹo: chỉnh exp/aud bằng cách DECODE token (jwt.io) để biết giá trị, rồi test có–không.
```

### Test 4 — decode vs verify (soát code, không gửi request)

```
grep -rn "jwt.decode\|jwtDecode\|atob(" src/        # tìm chỗ đọc payload không verify
   → nếu kết quả được dùng cho phân quyền (if role===... / req.user=...) → LỖ HỔNG
grep -rn "algorithms" src/                           # verify có allowlist alg chưa?
   → thiếu options algorithms:[...] ở chỗ verify → nguy cơ alg:none/confusion
```

> [!WARNING]
> Chỉ chạy các test này trên **hệ thống của bạn** (hoặc được phép kiểm thử). Dò lỗ hổng trên hệ thống của người khác mà không có sự cho phép là vi phạm pháp luật. Mục đích ở đây là *tự kiểm phòng thủ của chính mình*.

> [!TIP]
> Công cụ thực chiến: `jwt_tool` (Python) tự động chạy nhiều test (alg:none, confusion, kid injection, crack HMAC) trên một token; `hashcat -m 16500` để crack HMAC; tab Debugger ở jwt.io để decode/xem claim. Đưa các test này vào CI security scan nếu hệ thống nhạy cảm.

---

## 13. CVE thực tế & bài học

Các lỗ hổng ở bài này không phải lý thuyết — chúng đã thành CVE thật trong các thư viện JWT lớn:

```
┌───────────────────────────────────────────────────────────────────────────┐
│  alg:none (cả họ "none bypass")                                            │
│     Nhiều thư viện JWT (2015, Auth0 cảnh báo) chấp nhận alg:none khi gọi    │
│     verify mà không truyền alg kỳ vọng → giả token tùy ý.                   │
│     BÀI HỌC: luôn truyền algorithms allowlist; đừng để lib "tự đoán" alg.   │
│                                                                             │
│  RS256 → HS256 confusion (CVE-2016-5431, CVE-2016-10555 và nhiều bản khác) │
│     Lib dùng CÙNG một hàm verify cho cả HMAC lẫn RSA → attacker đổi alg     │
│     sang HS256 và ký HMAC bằng PUBLIC key (ai cũng biết) → token "hợp lệ".  │
│     BÀI HỌC: tách key theo alg; allowlist đúng một họ alg cho mỗi key.      │
│                                                                             │
│  kid path traversal / injection                                            │
│     kid dùng làm đường dẫn file/khóa DB không khử trùng → đọc /dev/null     │
│     hay file đoán-được làm khóa HMAC → giả token.                           │
│     BÀI HỌC: kid là input không tin cậy → allowlist + tham số hóa.         │
│                                                                             │
│  jwk/jku header injection (nhiều thư viện & cấu hình OIDC)                  │
│     verifier tin khóa nhúng trong header / URL trong token → dùng khóa      │
│     của attacker để verify → bypass hoàn toàn.                              │
│     BÀI HỌC: khóa verify CHỈ từ nguồn tin cậy cấu hình sẵn.                 │
└───────────────────────────────────────────────────────────────────────────┘
```

```
ĐIỂM CHUNG CỦA TẤT CẢ CVE TRÊN:
   gốc rễ không phải "JWT không an toàn" mà là "verifier tin HEADER do attacker điền"
   để quyết định alg/khóa. Sửa gốc (allowlist alg + khóa từ nguồn tin cậy) đóng
   gần như toàn bộ họ CVE này CÙNG LÚC.
```

> [!IMPORTANT]
> Lý do các CVE này lặp đi lặp lại qua nhiều thư viện trong nhiều năm: API verify "tiện" (chỉ `verify(token, key)`) khuyến khích thói quen sai (để lib tự đoán alg). Thư viện hiện đại buộc truyền `algorithms` chính là phản ứng với lớp CVE này. Khi chọn/nâng cấp thư viện JWT, ưu tiên loại **bắt buộc allowlist alg** và cập nhật bản vá. Chi tiết cơ chế confusion ở [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/).

---

## 14. Bảng đối chiếu lỗ hổng ↔ phòng thủ

| Lỗ hổng | Nhóm | Cơ chế | Phòng thủ chính |
|---------|------|--------|------------------|
| `alg:none` | giả | header tự khai "không ký" | allowlist alg phía verifier |
| Secret HMAC yếu | giả | brute-force offline | secret ≥256-bit ngẫu nhiên / RS256 |
| alg confusion RS→HS | giả | ký HMAC bằng public key | tách key theo alg, allowlist alg |
| Không verify (chỉ decode) | giả | tin payload chưa kiểm ký | luôn `verify`, không `decode` để authz |
| `kid` injection | giả | path traversal / SQLi | allowlist kid, tham số hóa |
| `jku`/`x5u`/`jwk` injection | giả | token tự chỉ khóa | khóa từ nguồn tin cậy, không từ token |
| Bỏ `exp`/`nbf` | dùng sai | token sống mãi | bắt buộc exp, kiểm thời gian + leeway |
| Bỏ `aud`/`iss` | dùng sai | token nhầm dịch vụ | ghim issuer + audience |
| Claim/type confusion | dùng sai | đọc sai claim/kiểu | validate schema sau verify |
| Replay | dùng sai | gửi lại token bắt được | TLS + exp ngắn + jti one-time |
| Lộ PII payload | lộ tin | base64url đọc được | tối thiểu claim / JWE |
| JWT bomb / JWKS storm | DoS | token lớn / kid lạ | giới hạn size, cache JWKS |

---

## 15. Checklist verifier an toàn

```
□ algorithms: [...] — ALLOWLIST cố định, KHÔNG đọc alg từ token để quyết
□ Từ chối alg:none (allowlist tự lo việc này)
□ Khóa verify từ NGUỒN TIN CẬY cấu hình sẵn (không từ jwk/jku/x5u trong header)
□ kid: tra qua allowlist / prepared statement, không readFile/nối chuỗi SQL
□ verify chữ ký (KHÔNG chỉ decode) cho MỌI quyết định phân quyền
□ Bắt buộc & kiểm exp (+leeway), kiểm nbf nếu có
□ Ghim issuer (iss) và audience (aud) = chính dịch vụ này
□ Validate SCHEMA claim sau verify (kiểu + ràng buộc; aud có thể là mảng)
□ TLS bắt buộc; token ở Authorization header, KHÔNG ở URL; không log token
□ Giới hạn kích thước token; cache JWKS + cooldown
□ Secret HMAC ≥256-bit ngẫu nhiên (hoặc dùng RS256/ES256)
```

> [!TIP]
> Dùng checklist này khi review code verify hoặc cấu hình API gateway. Phần lớn lỗ hổng ở bài này được chặn chỉ bằng hai dòng: `algorithms: ['RS256']` + `{ issuer, audience }`, cộng với "luôn `verify` không `decode`". Đó là 80% giá trị phòng thủ với 20% công sức.

---

## 16. Tóm tắt — Cheat sheet

```
╭──────────────────────────────────────────────────────────────────────────╮
│  LỖ HỔNG JWT = 2 nhóm:                                                     │
│    A. GIẢ token   → alg:none, secret yếu, confusion, kid/jku inj, ko verify│
│    B. DÙNG SAI    → bỏ exp/nbf/aud/iss, claim/type confusion, replay       │
│                                                                            │
│  GỐC RỄ lặp lại:                                                          │
│    • để TOKEN (attacker điền) quyết định alg/khóa → allowlist phía verifier│
│    • decode ≠ verify → luôn verify trước khi authz                        │
│    • verify là NHIỀU CỔNG (ký + alg + exp + aud + iss), bỏ 1 = lỗ hổng     │
│    • payload base64url = công khai → đừng nhét bí mật                      │
│    • kid/jku/x5u/jwk = input không tin cậy → đừng tin để chọn khóa         │
│                                                                            │
│  ĐỊNH LƯỢNG: secret "secret" crack sau 6 thử/0.14ms; GPU vài TỶ HMAC/s     │
│    ⇒ secret PHẢI ≥256-bit ngẫu nhiên                                      │
│                                                                            │
│  80/20: algorithms:['RS256'] + {issuer,audience} + luôn verify            │
│         chặn phần lớn lỗ hổng.                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Verifier giữ quyền quyết định, không phải token.** Allowlist thuật toán, chọn khóa từ nguồn tin cậy — đừng để `alg`/`kid`/`jku`/`jwk` trong header (do attacker điền) điều khiển cách verify.
2. **Verify là nhiều cổng, và decode không phải verify.** Kiểm chữ ký + alg + exp/nbf + aud + iss; mọi authz dựa trên `verify` chứ không `decode`.
3. **Secret mạnh, payload sạch, TLS luôn bật.** Secret ≥256-bit ngẫu nhiên (hoặc RS256), không nhét bí mật vào payload, không để token rò ra log/URL.

Đọc tiếp: [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/) · [XSS/CSRF & Token Theft](/security/xss-csrf-token-theft/) · [Secure Storage](/security/secure-storage/) · [Security Best Practices](/security/security-best-practices/).
