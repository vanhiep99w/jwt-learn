---
title: "Claims trong JWT — Deep Dive"
description: "Mổ xẻ claims: registered (iss/sub/aud/exp/nbf/iat/jti) vs public vs private, mỗi claim nghĩa là gì và verify ra sao, đặt gì/không nên đặt, kích thước payload thật và đánh đổi khi token phình to."
---

## Mục lục

- [1. Claim là gì — và vì sao tên claim lại ngắn cũn](#1-claim-là-gì--và-vì-sao-tên-claim-lại-ngắn-cũn)
- [2. Ba loại claim: registered, public, private](#2-ba-loại-claim-registered-public-private)
- [3. Bảy registered claim — mổ từng cái](#3-bảy-registered-claim--mổ-từng-cái)
- [4. iss / sub / aud — bộ ba định danh ngữ cảnh](#4-iss--sub--aud--bộ-ba-định-danh-ngữ-cảnh)
- [5. exp / nbf / iat — bộ ba thời gian](#5-exp--nbf--iat--bộ-ba-thời-gian)
- [6. jti — định danh token & chống replay](#6-jti--định-danh-token--chống-replay)
- [7. Public vs private claim — quy ước đặt tên](#7-public-vs-private-claim--quy-ước-đặt-tên)
- [8. Đặt gì vào payload — và đặt bao nhiêu](#8-đặt-gì-vào-payload--và-đặt-bao-nhiêu)
- [9. Claims là ảnh chụp đông cứng](#9-claims-là-ảnh-chụp-đông-cứng)
- [10. Anti-patterns cần tránh](#10-anti-patterns-cần-tránh)
- [11. Tóm tắt — Cheat sheet](#11-tóm-tắt--cheat-sheet)

---

## 1. Claim là gì — và vì sao tên claim lại ngắn cũn

Payload của JWT là một object JSON; mỗi cặp khoá–giá trị trong đó gọi là một **claim** (một "lời khẳng định"). `{"sub":"42"}` nghĩa là token *khẳng định* "chủ thể là user 42".

```
PAYLOAD = tập hợp các CLAIM = các lời khẳng định về chủ thể & token:
   {"iss":"auth.shop", "sub":"42", "exp":1700003600, "role":"admin"}
     │                  │           │                  │
     "ai phát ra"       "về ai"     "hết hạn khi nào"  "quyền gì"
```

Vì sao tên claim chuẩn lại cụt lủn (`sub`, `aud`, `exp`) chứ không phải `subject`, `audience`, `expiration`?

```
┌───────────────────────────────────────────────────────────────────────────┐
│  LÝ DO: JWT đi kèm MỌI request → mỗi byte payload nhân lên hàng triệu lần.│
│     "exp" (3 ký tự) vs "expiration" (10) → tiết kiệm 7 byte MỖI token.    │
│     RFC 7519 cố tình chọn tên 3 ký tự để token gọn nhất có thể.           │
│  → đây cũng là triết lý chung: payload càng nhỏ càng tốt (xem §8).        │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Claim chỉ là dữ liệu trong payload — và payload **đọc được, không mã hoá** (xem [Encoding vs Encryption](/fundamentals/encoding-vs-encryption/)). Giá trị của claim đến từ việc nó nằm trong vùng **được chữ ký bảo vệ**: sửa một claim làm hỏng chữ ký. Nên claim đáng tin *sau khi verify*, nhưng không bao giờ *bí mật*.

---

## 2. Ba loại claim: registered, public, private

RFC 7519 chia claim làm ba nhóm theo mức độ "ai định nghĩa tên":

```
┌─────────────────┬──────────────────────────────────────────────────────────┐
│ REGISTERED      │ tên ĐÃ ĐĂNG KÝ trong IANA, có ngữ nghĩa chuẩn.           │
│ (chuẩn)         │ iss, sub, aud, exp, nbf, iat, jti — 7 cái phổ biến.      │
│                 │ → thư viện JWT hiểu & verify tự động (exp, nbf, aud...). │
├─────────────────┼──────────────────────────────────────────────────────────┤
│ PUBLIC          │tên do bạn đặt nhưng ĐĂNG KÝ/đặt theo namespace chống đụng│
│ (công khai)     │ vd "https://myapp.com/role" hoặc tên trong IANA registry.│
│                 │ → dùng khi token được CHIA SẺ giữa nhiều bên.            │
├─────────────────┼──────────────────────────────────────────────────────────┤
│ PRIVATE         │ tên TỰ ĐẶT, chỉ có ý nghĩa giữa các bên đã thống nhất.   │
│ (riêng tư)      │ vd "role", "tenant_id", "plan" — nội bộ hệ của bạn.      │
│                 │ → rủi ro: trùng tên với bên khác nếu token đi ra ngoài.  │
└─────────────────┴──────────────────────────────────────────────────────────┘
```

```
VÍ DỤ MỘT PAYLOAD CÓ CẢ BA LOẠI:
   {
     "iss": "https://auth.shop",      ← registered
     "sub": "1234567890",             ← registered
     "exp": 1700003600,               ← registered
     "https://shop.com/role":"admin", ← public (namespace URI chống đụng)
     "tenant_id": "acme",             ← private (chỉ hệ bạn hiểu)
     "plan": "pro"                    ← private
   }
```

> [!NOTE]
> Quy tắc thực dụng: dùng **registered** cho mọi thứ có sẵn (đừng tự chế `expiry` khi đã có `exp`); dùng **private** (tên ngắn) cho claim nội bộ khi token chỉ luẩn quẩn trong hệ của bạn; chỉ cần **public** (namespace URI) khi token được bên thứ ba tiêu thụ và có nguy cơ trùng tên claim.

---

## 3. Bảy registered claim — mổ từng cái

| Claim | Tên đầy đủ | Ý nghĩa | Verifier làm gì |
|-------|-----------|---------|-----------------|
| `iss` | Issuer | Ai phát token | So với issuer kỳ vọng |
| `sub` | Subject | Token nói về ai (user id) | Dùng làm danh tính |
| `aud` | Audience | Token dành cho dịch vụ nào | So với chính mình |
| `exp` | Expiration Time | Hết hạn (epoch giây) | Từ chối nếu now ≥ exp |
| `nbf` | Not Before | Chưa hiệu lực trước mốc này | Từ chối nếu now < nbf |
| `iat` | Issued At | Phát lúc nào (epoch giây) | Tính tuổi token / sliding |
| `jti` | JWT ID | Định danh duy nhất của token | Chống replay / denylist |

```
┌───────────────────────────────────────────────────────────────────────────┐
│  3 CLAIM ĐỊNH DANH NGỮ CẢNH (WHO/WHERE):  iss · sub · aud                 │
│  3 CLAIM THỜI GIAN (WHEN):                exp · nbf · iat                 │
│  1 CLAIM ĐỊNH DANH TOKEN (WHICH):         jti                             │
│  → nhớ theo nhóm dễ hơn nhớ rời 7 cái.                                    │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Tất cả claim này **tùy chọn** theo RFC — JWT không bắt buộc có cái nào. Nhưng "tùy chọn theo chuẩn" không có nghĩa "tùy chọn cho bạn": một verifier an toàn nên **bắt buộc** `exp` (chống token sống mãi) và `aud`/`iss` (chống token dùng nhầm chỗ). Bỏ chúng là cả một họ lỗ hổng (xem [Common Vulnerabilities](/security/common-vulnerabilities/)).

---

## 4. iss / sub / aud — bộ ba định danh ngữ cảnh

Ba claim này trả lời "token này, do AI phát, nói về AI, dành cho AI" — và việc verify chúng chống được cả một lớp tấn công "dùng token đúng-chữ-ký nhưng sai-ngữ-cảnh".

```
iss (issuer)   "ai phát ra token này"
   vd "https://auth.shop"
   VERIFY: verifier so iss với danh sách issuer tin cậy.
   CHỐNG:  token do issuer lạ phát (vd hệ khác, hoặc attacker tự dựng IdP).

sub (subject)  "token nói về CHỦ THỂ nào" — thường là user id
   vd "1234567890"  (NÊN là id ổn định, KHÔNG nên là email/username dễ đổi)
   DÙNG:   định danh user xuyên suốt; ghép (iss, sub) là khoá định danh toàn cục.

aud (audience) "token dành cho DỊCH VỤ nào tiêu thụ"
   vd "api.shop"  hoặc  ["api.shop","billing.shop"]
   VERIFY: mỗi service kiểm aud CÓ CHỨA chính nó không.
   CHỐNG:  token cấp cho service A bị mang sang dùng ở service B.
```

```
VÌ SAO aud QUAN TRỌNG — kịch bản "token dùng nhầm chỗ":
   auth server cấp token cho "profile-service" (aud="profile")
   nếu "payment-service" KHÔNG kiểm aud → chấp nhận luôn token đó
   → token đọc-profile vô tình mở được cả thanh toán. Kiểm aud chặn điều này.
```

> [!TIP]
> Đặt `sub` là **id nội bộ ổn định** (vd UUID/số), đừng đặt là email hay username — vì người dùng đổi email/username thì danh tính trong mọi token cũ vỡ. Ghép `(iss, sub)` cho danh tính toàn cục khi gộp nhiều nguồn đăng nhập. Chi tiết ở [Audience, Issuer, Subject](/internals/audience-issuer-subject/).

---

## 5. exp / nbf / iat — bộ ba thời gian

Cả ba dùng **epoch giây** (NumericDate) — số giây kể từ 1970-01-01 UTC. Đây là nguồn của một lỗi kinh điển.

```
exp = 1700003600   →  2023-11-14T23:13:20Z   (hết hạn)
iat = 1700000000   →  2023-11-14T22:13:20Z   (phát)
exp - iat = 3600 giây = 60 phút  → TTL của token này là 1 giờ
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  LỖI KINH ĐIỂN: exp = Date.now()  (JavaScript trả MILI-giây!)             │
│     Date.now()           = 1700000000000  (mili-giây)                     │
│     epoch giây đúng       = 1700000000     (chia 1000)                    │
│  → đặt exp = Date.now() → token "hết hạn" vào năm ~55000 → sống ~1700 năm!│
│  ĐÚNG: exp = Math.floor(Date.now()/1000) + ttlGiây                        │
└───────────────────────────────────────────────────────────────────────────┘
```

```
nbf (not before): token CHƯA hiệu lực trước mốc này.
   dùng khi: phát token để dùng trong tương lai (vé hẹn giờ, lịch kích hoạt).
   VERIFY: now < nbf → từ chối (token "chưa tới giờ").

CLOCK SKEW: đồng hồ các máy lệch nhau vài giây → token vừa phát có thể bị
   máy khác coi là "chưa tới nbf" hoặc "đã quá exp". → cho phép leeway vài giây.
```

> [!IMPORTANT]
> `exp` là claim quan trọng nhất về mặt bảo mật: nó giới hạn cửa sổ thiệt hại khi token bị lộ. Token không `exp` = lộ là vĩnh viễn. Verifier nên **bắt buộc** `exp`, và issuer nên đặt TTL **ngắn** cho access token (5–15'). Cơ chế đầy đủ (sliding vs absolute, leeway) ở [Expiration & Renewal](/lifecycle/expiration-and-renewal/) và [Time-based Claims](/internals/time-based-claims/).

---

## 6. jti — định danh token & chống replay

`jti` (JWT ID) là một chuỗi **duy nhất** cho mỗi token. Nó là mảnh ghép biến JWT stateless thành "có thể theo dõi/thu hồi từng cái".

```
jti dùng để:
   ① CHỐNG REPLAY: lưu jti đã dùng → từ chối nếu thấy lại (token một-lần).
   ② DENYLIST/THU HỒI: muốn revoke một token cụ thể → thêm jti vào denylist.
   ③ AUDIT/TRUY VẾT: log jti → lần ra token nào gây ra hành động nào.

   {"sub":"42","jti":"a1b2c3d4","exp":1700003600}
                  └── duy nhất mỗi token (UUID/random) ──┘
```

```
ĐÁNH ĐỔI: dùng jti để chống replay/denylist nghĩa là verifier phải TRA STORE
   (jti đã dùng chưa? jti có trong denylist?) → mất tính stateless thuần.
   → chỉ thêm khi thực sự cần (token một-lần, hoặc cần thu hồi từng token).
```

> [!NOTE]
> `jti` là cầu nối giữa "JWT stateless" và "cần kiểm soát từng token". Nó không miễn phí (phải có store) nhưng cho phép các kịch bản như magic-link một-lần, thu hồi token bị lộ, hay phát hiện reuse. Xem cách dùng trong [Blacklist vs Whitelist](/lifecycle/blacklist-whitelist/) và [Revocation & Logout](/lifecycle/revocation-and-logout/).

---

## 7. Public vs private claim — quy ước đặt tên

```
VẤN ĐỀ ĐỤNG TÊN (collision): token đi qua nhiều bên, mỗi bên có claim "role"
   với ý nghĩa khác nhau → hiểu nhầm quyền.

GIẢI PHÁP:
   • PRIVATE (token nội bộ): tên ngắn "role","tenant" — chấp nhận được vì chỉ
     hệ bạn đọc; rủi ro đụng tên = thấp.
   • PUBLIC (token chia sẻ ra ngoài): đặt theo NAMESPACE URI để chống đụng:
        "https://shop.com/role": "admin"
        "https://shop.com/tenant": "acme"
     hoặc dùng tên đã đăng ký trong IANA JWT registry.
```

```
QUY ƯỚC THỰC TẾ (OIDC dùng nhiều): claim hồ sơ chuẩn hoá sẵn —
   name, email, email_verified, picture, locale...  (định nghĩa trong OIDC)
   → nếu làm OIDC, dùng các tên chuẩn này thay vì tự chế.
```

> [!TIP]
> Đừng over-engineer namespace cho hệ nội bộ: nếu token của bạn chỉ luẩn quẩn giữa frontend và backend của chính bạn, `"role":"admin"` là đủ. Chỉ leo lên namespace URI khi token thực sự đi ra ngoài (federation, bên thứ ba tiêu thụ). Phức tạp hoá sớm là một dạng lãng phí.

---

## 8. Đặt gì vào payload — và đặt bao nhiêu

Câu hỏi thực dụng nhất: nhét gì vào claims? Nguyên tắc: **tối thiểu đủ dùng**.

```
ĐO KÍCH THƯỚC THẬT (base64url của payload):
   tối thiểu  {sub, exp}                                =  39 byte
   điển hình  {iss,sub,aud,exp,iat,nbf,jti}             = 175 byte
   "béo"      + name,email,roles[3],permissions[4],dept = 410 byte
   → payload béo gấp ~10 lần tối thiểu, đi kèm MỌI request.
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  NÊN ĐẶT:                                                                 │
│     • định danh: sub (+ iss)                                              │
│     • ngữ cảnh:  aud                                                      │
│     • thời gian: exp, iat (nbf nếu cần)                                   │
│     • quyền Ở MỨC THÔ đủ để phân quyền nhanh: role / scope (vài giá trị)  │
│                                                                           │
│  KHÔNG NÊN ĐẶT:                                                           │
│     • mật khẩu, secret, khoá  → lộ (payload đọc được)                     │
│     • PII nhạy cảm: số CMND, thẻ, địa chỉ, sức khoẻ → lộ + ràng buộc luật │
│     • dữ liệu hay đổi: số dư, giỏ hàng → claim là ảnh chụp đông cứng (§9) │
│     • danh sách quyền CHI TIẾT dài dằng dặc → token phình, khó cập nhật   │
└───────────────────────────────────────────────────────────────────────────┘
```

```
QUYỀN: role thô trong token, chi tiết tra ngoài
   token mang  "role":"admin"  (1 giá trị thô)
   chi tiết "admin được làm gì" → tra ở resource server (DB/policy), KHÔNG nhồi token.
   → token nhỏ + đổi policy không cần phát lại token.
```

> [!WARNING]
> Cám dỗ "token tự chứa nên nhét hết vào cho khỏi query" dẫn tới hai vấn đề: (1) token phình to đi kèm mọi request (băng thông, nguy cơ vượt giới hạn header), (2) dữ liệu trong token là **ảnh chụp** — đổi ở DB không cập nhật token đang sống (xem §9). Giữ payload tối thiểu; tra dữ liệu tươi từ nguồn khi cần.

---

## 9. Claims là ảnh chụp đông cứng

Đây là hệ quả sâu nhất của "tự chứa" và là nguồn của nhiều bug logic.

```
t0  user có role="editor" → phát JWT {"sub":"42","role":"editor","exp": t0+3600}
t1  admin HẠ quyền user xuống role="viewer" trong DB
t1..exp  user VẪN gửi JWT cũ ghi "role":"editor"
         → resource server đọc claim → vẫn cho quyền editor!
         → quyền trong TOKEN ≠ quyền trong DB cho tới khi token hết hạn.
```

```
┌────────────────────────────────────────────────────────────────────────────┐
│  CLAIM = ẢNH CHỤP TẠI LÚC PHÁT, không phải "trạng thái hiện tại".          │
│  Hệ quả: mọi thay đổi quyền/trạng thái chỉ có hiệu lực ở token PHÁT SAU đó.│
│                                                                            │
│  GIẢM ĐAU:                                                                 │
│     • TTL access NGẮN → ảnh chụp cũ hết hạn nhanh (5–15')                  │
│     • quyền nhạy cảm → kiểm TƯƠI ở resource server, đừng tin claim         │
│     • cần thu hồi tức thì → denylist theo jti / tokensValidAfter           │
└────────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Quy tắc vàng: **đặt vào claim những gì đúng-tại-lúc-phát và ít đổi (danh tính, issuer); KHÔNG đặt thứ thay đổi liên tục hoặc cần chính xác tức thì (số dư, quyền nhạy cảm).** Với quyền quan trọng (xoá dữ liệu, chuyển tiền), luôn kiểm tươi ở server thay vì tin role trong token. Liên hệ TTL ở [Expiration & Renewal](/lifecycle/expiration-and-renewal/).

---

## 10. Anti-patterns cần tránh

| Anti-pattern | Hậu quả | Thay bằng |
|--------------|---------|-----------|
| `exp = Date.now()` (mili-giây) | TTL sai ~1700 năm | `Math.floor(Date.now()/1000)+ttl` |
| Không có `exp` | Token sống mãi, lộ là vĩnh viễn | Luôn set exp, TTL ngắn |
| Verifier bỏ kiểm `aud`/`iss` | Token dùng nhầm dịch vụ/issuer lạ | Ghim audience & issuer kỳ vọng |
| Đặt PII/secret trong claim | Lộ (payload đọc được) | Claims tối thiểu; tra từ DB |
| `sub` = email/username | Đổi email → vỡ danh tính token cũ | `sub` = id nội bộ ổn định |
| Nhồi danh sách quyền chi tiết | Token phình, khó cập nhật | role/scope thô + tra policy ngoài |
| Tin role trong token cho thao tác nhạy cảm | Stale claim giữ quyền đã thu hồi | Kiểm tươi ở server cho quyền quan trọng |
| Tự chế `expiry`/`userid` thay registered | Thư viện không verify tự động | Dùng `exp`/`sub` chuẩn |
| Claim hay đổi (số dư, giỏ hàng) | Ảnh chụp đông cứng → sai số | Để ngoài token, tra tươi |

---

## 11. Tóm tắt — Cheat sheet

```
┌─────────────────────────────── CLAIMS ────────────────────────────────────┐
│                                                                           │
│  BA LOẠI:  registered (iss,sub,aud,exp,nbf,iat,jti) · public (namespace)  │
│            · private (tên tự đặt, nội bộ)                                 │
│                                                                           │
│  NHÓM REGISTERED:                                                         │
│     WHO/WHERE  iss (ai phát) · sub (về ai) · aud (cho dịch vụ nào)        │
│     WHEN       exp (hết hạn) · nbf (chưa hiệu lực) · iat (phát lúc nào)   │
│     WHICH      jti (định danh token, chống replay/denylist)               │
│                                                                           │
│  ĐẶT:      định danh + ngữ cảnh + thời gian + quyền THÔ (role/scope)      │
│  ĐỪNG ĐẶT: PII/secret · dữ liệu hay đổi · quyền chi tiết dài              │
│                                                                           │
│  NHỚ:  epoch GIÂY (không phải mili-giây) · claim = ẢNH CHỤP đông cứng     │
└───────────────────────────────────────────────────────────────────────────┘
```

```
3 NGUYÊN TẮC GHIM:
   ① REGISTERED TRƯỚC — có sẵn thì đừng tự chế (exp, sub, aud...).
   ② PAYLOAD TỐI THIỂU — mỗi byte đi kèm mọi request; PII/secret không vào token.
   ③ CLAIM LÀ ẢNH CHỤP — quyền nhạy cảm kiểm tươi ở server, TTL ngắn để ảnh mau cũ.
```

> [!NOTE]
> Đọc tiếp: [Encoding vs Encryption](/fundamentals/encoding-vs-encryption/) (vì sao claim đọc được), [Time-based Claims](/internals/time-based-claims/) (exp/nbf/iat sâu hơn), [Audience, Issuer, Subject](/internals/audience-issuer-subject/) (bộ ba ngữ cảnh), và [Token Validation Flow](/internals/token-validation-flow/) (verifier kiểm claim ra sao).
