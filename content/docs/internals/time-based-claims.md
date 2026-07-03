---
title: "Time-based Claims — exp, nbf, iat, và Đồng Hồ"
description: "Mổ xẻ 3 claim thời gian của JWT — exp (khi nào hết hạn), nbf (khi nào bắt đầu có hiệu lực), iat (khi nào được phát hành) — cùng bài toán clock skew, replay attack, và TTL chuẩn cho từng loại token. Văn phong đời thường, ẩn dụ vé xem phim, kèm bảng TTL thực chiến và code."
---

# Time-based Claims — exp, nbf, iat, và Đồng Hồ

## Mục lục

- [Ba claim quyết định khi nào token sống — và khi nào chết](#1-ba-claim-quyết-định-khi-nào-token-sống--và-khi-nào-chết)
- [Ba claim thời gian — cái nào làm gì](#2-ba-claim-thời-gian--cái-nào-làm-gì)
- [exp — khi nào token hết hạn, và vì sao quan trọng nhất](#3-exp--khi-nào-token-hết-hạn-và-vì-sao-quan-trọng-nhất)
- [nbf — khi nào token bắt đầu có hiệu lực](#4-nbf--khi-nào-token-bắt-đầu-có-hiệu-lực)
- [iat — khi nào token được phát hành](#5-iat--khi-nào-token-được-phát-hành)
- [Bài toán clock skew — vì sao server và client chênh nhau vài giây](#6-bài-toán-clock-skew--vì-sao-server-và-client-chênh-lệch-mấy-giây)
- [TTL chuẩn cho từng loại token — bảng tham chiếu](#7-ttl-chuẩn-cho-từng-loại-token--bảng-tham-chiếu)
- [Replay attack — token hợp lệ nhưng bị dùng lại](#8-replay-attack--token-hợp-lệ-nhưng-bị-dùng-lại)
- [Hai cái bẫy phổ biến khi xử lý thời gian](#9-hai-cái-bẫy-phổ-biến-khi-xử-lý-thời-gian)
- [Code thực chiến — validate time claims đúng cách](#10-code-thực-chiến--validate-time-claims-đúng-cách)
- [Tóm tắt — Cheat sheet](#11-tóm-tắt--cheat-sheet)

---

## 1. Ba claim quyết định khi nào token sống — và khi nào chết

Một JWT access token không tự biết khi nào "hết hạn" — nó chỉ là một chuỗi ký tự có chữ ký. Vòng đời của token (sinh ra, bắt đầu có hiệu lực, hết hạn) do **ba claim thời gian** quyết định: `iat`, `nbf`, `exp`. Trong ba cái đó, `exp` (expiration) là quan trọng nhất và đáng được để ý nhất.

Bỏ quên `exp` là lỗi sơ đẳng nhưng vẫn gặp: token sinh ra mà không có hạn dùng thì nó **sống vĩnh viễn**. Một khi bị lộ — qua header `Authorization` sniff trên WiFi công cộng, qua log bị leak, qua XSS — kẻ tấn công giữ token đó dùng được mãi mãi, cho đến khi admin chủ động revoke (mà nhiều hệ thống còn không có cơ chế revoke). Token bị lộ lại thường không được phát hiện ngay, nên hậu quả thường nặng nề.

Để dễ hình dung vị trí của ba claim trên dòng thời gian của một token:

```diagram
   Dòng thời gian của một token:
   ─────┬───────────┬───────────────────────┬──────────►
        │ iat       │ nbf                   │ exp
        │           │                       │
   (phát hành)  (bắt đầu      |     (hết hạn —
                 hiệu lực)    │      reject mọi request)
                               │
                     ← khoảng token hợp lệ →
```

- **`iat`** (Issued At) — thời điểm token được phát hành, chỉ mang ý nghĩa ghi chú.
- **`nbf`** (Not Before) — token chỉ bắt đầu có hiệu lực từ thời điểm này (trước đó verifier phải reject).
- **`exp`** (Expiration) — thời điểm token hết hạn, sau đó verifier phải reject. Đây là ranh giới sống chết.

Doc này mổ xẻ chi tiết ba claim trên, cùng bài toán đồng hồ đi kèm: clock skew giữa server và client, replay attack khi token bị dùng lại, và TTL chuẩn cho từng loại token.

---

## 2. Ba claim thời gian — cái nào làm gì

JWT có đúng **3 claim liên quan đến thời gian** (đều là **registered claim** trong RFC 7519). Hiểu nhầm vai trò của một trong ba là source bug.

### 2.1. Bảng tổng quan

| Claim | Tên đầy đủ | Nghĩa | Bắt buộc? | Kiểm tra khi verify? |
|-------|-----------|-------|-----------|----------------------|
| `exp` | Expiration Time | Token hết hạn lúc nào | **Nên có** (access token) | **Có** — reject nếu quá `exp` |
| `nbf` | Not Before | Token chỉ hiệu lực từ lúc nào | Tuỳ chọn | Có (nếu có trong token) |
| `iat` | Issued At | Token được phát hành lúc nào | Tuỳ chọn | Không (chỉ thông tin) |

```diagram
   Dòng thời gian của một token:
   ─────┬───────────┬───────────────────────┬──────────►
        │ iat       │ nbf                   │ exp
        │           │                       │
   (phát hành)  (bắt đầu      |     (hết hạn —
                 hiệu lực)    │      reject mọi request)
                               │
                     ← khoảng token hợp lệ →
```

### 2.2. Ẩn dụ: vé xem phim

Hiểu bằng đời thường — JWT giống **vé xem phim**:

```diagram
   ┌─────────────────────────────────────────────┐
   │  VÉ XEM PHIM                                │
   │                                             │
   │  iat: vé in lúc 18:00    (khi vé được phát) │
   │  nbf: vào rạp từ 19:30   (cửa mở lúc 19:30) │
   │  exp: vé hết hạn 20:15   (phim chiếu 20:15) │
   │                                             │
   │  ─ 19:00 đến rạp → cửa CHƯA mở (nbf)        │
   │  ─ 19:30 đến rạp → vào được ✓               │
   │  ─ 20:30 đến rạp → phim đã chiếu, hết (exp) │
   └─────────────────────────────────────────────┘
```

- **`iat`** = thời điểm in vé (chỉ ghi chú, không ai kiểm)
- **`nbf`** = cửa rạp mở lúc nào (trước đó không cho vào)
- **`exp`** = vé hết hạn lúc nào (sau đó không dùng được)

> [!NOTE]
> Tất cả 3 claim đều là **Unix timestamp** (số giây từ 01/01/1970 UTC), không phải chuỗi ISO date. `{ "exp": 1735689600 }` đúng, `{ "exp": "2025-12-31" }` sai format và sẽ bị thư viện reject.

---

## 3. exp — khi nào token hết hạn, và vì sao quan trọng nhất

`exp` (Expiration Time) là claim thời gian duy nhất **nên có trong mọi access token**. Nó định nghĩa **thời gian sống tối đa** của token — qua thời điểm đó, verifier phải reject.

### 3.1. exp làm gì

```diagram
   Token: { "sub": "u1", "exp": 1735689600 }

   Verifier nhận request kèm token:
      now = current Unix timestamp
      if now >= exp:
         → REJECT (401, "token expired")
      else:
         → chấp nhận (còn hiệu lực)
```

`exp` là **hạn sử dụng** của token. Giống sữa có hạn sử dụng — qua hạn, dù sữa trông vẫn tốt, vứt đi.

### 3.2. Vì sao exp quan trọng nhất — giới hạn thiệt hại

`exp` không giữ cho token "không bị lộ" — nó giới hạn **thời gian kẻ tấn công có window dùng token đã lộ**.

```diagram
   Token CÓ exp (vd 15 phút):
   ┌─────────────────────────────────────────┐
   │ 00:00: phát hành token (exp=00:15)      │
   │ 00:05: token bị lộ (WiFi sniff)         │
   │ 00:05–00:15: kẻ tấn công DÙNG ĐƯỢC      │ ← window 10 phút
   │ 00:15: token hết hạn → vô dụng          │
   └─────────────────────────────────────────┘
   Thiệt hại tối đa: 10 phút sử dụng

   Token KHÔNG có exp:
   ┌─────────────────────────────────────────┐
   │ 00:00: phát hành token                  │
   │ 00:05: token bị lộ                      │
   │ 00:05 → ∞: kẻ tấn công dùng MÃI MÃI     │ ← window VÔ HẠN
   └─────────────────────────────────────────┘
   Thiệt hại tối đa: VÔ HẠN (cho đến khi admin revoke)
```

<Callout type="error" title="exp là primary defense khi token bị lộ">
Không có cách nào đảm bảo token không bao giờ bị lộ — XSS, WiFi sniff, log leak, malware đều có thể lộ token. **`exp` là lớp phòng thủ cuối**: khi token đã lộ, `exp` giới hạn window thiệt hại. Access token ngắn (5-15 phút) → dù lộ, kẻ tấn công chỉ có 15 phút. Đó là lý do access token PHẢI có `exp` ngắn, refresh token mới cho dài hơn.
</Callout>

### 3.3. exp có thể bị thiếu

Đây là điểm dễ quên: **`exp` là tuỳ chọn trong RFC**. Một token không có `exp` vẫn là JWT hợp lệ về mặt cấu trúc. Nhiều thư viện verify **không reject** token thiếu `exp` theo mặc định — chúng chỉ reject nếu `exp` có *và* đã quá hạn.

```diagram
   Token A: { "sub":"u1", "exp": 1735689600 }
            → verifier check exp → reject nếu quá hạn ✓

   Token B: { "sub":"u1" }   ← KHÔNG có exp
            → verifier mặc định: không check gì → chấp nhận MÃI ⚠
```

> [!IMPORTANT]
> Phải config verifier **require `exp`** — reject mọi access token không có `exp`. Vì `jsonwebtoken` (Node) và nhiều thư viện **không có option require native**, phải check thủ công sau khi verify: `if (payload.exp === undefined) throw`. Trong PyJWT: kiểm tra `payload.get('exp') is not None` sau decode. Mặc định các thư viện **không require** — đây là gap chết người.

---

## 4. nbf — khi nào token bắt đầu có hiệu lực

`nbf` (Not Before) là claim ít được dùng nhưng quan trọng trong vài tình huống. Nó định nghĩa **thời điểm token bắt đầu có hiệu lực** — trước `nbf`, verifier phải reject.

### 4.1. Khi nào cần nbf

`nbf` ít dùng vì đa số token phát hành là dùng ngay. Nhưng có 3 tình huống cần `nbf`:

| Tình huống | Ví dụ | Vì sao cần `nbf` |
|-----------|-------|------------------|
| **Token trước thời gian** | Subscription bắt đầu từ 01/01 | Token cấp trước đó, không dùng được tới 01/01 |
| **Giảm window replay** | Token nghi bị sniff | Phát hành token mới với `nbf` = sau khi phát hiện |
| **Đồng bộ multi-region** | Token cấp ở region khác giờ | Tránh race condition giữa các region |

```diagram
   Tình huống: subscription start
   ┌─────────────────────────────────────────────────┐
   │ 12/30: user mua subscription                    │
   │        → cấp token: nbf=01/01, exp=01/30        │
   │ 12/30: user dùng token → REJECT (chưa tới nbf)  │
   │ 01/01: user dùng token → ✓ (đã tới nbf)         │
   │ 01/30: token hết hạn (exp)                      │
   └─────────────────────────────────────────────────┘
```

### 4.2. Verify nbf đúng cách

```diagram
   Verifier logic:
      now = current timestamp
      if (nbf present AND now < nbf):
         → REJECT (401, "token not yet valid")
      else:
         → tiếp tục check exp, iss, aud...
```

`nbf` chỉ check **nếu có** trong token. Token không có `nbf` = hiệu lực ngay lập tức.

> [!TIP]
> Đừng lạm dụng `nbf`. Đa số case không cần — nếu token dùng ngay, để token không có `nbf`. Dùng `nbf` khi **thực sự có lý do** token không được dùng trước một thời điểm. Lạm dụng `nbf` chỉ tăng phức tạp và tạo bug (quên config clock skew → reject oan).

---

## 5. iat — khi nào token được phát hành

`iat` (Issued At) là claim **chỉ mang tính thông tin** — verifier không reject dựa trên `iat`. Nó ghi lại thời điểm token được tạo.

### 5.1. iat dùng để làm gì

```diagram
   Token: { "sub":"u1", "iat":1735689000, "exp":1735690000 }

   iat dùng để:
   ├── Tính tuổi token: now - iat = "token này 5 phút tuổi"
   ├── Detect token cũ bất thường (đã exp nhưng vẫn gửi)
   ├── Audit: token này cấp khi nào?
   └── Rotate: nếu iat quá cũ, ép refresh
```

### 5.2. iat không phải để verify

Đừng nhầm `iat` với `exp`. `iat` **không bao giờ** dùng để reject — nó chỉ ghi chú.

```diagram
   SAI:  if (now - iat > max_age) reject("token too old")
         → dùng iat như exp thứ hai, sai mục đích

   ĐÚNG: exp quyết định "còn hiệu lực không"
         iat chỉ để audit/log/rotate logic
```

<Callout title="iat hữu ích cho rotation">
Một pattern phổ biến: service check `iat` để biết token có cần rotate không. Vd: nếu `iat` quá 7 ngày (refresh token), ép user đăng nhập lại. Đây không phải verify (token vẫn hợp lệ về exp), mà là **policy rotation** chủ động. `iat` cung cấp dữ liệu để ra quyết định policy, không phải để reject.
</Callout>

### 5.3. Quan hệ giữa iat, nbf, exp

Khi cả 3 cùng có mặt (thường là vậy), quan hệ logic phải là:

```diagram
   iat ≤ nbf ≤ exp

   iat: phát hành lúc 18:00
   nbf: hiệu lực từ 19:30 (≥ iat — không hiệu lực trước khi phát hành!)
   exp: hết hạn lúc 20:15 (≥ nbf — phải hiệu lực trước khi hết hạn)

   ⚠ Nếu nbf < iat hoặc exp < nbf → token sai logic, verifier nên reject
```

---

## 6. Bài toán clock skew — vì sao server và client chênh lệch

Đây là bài toán thực tế ít được dạy nhưng gây ra rất nhiều bug production. **Đồng hồ của các máy tính không hoàn toàn khớp nhau** — server A chạy nhanh hơn server B vài giây, client chậm hơn server vài trăm ms.

### 6.1. Vì sao có clock skew

```diagram
   Auth Server:    12:00:00.000
   API Server:     11:59:58.500   ← chậm 1.5 giây so với auth
   Client mobile:  12:00:01.200   ← nhanh 1.2 giây

   Mỗi máy đều "think" giờ mình đúng, nhưng thực tế chênh nhau vài giây
```

Nguồn gây chênh lệch:

- **NTP sync chưa kịp** — server mới boot, đồng hồ chưa sync
- **Network latency** — client tính timestamp chậm hơn server thật
- **Container timezone** — Docker container có thể sai timezone
- **Virtual machine drift** — VM đồng hồ drift theo thời gian

### 6.2. Clock skew làm vỡ token

Không có clock skew tolerance, token **bị reject oan** liên tục:

```diagram
   Auth server phát hành: exp = 12:00:00 (giờ auth server)
   API server verify lúc: 12:00:01 (giờ API server, nhanh hơn 1 giây)
   → API server: now (12:00:01) >= exp (12:00:00) → REJECT "expired"

   Nhưng thực tế token mới hết hạn 1 giây trước (theo API server),
   theo auth server thì vẫn còn 1 giây → reject OAN
```

### 6.3. Giải pháp: clock skew tolerance (leeway)

Mọi thư viện JWT đều có option **clock skew tolerance** — cho phép lệch vài giây:

```diagram
   exp = 12:00:00
   clockSkew = 60 giây

   Verifier logic:
      now = current timestamp
      if (now > exp + clockSkew):   ← cho phép lệch 60s
         → REJECT
      else:
         → accept

   Tức là: token có exp 12:00:00 vẫn dùng được tới 12:01:00 (với skew 60s)
```

| Thư viện | Option |
|----------|--------|
| `jsonwebtoken` (Node) | `verify(token, key, { clockTimestamp, clockTolerance })` |
| PyJWT (Python) | `jwt.decode(token, leeway=timedelta(seconds=60))` |
| jjwt (Java) | `.setAllowedClockSkewSeconds(60)` |

<Callout type="warn" title="Clock skew không phải miễn phí">
Clock skew tolerance cho phép token dùng **sau khi exp** vài giây — đó là trade-off. Skew 60s nghĩa là token đã "hết hạn" vẫn dùng được 60s nữa → window thiệt hại khi token bị lộ tăng 60s. Đừng set skew quá cao (vd 1 giờ) chỉ để "fix bug" — đó là dấu hiệu auth server lệch giờ, cần fix NTP thay vì tăng skew. **Skew chuẩn: 30-60 giây**, không hơn.
</Callout>

---

## 7. TTL chuẩn cho từng loại token — bảng tham chiếu

Bao lâu thì token nên hết hạn? Câu trả lời phụ thuộc loại token. Đây là bảng tham chiếu thực chiến, dựa trên practice của Google, Auth0, AWS Cognito:

| Loại token | TTL khuyến nghị | Vì sao |
|-----------|-----------------|--------|
| **Access token** | **5-15 phút** | Ngắn nhất — giới hạn thiệt hại tối đa khi lộ |
| **ID token** (OIDC) | 5-15 phút | Cùng access token — chỉ để auth lần đầu |
| **Refresh token** (web) | 1-7 ngày | Cho phép rotate access token mà khỏi đăng nhập lại |
| **Refresh token** (mobile) | 30-90 ngày | Mobile UX — không bắt đăng nhập liên tục |
| **Refresh token** (SPA) | 1-30 ngày | Tùy mức độ nhạy cảm |
| **Service token** (machine) | 1 giờ | Có thể rotate qua client_credentials |

### 7.1. Vì sao access token phải NGẮN

```diagram
   Access token 15 phút + Refresh token 7 ngày:
   ┌───────────────────────────────────────────────┐
   │ 00:00: access token T1 cấp (exp 00:15)        │
   │ 00:15: access token T1 hết hạn                │
   │        → dùng refresh token → cấp T2 mới      │
   │ 00:30: T2 hết hạn → refresh → T3              │
   │ ...                                           │
   │ 7 ngày: refresh token hết hạn → đăng nhập lại │
   └───────────────────────────────────────────────┘

   Nếu access token T1 bị lộ: window thiệt hại = 15 phút
   Nếu refresh token bị lộ: window = 7 ngày (nhưng lưu ở nơi an toàn hơn)
```

Nguyên lý: **token mang đi (access) ngắn + token lưu kỹ (refresh) dài**. Access token đi trong mọi request → dễ lộ → ngắn. Refresh token chỉ dùng 1 endpoint → khó lộ hơn → dài hơn nhưng phải lưu kỹ (httpOnly cookie, không localStorage). Chi tiết: [access-token-vs-refresh-token](/lifecycle/access-token-vs-refresh-token/).

<Callout title="Đừng kéo dài access token để 'tránh đăng nhập'">
Một sai lầm phổ biến: set access token TTL = 7 ngày "cho user khỏi đăng nhập lại". Hệ quả: token bị lộ → kẻ tấn công dùng được 7 ngày. Giải pháp đúng: **access token ngắn + refresh token dài** — user vẫn khỏi đăng nhập (refresh tự động), nhưng access token lộ chỉ thiệt hại 15 phút. UX tốt + bảo mật tốt.
</Callout>

---

## 8. Replay attack — token hợp lệ nhưng bị dùng lại

Bài toán liên quan chặt chẽ với time claims: **replay attack** — kẻ tấn công bắt được token, dùng lại nhiều lần trong window token còn hiệu lực.

### 8.1. Replay attack là gì

```diagram
   00:00: user gọi POST /api/transfer (amount=100)
          → request kèm Authorization: Bearer eyJ...token
          → server xử lý, chuyển 100

   00:05: kẻ tấn công (đã sniff token) dùng lại:
          POST /api/transfer (amount=10000)
          Authorization: Bearer eyJ...token  (cùng token, còn hiệu lực)
          → server: token ✓ → xử lý chuyển 10000  💀
```

Token hợp lệ, chưa hết hạn, chữ ký đúng — server không cách nào biết đây là "token bị dùng lại" chứ không phải user chủ động.

### 8.2. Ba lớp phòng thủ

| Lớp | Cơ chế | Hiệu quả |
|-----|--------|----------|
| **TTL ngắn** (exp) | Access token 5-15 phút | Window replay ngắn |
| **Nonce/jti** | Token có ID duy nhất, server track đã dùng | Chặn replay từng token |
| **HTTPS + HSTS** | Mã hoá đường truyền | Ngăn sniff từ đầu |

```diagram
   Lớp 1 (TTL): access token 15 phút
                → replay chỉ dùng được trong 15 phút

   Lớp 2 (jti): token có jti (UUID)
                server lưu "đã thấy jti này" → reject lần 2
                → chặn hoàn toàn replay (nhưng cần server stateful)

   Lớp 3 (HTTPS): mã hoá đường truyền
                → kẻ tấn công không sniff được token từ đầu
                → ngừa từ gốc
```

> [!NOTE]
> `jti` (JWT ID) là claim duy nhất của từng token — như số serial trên vé. Khi dùng kết hợp với server tracking, `jti` biến token thành **one-time use** (dùng 1 lần rồi vứt). Nhưng điều này đánh mất tính **stateless** của JWT — server phải lưu set các `jti` đã thấy. Trade-off: stateless (không cần jti tracking) vs anti-replay (cần jti tracking). Đa số chọn stateless + TTL ngắn + HTTPS.

---

## 9. Hai cái bẫy phổ biến khi xử lý thời gian

### 9.1. Bẫy 1: dùng thời gian client để verify

```diagram
   SAI:  client gửi timestamp trong request
         server: if (clientTime > exp) reject
         → kẻ tấn công gửi clientTime giả (nhỏ hơn exp) → bypass

   ĐÚNG: server dùng ĐỒNG HỒ CỦA CHÍNH MÌNH (server clock)
         → không tin timestamp từ client
```

Thời gian verify phải luôn là **đồng hồ server**, không bao giờ dùng thời gian client gửi. Đây là lý do `exp`/`nbf`/`iat` được verify bằng `Date.now()` của server, không phải giá trị từ request.

### 9.2. Bẫy 2: timezone mess

```diagram
   SAI:  exp = "2025-12-31 23:59:59 GMT+7"
         → chuỗi ISO, không phải Unix timestamp
         → thư viện reject hoặc parse sai

   ĐÚNG: exp = 1735689599  (Unix timestamp UTC)
         → độc lập timezone, chuẩn RFC
```

Tất cả time claims phải là **Unix timestamp (UTC)**, không bao giờ dùng chuỗi ngày giờ có timezone. TimeZone gây confusion và bug parse.

<Callout type="warn" title="Đừng sinh exp bằng Date string">
Một lỗi phổ biến ở developer mới: set `exp` bằng `Date().toString()` hoặc ISO string. RFC 7519 yêu cầu `exp` là **NumericDate** — số giây từ epoch UTC. Dùng chuỗi → thư viện reject, hoặc tệ hơn, parse nhầm thành timestamp khác → token có hiệu lực bất thường. Luôn: `Math.floor(Date.now() / 1000) + ttl`.
</Callout>

---

## 10. Code thực chiến — validate time claims đúng cách

Mẫu code Node.js validate đầy đủ 3 time claims + clock skew + require exp.

```typescript
import jwt from 'jsonwebtoken';

const CLOCK_SKEW_SECONDS = 60; // cho phép lệch 60 giây

export function validateToken(token: string): jwt.JwtPayload {
  // 1. Verify chữ ký + check exp tự động (nếu có) + clock skew
  const payload = jwt.verify(token, process.env.JWT_SECRET!, {
    algorithms: ['HS256'],           // whitelist thuật toán
    clockTolerance: CLOCK_SKEW_SECONDS,  // skew 60s
    // ignoreExpiration: false,      // mặc định đã check exp
    // ignoreNotBefore: false,       // mặc định đã check nbf
  }) as jwt.JwtPayload;

  // 2. ★ Require exp cho access token (mặc định thư viện không require)
  if (payload.exp === undefined) {
    throw new Error('access token must have exp');
  }

  // 3. (Tuỳ chọn) Policy: max age dựa trên iat
  //    Vd refresh token phải được rotate trong 7 ngày
  if (payload.iat !== undefined) {
    const MAX_REFRESH_AGE = 7 * 24 * 3600; // 7 ngày
    const age = Math.floor(Date.now() / 1000) - payload.iat;
    if (age > MAX_REFRESH_AGE) {
      throw new Error('token too old, must re-login');
    }
  }

  // 4. nbf đã được jwt.verify check tự động (nếu có trong token)
  //    Không cần check thủ công

  return payload;
}

// Khi phát hành token:
export function issueAccessToken(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      sub: userId,
      iat: now,                    // issued at (thông tin)
      exp: now + 15 * 60,          // hết hạn sau 15 phút (BẮT BUỘC)
      // nbf: now,                 // không cần — hiệu lực ngay
    },
    process.env.JWT_SECRET!,
    { algorithm: 'HS256' },
  );
}
```

<Callout type="warn" title="PyJWT / jjwt tương tự">
Pattern giống nhau ở mọi ngôn ngữ: (1) thư viện tự check `exp`/`nbf` nếu có, (2) **phải tự require `exp`** (mặc định không require), (3) set clock skew 30-60s. PyJWT: `jwt.decode(token, leeway=60)`. jjwt: `.setAllowedClockSkewSeconds(60)`. Đừng quên step 2 — đó là gap chết người.
</Callout>

---

## 11. Tóm tắt — Cheat sheet

**Ba claim thời gian:**

```diagram
╭────────────────────────────────────────────────────────────────────╮
│              TIME CLAIMS — CHEAT SHEET                             │
│                                                                    │
│  exp  — Expiration  — khi nào hết hạn    ★ QUAN TRỌNG NHẤT         │
│  nbf  — Not Before  — khi nào bắt đầu hiệu lực                     │
│  iat  — Issued At   — khi nào phát hành (chỉ thông tin)            │
│                                                                    │
│  Format: Unix timestamp (số giây từ 01/01/1970 UTC)                │
│  Quan hệ: iat ≤ nbf ≤ exp                                          │
╰────────────────────────────────────────────────────────────────────╯
```

**5 nguyên tắc bất di bất dịch:**

| # | Nguyên tắc | Vì sao |
|---|-----------|--------|
| 1 | **Access token PHẢI có `exp`** (5-15 phút) | Giới hạn thiệt hại khi lộ |
| 2 | **Verifier phải require `exp`** | Mặc định thư viện không require |
| 3 | **Clock skew 30-60 giây** | Tránh reject oan do lệch đồng hồ |
| 4 | **Dùng đồng hồ server, không tin client** | Tránh bypass bằng giả timestamp |
| 5 | **Unix timestamp UTC, không ISO string** | Tránh timezone confusion |

**Bảng TTL chuẩn:**

| Token | TTL | Lý do |
|-------|-----|-------|
| Access | 5-15 phút | Ngắn — giới hạn thiệt hại |
| Refresh (web) | 1-7 ngày | Rotate access, khỏi đăng nhập lại |
| Refresh (mobile) | 30-90 ngày | UX mobile |
| Service | 1 giờ | Rotate qua client_credentials |

**Bốn câu hỏi thường gặp:**

- **Token không có `exp` có hợp lệ không?** — Có (RFC cho phép), nhưng **phải reject** ở verifier qua config require.
- **`exp` nên set bao lâu?** — Access token 5-15 phút, refresh token 1-7 ngày, tùy loại.
- **Clock skew nên set bao nhiêu?** — 30-60 giây. Quá cao → tăng window thiệt hại; quá thấp → reject oan.
- **`iat` để làm gì?** — Chỉ thông tin (audit, rotation policy), không dùng để reject.

---

## Tài liệu tham khảo

- [RFC 7519 §4.1.4 — `exp` claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
- [RFC 7519 §4.1.5 — `nbf` claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
- [RFC 7519 §4.1.6 — `iat` claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
- [RFC 8725 §4.1.5 — Use Short Expiration Times](https://datatracker.ietf.org/doc/html/rfc8725#section-4.1.5)
- Trong repo: [expiration-and-renewal](/lifecycle/expiration-and-renewal/), [access-token-vs-refresh-token](/lifecycle/access-token-vs-refresh-token/), [issuing-token](/lifecycle/issuing-token/), [token-validation-flow](/internals/token-validation-flow/).
