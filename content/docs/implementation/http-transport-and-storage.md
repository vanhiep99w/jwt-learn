---
title: "HTTP Transport & Storage"
description: "Mổ xẻ chi tiết cách truyền và lưu JWT đúng chuẩn: vòng đời token trên đường truyền, Authorization Bearer vs cookie, cookie HttpOnly+Secure+SameSite + tiền tố __Host-/__Secure-, vì sao KHÔNG để token trên URL, mô hình mối đe dọa XSS vs CSRF (kèm phòng thủ double-submit/synchronizer), ma trận nơi lưu, mẫu access-ở-memory + refresh-ở-cookie, CORS cross-origin, mobile Keychain/Keystore, ca sự cố thực tế, anti-patterns và checklist."
---

# HTTP Transport & Storage

## Mục lục

- [1. Bối cảnh: token đúng nhưng vẫn bị đánh cắp](#1-bối-cảnh-token-đúng-nhưng-vẫn-bị-đánh-cắp)
- [2. Tổng quan: vòng đời token trên đường truyền](#2-tổng-quan-vòng-đời-token-trên-đường-truyền)
- [3. Hai câu hỏi tách biệt: truyền và lưu](#3-hai-câu-hỏi-tách-biệt-truyền-và-lưu)
- [4. Truyền token: Authorization Bearer](#4-truyền-token-authorization-bearer)
  - [4.1 Cú pháp & cách đọc đúng](#41-cú-pháp--cách-đọc-đúng)
  - [4.2 Vì sao Bearer ít CSRF hơn](#42-vì-sao-bearer-ít-csrf-hơn)
- [5. Truyền token: Cookie](#5-truyền-token-cookie)
  - [5.1 Thuộc tính cookie bắt buộc](#51-thuộc-tính-cookie-bắt-buộc)
  - [5.2 SameSite và cross-site](#52-samesite-và-cross-site)
  - [5.3 Tiền tố __Host- và __Secure-](#53-tiền-tố-__host--và-__secure-)
- [6. Vì sao KHÔNG để token trên URL](#6-vì-sao-không-để-token-trên-url)
- [7. HTTPS, TLS và HSTS: lớp nền bắt buộc](#7-https-tls-và-hsts-lớp-nền-bắt-buộc)
- [8. Mô hình mối đe dọa: XSS vs CSRF](#8-mô-hình-mối-đe-dọa-xss-vs-csrf)
  - [8.1 Phòng thủ CSRF chiều sâu: double-submit & synchronizer](#81-phòng-thủ-csrf-chiều-sâu-double-submit--synchronizer)
- [9. Ma trận nơi lưu token](#9-ma-trận-nơi-lưu-token)
- [10. Mẫu khuyến nghị: access ở memory + refresh ở cookie](#10-mẫu-khuyến-nghị-access-ở-memory--refresh-ở-cookie)
- [11. CORS cho cross-origin](#11-cors-cho-cross-origin)
- [12. Lưu token trên mobile](#12-lưu-token-trên-mobile)
- [13. Edge cases thực tế — những lỗi khó debug](#13-edge-cases-thực-tế--những-lỗi-khó-debug)
- [14. Anti-patterns cần tránh](#14-anti-patterns-cần-tránh)
- [15. Câu hỏi thường gặp](#15-câu-hỏi-thường-gặp)
- [16. Checklist transport & storage](#16-checklist-transport--storage)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## 1. Bối cảnh: token đúng nhưng vẫn bị đánh cắp

Đội của bạn đã làm "đúng sách" phần mật mã: JWT ký bằng RS256, verify đủ `iss`/`aud`/`exp`, khóa xoay định kỳ. Vậy mà tháng sau, một khách hàng báo tài khoản bị truy cập trái phép — dù mật khẩu chưa bao giờ lộ. Truy vết, bạn phát hiện ba thứ:

```text
1) access_token=eyJ... xuất hiện trong access log của CDN (vì frontend cũ gắn token vào query string)
2) refresh_token nằm trong localStorage → một thư viện analytics bị nhiễm đã đọc và gửi đi
3) cookie phiên thiếu cờ Secure → bị sniff trên Wi-Fi công cộng ở sân bay
```

Không một lỗi nào ở trên thuộc về "ký/verify". Chúng đều thuộc tầng **truyền** (transport) và **lưu** (storage) — tầng mà nhiều đội xem nhẹ vì "token đã ký rồi thì sao mà giả được". Sự thật: kẻ tấn công **không cần giả** token; chúng chỉ cần **lấy được** một token thật. Một JWT ký hoàn hảo vẫn vô dụng về mặt an toàn nếu nó rò qua log, bị XSS đọc, hay bị nghe lén trên đường truyền.

> [!IMPORTANT]
> Bảo mật JWT là một chuỗi: **cấp → truyền → lưu → gửi lại → verify → thu hồi**. Mắt xích yếu nhất quyết định độ an toàn. Doc này tập trung vào hai mắt xích hay bị bỏ quên nhất — *truyền* và *lưu* — và gắn mỗi quyết định kỹ thuật với một mối đe dọa cụ thể (nghe lén, XSS, CSRF, rò log).

---

## 2. Tổng quan: vòng đời token trên đường truyền

```diagram
╭───────────────────────────────────────────────────────────────────────────╮
│                  VÒNG ĐỜI TOKEN — TỪ SERVER ĐẾN REQUEST KẾ TIẾP             │
│                                                                             │
│   [1] CẤP                [2] TRUYỀN VỀ           [3] LƯU                     │
│   server issue           Set-Cookie / body       memory? cookie? store?     │
│   access + refresh  ──▶  qua HTTPS          ──▶   (mục 9, 10)                │
│                              │                        │                      │
│                          rò nếu HTTP/URL          rò nếu XSS đọc được        │
│                                                       │                      │
│   [5] VERIFY        ◀──  [4] GỬI LẠI mỗi request ◀────┘                      │
│   (doc khác)             Authorization / Cookie                             │
│                              │                                              │
│                          rò nếu log/Referer/proxy cắt                       │
╰───────────────────────────────────────────────────────────────────────────╯
```

Mỗi mũi tên là một cơ hội rò rỉ. Doc đi theo đúng thứ tự đó: *truyền* (mục 4–7) trước, *lưu* (mục 9–12) sau, và xuyên suốt là hai mối đe dọa XSS/CSRF (mục 8).

> [!IMPORTANT]
> "Truyền" và "lưu" là **hai quyết định khác nhau**, đừng gộp. *Truyền* quyết định token đi qua header hay cookie (ảnh hưởng CSRF, CORS). *Lưu* quyết định token nằm ở memory/cookie/storage (ảnh hưởng XSS, mất khi reload). Một mẫu an toàn phổ biến kết hợp cả hai: **access token gửi qua `Authorization` + lưu ở memory**, còn **refresh token lưu+gửi qua cookie `HttpOnly`**.

---

## 3. Hai câu hỏi tách biệt: truyền và lưu

| Quyết định | Lựa chọn | Đánh đổi chính |
|------------|----------|----------------|
| **Truyền** (gửi token thế nào) | `Authorization: Bearer` | Client phải tự đính kèm; không tự gửi → ít CSRF; cần lưu token ở nơi JS đọc được |
| | Cookie | Trình duyệt tự gửi; tiện nhưng dính CSRF; có thể `HttpOnly` chống XSS |
| **Lưu** (cất token ở đâu) | Memory (biến JS) | An toàn XSS nhất nhưng mất khi reload |
| | Cookie `HttpOnly` | JS không đọc được (chống XSS) nhưng tự gửi (CSRF) |
| | `localStorage` | Tiện, bền qua reload — nhưng **XSS đọc được** |

<Callout type="info">
Hai câu hỏi này tương tác nhau: nếu gửi qua <code>Authorization</code> header, JS phải đọc được token để đính kèm → không thể để token ở cookie <code>HttpOnly</code>. Nếu để cookie <code>HttpOnly</code> (JS không đọc được), trình duyệt phải tự gửi → bạn dùng cơ chế cookie, không phải header. Hiểu ràng buộc này trước khi chọn.
</Callout>

Một cách tư duy hữu ích: **ai là người chủ động gắn token vào request?**

```diagram
Authorization: Bearer   →  CODE của BẠN chủ động gắn (đọc token từ đâu đó rồi set header)
Cookie                  →  TRÌNH DUYỆT tự động gắn (bạn không viết dòng nào)
```

"Trình duyệt tự gắn" chính là gốc rễ của CSRF: site độc có thể khiến trình duyệt nạn nhân gửi request *kèm cookie* mà không cần đọc được cookie. Ngược lại, "code của bạn chủ động gắn" nghĩa là site độc không thể gắn `Authorization` thay bạn — nên Bearer miễn nhiễm CSRF một cách tự nhiên.

---

## 4. Truyền token: Authorization Bearer

### 4.1 Cú pháp & cách đọc đúng

Cách chuẩn cho API: client đính token vào header mỗi request.

```text
GET /api/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1Ni...payload...signature
```

```javascript
// Client tự đính token (token lấy từ memory — xem mục 10)
const res = await fetch('https://api.example.com/orders', {
  headers: { Authorization: `Bearer ${accessToken}` },
});
```

```javascript
// Server (Express) đọc đúng — KHÔNG dùng replace() cẩu thả
function bearerToken(req) {
  const h = req.headers.authorization;
  if (!h) return null;
  const [scheme, token, ...rest] = h.split(' ');
  if (scheme !== 'Bearer' || !token || rest.length) return null; // đúng "Bearer <1 token>"
  return token.trim();
}
```

<Callout type="warn">
Đừng đọc token bằng <code>h.replace('Bearer ', '')</code>: nếu header là <code>Basic xxx</code> nó vẫn trả về <code>Basic xxx</code> (không khớp "Bearer ") và bạn đem cả chuỗi đó đi verify → lỗi khó hiểu. Cũng đừng so sánh phân biệt hoa thường lỏng lẻo — RFC 6750 quy định scheme là <code>Bearer</code>. Tách theo space và kiểm <code>scheme === 'Bearer'</code> tường minh.
</Callout>

### 4.2 Vì sao Bearer ít CSRF hơn

| Ưu | Nhược |
|----|-------|
| Trình duyệt **không tự gửi** → bề mặt CSRF gần như bằng 0 | Client phải tự quản lý + đính token |
| Hợp API không-trình-duyệt (mobile, service-to-service) | Token phải nằm nơi JS đọc được → cân nhắc XSS |
| Tường minh, dễ debug (thấy rõ header) | Không tự bền qua reload (nếu để memory) |

```diagram
CSRF cần điều gì để thành công?
   → request tự động kèm "thứ chứng minh danh tính" mà nạn nhân không hay biết
   → cookie thỏa điều này (trình duyệt tự gửi)
   → Authorization header KHÔNG (site độc không set được header này cross-origin)
Kết luận: dùng Bearer cho access token = miễn CSRF gần như tự nhiên.
```

> [!TIP]
> `Authorization: Bearer` là lựa chọn mặc định cho **access token** của API. Vì trình duyệt không tự gửi header này, kẻ tấn công không thể lợi dụng CSRF để "mượn" phiên người dùng như với cookie. Đổi lại, token phải nằm nơi JS truy cập được — nên để ở **memory** thay vì `localStorage` (xem [mục 9](#9-ma-trận-nơi-lưu-token)).

---

## 5. Truyền token: Cookie

Cookie phù hợp cho **refresh token** (và phiên web truyền thống): trình duyệt tự gửi, và có thể đặt `HttpOnly` để JS không đọc được.

### 5.1 Thuộc tính cookie bắt buộc

```javascript
res.cookie('refresh_token', refreshToken, {
  httpOnly: true,                 // JS KHÔNG đọc được → chống XSS đánh cắp
  secure: true,                   // chỉ gửi qua HTTPS → chống nghe lén
  sameSite: 'lax',                // giảm CSRF (xem 5.2)
  path: '/auth',                  // chỉ gửi tới endpoint refresh, không gửi mọi request
  maxAge: 7 * 24 * 3600 * 1000,   // hạn cookie ~ hạn refresh token
  // domain: không set nếu không cần share subdomain (mặc định host-only an toàn hơn)
});
```

| Thuộc tính | Tác dụng | Bỏ qua = hậu quả |
|------------|----------|-------------------|
| `HttpOnly` | JS không đọc được cookie | XSS đọc & gửi token đi |
| `Secure` | Chỉ gửi qua HTTPS | Token lộ trên HTTP/nghe lén Wi-Fi |
| `SameSite` | Hạn chế gửi cross-site | Bề mặt CSRF lớn |
| `Path` | Giới hạn URL gửi cookie | Refresh token bị gửi kèm mọi request (lộ thừa) |
| `Max-Age`/`Expires` | Tự xóa khi hết hạn | Cookie sống lâu hơn token, gây nhầm lẫn |
| `Domain` (cẩn thận) | Phạm vi subdomain | Set rộng = subdomain bị chiếm cũng đọc được cookie |

<Callout type="warn">
Thiếu <code>HttpOnly</code> là sai lầm nghiêm trọng nhất: cookie trở thành "localStorage có tên khác" — XSS đọc được. Thiếu <code>Secure</code> khiến token bị gửi qua HTTP và lộ khi nghe lén. Cả hai phải <b>luôn</b> bật cho cookie chứa token. Đừng set <code>Domain</code> rộng (vd <code>.example.com</code>) trừ khi thật sự cần chia sẻ giữa subdomain — cookie host-only (không set Domain) an toàn hơn vì một subdomain bị chiếm không tự động lộ cookie.
</Callout>

### 5.2 SameSite và cross-site

```diagram
SameSite=Strict  → cookie KHÔNG gửi khi điều hướng từ site khác sang
                    (an toàn nhất, nhưng phá vỡ link từ ngoài vào — vd click link
                     trong email tới trang cần đăng nhập sẽ thấy như chưa login)
SameSite=Lax      → gửi khi điều hướng top-level GET (click link), KHÔNG gửi cho
                    request ngầm cross-site (img/form ẩn, POST cross-site) → cân bằng tốt
SameSite=None     → gửi cả cross-site, BẮT BUỘC kèm Secure
                    (chỉ dùng khi frontend & API khác site và thật sự cần)
```

| Mức | Gửi khi click link từ site khác? | Gửi với POST/iframe cross-site? | CSRF |
|-----|-----------------------------------|----------------------------------|------|
| `Strict` | ❌ | ❌ | An toàn nhất, UX kém với link ngoài |
| `Lax` (mặc định mới) | ✅ (GET top-level) | ❌ | Cân bằng tốt cho hầu hết app |
| `None` + `Secure` | ✅ | ✅ | Cần thêm chống CSRF (xem 8.1) |

> [!NOTE]
> `SameSite=Lax` là mặc định hợp lý cho hầu hết app: nó chặn phần lớn CSRF (request ngầm cross-site không kèm cookie) mà không phá trải nghiệm click link từ email/site khác. Chỉ dùng `SameSite=None` (kèm `Secure` bắt buộc) khi frontend và API nằm ở site khác nhau và bạn buộc phải gửi cookie cross-site — khi đó **bắt buộc** thêm chống CSRF (token/double-submit, mục 8.1).

### 5.3 Tiền tố __Host- và __Secure-

Trình duyệt hiện đại hiểu hai tiền tố tên cookie mang ý nghĩa ràng buộc bảo mật do chính trình duyệt ép:

```diagram
__Secure-refresh_token   → trình duyệt CHỈ chấp nhận nếu cookie có cờ Secure (set qua HTTPS)
__Host-refresh_token     → mạnh hơn: phải Secure + KHÔNG có Domain + Path=/ + set từ HTTPS
                           → cookie "ghim" vào đúng host, subdomain không ghi đè được
```

```javascript
// Cookie host-only được trình duyệt ép cứng các ràng buộc bảo mật
res.cookie('__Host-refresh_token', refreshToken, {
  httpOnly: true,
  secure: true,        // bắt buộc với __Host-
  sameSite: 'lax',
  path: '/',           // __Host- yêu cầu path '/' và KHÔNG có domain
});
```

<Callout type="info">
Tiền tố <code>__Host-</code> là một lớp phòng thủ "miễn phí": ngay cả khi code phía sau lỡ set cookie thiếu <code>Secure</code> hoặc cố gắn <code>Domain</code> rộng, trình duyệt sẽ <b>từ chối</b> cookie. Nó chống tấn công "cookie tossing" (subdomain bị chiếm ghi đè cookie của domain cha). Lưu ý <code>__Host-</code> yêu cầu <code>Path=/</code>, nên nếu bạn muốn giới hạn refresh cookie ở <code>/auth</code>, hãy dùng <code>__Secure-</code> kèm <code>path: '/auth'</code>.
</Callout>

---

## 6. Vì sao KHÔNG để token trên URL

Đặt token vào query string (`?token=eyJ...` hay `?access_token=...`) là một trong những rò rỉ phổ biến và nguy hiểm nhất.

```diagram
GET /api/orders?token=eyJhbGci...  ← SAI
       │
       ├── ghi vào access log của server/proxy/CDN         → lộ trong log (giữ hàng tháng)
       ├── ghi vào lịch sử trình duyệt + bookmark           → lộ trên máy client dùng chung
       ├── gửi qua header Referer khi load tài nguyên ngoài → lộ sang bên thứ 3 (ads/analytics)
       ├── nằm trong URL share (copy gửi chat/email)        → lộ qua kênh không kiểm soát
       └── cache bởi proxy trung gian                       → lộ cho người dùng khác sau NAT
```

**Đường rò qua `Referer` rất tinh vi.** Khi trang `https://app.example.com/page?token=eyJ...` load một ảnh hoặc script từ bên thứ ba, trình duyệt mặc định gắn header `Referer: https://app.example.com/page?token=eyJ...` — token bay thẳng sang server của bên thứ ba (CDN ảnh, mạng quảng cáo, công cụ analytics). Dù bạn đặt `Referrer-Policy: no-referrer` để giảm thiểu, **đừng bao giờ** dựa vào đó: gốc rễ vẫn là token không nên ở URL.

> [!WARNING]
> Token **không bao giờ** được đặt trên URL/query string. URL bị ghi vào access log (server, proxy, CDN), lịch sử trình duyệt, và rò qua header `Referer` sang bên thứ ba. Luôn dùng header `Authorization` hoặc cookie. Ngoại lệ hiếm (vd magic link một lần, pre-signed URL) phải dùng token **dùng-một-lần**, **hết hạn cực ngắn** (giây–phút), và chấp nhận rủi ro có ý thức — không dùng cho access/refresh token thường.

---

## 7. HTTPS, TLS và HSTS: lớp nền bắt buộc

Mọi biện pháp lưu/truyền ở trên đều vô nghĩa nếu token đi qua kết nối không mã hóa. Token là "bearer credential" — ai cầm được là dùng được — nên việc nghe lén trên đường truyền = chiếm phiên.

```diagram
KHÔNG TLS:   client ──(HTTP, plaintext)──▶ attacker (cùng Wi-Fi) đọc token ──▶ server
CÓ TLS:      client ──(HTTPS, mã hóa)────▶ attacker chỉ thấy bytes ngẫu nhiên ──▶ server
CÓ HSTS:     trình duyệt TỪ CHỐI hạ cấp về HTTP → chống SSL-strip / chuyển hướng ép HTTP
```

```text
# Server gửi header HSTS để trình duyệt nhớ "chỉ dùng HTTPS với host này"
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

| Biện pháp | Chống | Ghi chú |
|-----------|-------|---------|
| TLS (HTTPS) | Nghe lén, sửa nội dung trên đường | Bắt buộc cho mọi traffic có token |
| HSTS | SSL-strip, ép hạ cấp HTTP | `includeSubDomains` + cân nhắc `preload` |
| Tắt redirect HTTP→HTTPS *giữ* token | Token rò ở request HTTP đầu tiên | Đừng nhận token ở cổng HTTP, kể cả để redirect |

<Callout type="warn">
Một sai lầm tinh vi: server lắng nghe cả cổng 80 (HTTP) "để redirect sang HTTPS". Nếu client lỡ gửi <code>Authorization</code> hoặc cookie tới cổng 80, token đã <b>lộ trước khi</b> redirect xảy ra. Hãy để cổng 80 chỉ redirect <i>các request không kèm credential</i>, dùng HSTS để trình duyệt tự lên HTTPS từ lần sau, và đặt cờ <code>Secure</code> để cookie không bao giờ đi qua HTTP.
</Callout>

---

## 8. Mô hình mối đe dọa: XSS vs CSRF

Chọn nơi truyền/lưu thực chất là chọn phòng thủ trước hai mối đe dọa khác nhau. Hiểu rõ hai cái này là chìa khóa của cả doc.

```diagram
XSS (Cross-Site Scripting)              CSRF (Cross-Site Request Forgery)
───────────────────────────            ──────────────────────────────────
Kẻ tấn công chạy JS TRONG trang bạn     Site độc khiến trình duyệt nạn nhân
→ đọc mọi thứ JS đọc được               TỰ GỬI request kèm cookie sẵn có
→ localStorage, biến JS, cookie KHÔNG   → lợi dụng việc cookie TỰ GỬI
   HttpOnly đều bị đọc                   → KHÔNG đọc được token, chỉ "mượn" phiên
PHÒNG: HttpOnly cookie (JS không đọc),  PHÒNG: SameSite cookie, CSRF token,
       CSP, sanitize/escape input              dùng Authorization header (không tự gửi)
```

Điểm mấu chốt thường bị nhầm:

```diagram
"Để token ở cookie HttpOnly" CHỐNG XSS đọc token   ✅
                              nhưng MỞ ra rủi ro CSRF (cookie tự gửi)  ⚠
"Để token ở Authorization"    CHỐNG CSRF tự nhiên   ✅
                              nhưng token phải nằm nơi JS đọc → cân nhắc XSS  ⚠
→ Không lựa chọn nào "an toàn tuyệt đối"; phải kết hợp (mục 10).
```

| | Cookie thường | Cookie `HttpOnly` | `localStorage` | Memory + Bearer |
|---|---|---|---|---|
| XSS đọc được token? | ✅ (nguy hiểm) | ❌ (an toàn) | ✅ (nguy hiểm) | ⚠ chỉ khi đang chạy |
| Tự gửi (rủi ro CSRF)? | ✅ | ✅ | ❌ | ❌ |

<Callout type="error" title="Vì sao localStorage cho token nhạy cảm là sai">
<code>localStorage</code> bị <b>mọi đoạn JS trên trang</b> đọc được — kể cả script của thư viện bên thứ ba bị nhiễm (supply-chain). Một lỗ hổng XSS duy nhất = lộ toàn bộ access + refresh token, và attacker có thể gửi chúng đi âm thầm. Refresh token (sống lâu) trong <code>localStorage</code> đặc biệt nguy hiểm vì nó cho phép tạo access token mới gần như vô hạn. Đây là lý do mẫu khuyến nghị để refresh ở cookie <code>HttpOnly</code>.
</Callout>

### 8.1 Phòng thủ CSRF chiều sâu: double-submit & synchronizer

Nếu buộc phải dùng cookie cho request làm thay đổi dữ liệu (POST/PUT/DELETE) và `SameSite` không đủ (vd cross-site với `SameSite=None`), thêm một trong hai mẫu chống CSRF:

```diagram
SYNCHRONIZER TOKEN (server giữ trạng thái)
  server tạo csrf_token, gắn vào form/trang  →  client gửi lại trong header/body
  server so khớp với giá trị nó lưu cho phiên  →  khớp mới chấp nhận
  → mạnh, nhưng server phải lưu token theo phiên

DOUBLE-SUBMIT COOKIE (không trạng thái)
  server set cookie csrf=abc (KHÔNG HttpOnly để JS đọc được)
  client đọc cookie, gửi LẠI giá trị đó trong header X-CSRF-Token
  server so khớp cookie vs header  →  khớp mới chấp nhận
  → site độc không đọc được cookie cross-site nên không điền đúng header
```

```javascript
// Double-submit: client đọc cookie csrf (không HttpOnly) và gửi lại trong header
function csrfHeader() {
  const m = document.cookie.match(/(?:^|; )csrf=([^;]+)/);
  return m ? { 'X-CSRF-Token': decodeURIComponent(m[1]) } : {};
}

await fetch('/api/orders', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json', ...csrfHeader() },
  body: JSON.stringify(order),
});
```

```javascript
// Server: so khớp cookie csrf vs header X-CSRF-Token
function checkCsrf(req, res, next) {
  const cookie = req.cookies.csrf;
  const header = req.get('X-CSRF-Token');
  if (!cookie || cookie !== header) return res.status(403).json({ error: 'csrf_failed' });
  next();
}
```

> [!TIP]
> Nếu bạn dùng **mẫu khuyến nghị** (access qua `Authorization: Bearer`), các API thay đổi dữ liệu vốn đã miễn CSRF — chỉ endpoint `/auth/refresh` (dùng cookie) cần để ý. Đặt `/auth/refresh` ở `SameSite=Lax`/`Strict` thường là đủ; chỉ khi cross-site (`SameSite=None`) mới cần thêm double-submit cho refresh.

---

## 9. Ma trận nơi lưu token

| Nơi lưu | Bền qua reload? | XSS đọc? | Tự gửi (CSRF)? | Dùng cho |
|---------|------------------|----------|-----------------|----------|
| **Memory** (biến JS) | ❌ (mất khi reload) | ⚠ chỉ khi đang chạy | ❌ | **Access token** |
| **Cookie `HttpOnly`** | ✅ | ❌ | ✅ (cần SameSite) | **Refresh token** |
| `localStorage` | ✅ | ✅ (nguy hiểm) | ❌ | ❌ Tránh cho token |
| `sessionStorage` | Chỉ trong tab | ✅ (nguy hiểm) | ❌ | ❌ Tránh cho token |
| IndexedDB | ✅ | ✅ (JS đọc được) | ❌ | ❌ Tránh cho token |
| Service Worker (biến) | Theo vòng đời SW | ⚠ trong scope SW | ❌ | Nâng cao, ít dùng |
| Keychain/Keystore | ✅ | Theo OS | ❌ | **Mobile** (mục 12) |

> [!TIP]
> Quy tắc đơn giản: **access token → memory**, **refresh token → cookie `HttpOnly`**. Tránh `localStorage`/`sessionStorage`/`IndexedDB` cho bất kỳ token nào vì JS (và do đó XSS) đọc được. Việc access token mất khi reload không phải vấn đề — dùng refresh token (trong cookie) để lấy access mới ngay khi tải lại trang (silent refresh, xem [mục 10](#10-mẫu-khuyến-nghị-access-ở-memory--refresh-ở-cookie)).

**Một biến thể nâng cao** đôi khi gặp: giữ access token trong biến của một **Service Worker** và để SW tự gắn `Authorization` cho fetch. Ưu điểm: access không nằm trong scope JS của trang (XSS ở trang khó chạm hơn). Nhược: phức tạp, SW có vòng đời riêng, và nếu chính SW bị tiêm mã thì vẫn lộ. Chỉ cân nhắc khi mô hình đe dọa thật sự đòi hỏi.

---

## 10. Mẫu khuyến nghị: access ở memory + refresh ở cookie

Đây là mẫu cân bằng tốt nhất giữa an toàn (XSS/CSRF) và trải nghiệm cho web SPA:

```mermaid
sequenceDiagram
    participant B as Browser (SPA)
    participant A as Auth/API server
    B->>A: POST /login (credentials)
    A-->>B: access (body JSON) + refresh (Set-Cookie HttpOnly)
    Note over B: access lưu ở BIẾN JS (memory), KHÔNG localStorage
    B->>A: GET /orders  (Authorization: Bearer access)
    A-->>B: 200 data
    Note over B: reload trang → access trong memory MẤT
    B->>A: POST /auth/refresh  (cookie refresh tự gửi)
    A-->>B: access MỚI (body) + refresh mới (Set-Cookie, rotation)
    Note over B: tiếp tục với access mới
```

```javascript
// --- LOGIN: server trả access trong body, refresh trong cookie HttpOnly ---
app.post('/login', async (req, res) => {
  const { access, refresh } = await issueTokens(req.body);   // sau khi xác thực
  res.cookie('__Host-refresh_token', refresh, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ access });          // access KHÔNG vào cookie; client giữ ở memory
});

// --- REFRESH: đọc refresh từ cookie, cấp access mới + xoay refresh ---
app.post('/auth/refresh', async (req, res) => {
  const refresh = req.cookies['__Host-refresh_token'];
  if (!refresh) return res.status(401).end();
  const { access, refresh: rotated } = await rotateRefresh(refresh);  // reuse detection bên trong
  res.cookie('__Host-refresh_token', rotated, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ access });
});
```

```javascript
// --- CLIENT: access ở memory; tự refresh khi 401 ---
let accessToken = null;                        // BIẾN memory, không localStorage

async function apiFetch(url, opts = {}) {
  const run = () => fetch(url, {
    ...opts,
    headers: { ...opts.headers, Authorization: `Bearer ${accessToken}` },
    credentials: 'include',                    // để cookie refresh được gửi khi cần
  });
  let res = await run();
  if (res.status === 401) {                    // access hết hạn/mất → silent refresh
    const r = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' });
    if (!r.ok) { redirectToLogin(); return r; }
    accessToken = (await r.json()).access;     // cập nhật access mới vào memory
    res = await run();                         // thử lại request gốc
  }
  return res;
}
```

> [!NOTE]
> Điểm mấu chốt: **access token không bao giờ chạm `localStorage`/cookie** — chỉ sống trong biến JS, mất khi reload và được khôi phục qua silent refresh. **Refresh token không bao giờ chạm JS** — nằm trong cookie `HttpOnly` mà JS không đọc được. Nhờ vậy XSS không lấy được refresh token (sống lâu), còn `Authorization` header tránh CSRF cho access. Mẫu chống refresh đua nhau (queue) và interceptor đầy đủ xem [SPA & Mobile Auth](/implementation/spa-and-mobile-auth/); đánh đổi nơi lưu chi tiết xem [Secure Storage](/security/secure-storage/).

---

## 11. CORS cho cross-origin

Khi SPA (vd `app.example.com`) gọi API ở origin khác (`api.example.com`), trình duyệt áp CORS. Cấu hình sai sẽ chặn cookie/header hoặc mở quá rộng.

```javascript
import cors from 'cors';

app.use(cors({
  origin: ['https://app.example.com'],   // allowlist cụ thể — KHÔNG dùng '*' khi gửi cookie
  credentials: true,                      // cho phép gửi cookie cross-origin
  allowedHeaders: ['Authorization', 'Content-Type', 'X-CSRF-Token'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  maxAge: 600,                            // cache preflight 10 phút (giảm OPTIONS lặp)
}));
```

Trình duyệt gửi **preflight** `OPTIONS` trước các request "non-simple" (có header `Authorization`, content-type JSON, method PUT/DELETE...). Server phải trả đúng các header CORS cho preflight, nếu không request thật bị chặn:

```text
OPTIONS /api/orders            ← preflight tự động của trình duyệt
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: authorization, content-type

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com   ← phải khớp origin cụ thể
Access-Control-Allow-Credentials: true                 ← cho cookie đi kèm
Access-Control-Allow-Headers: authorization, content-type
```

```diagram
QUY TẮC CORS QUAN TRỌNG:
□ credentials: true (gửi cookie) ⇒ origin PHẢI là allowlist cụ thể, KHÔNG được '*'
□ Trình duyệt sẽ TỪ CHỐI '*' + credentials → cookie không gửi được
□ Client fetch phải có credentials: 'include' để cookie đi kèm
□ Trả đúng Access-Control-Allow-Headers cho header tùy chỉnh (Authorization, X-CSRF-Token)
□ Preflight OPTIONS phải trả 2xx; cân nhắc maxAge để cache, giảm OPTIONS lặp
```

<Callout type="warn">
Đặt <code>Access-Control-Allow-Origin: *</code> cùng <code>credentials: true</code> vừa bị trình duyệt chặn, vừa nguy hiểm nếu vô hiệu hóa kiểm tra. Luôn dùng <b>allowlist origin cụ thể</b> khi cần gửi cookie/credentials cross-origin — và <b>đừng</b> phản chiếu mù (reflect) <code>Origin</code> của request vào header trả về mà không kiểm tra allowlist. Nếu frontend và API cùng site (vd qua reverse proxy chung domain), bạn tránh được phần lớn phức tạp CORS lẫn cross-site cookie.
</Callout>

---

## 12. Lưu token trên mobile

Mobile không có `localStorage`/cookie như web; dùng kho an toàn của OS:

```diagram
iOS      → Keychain (mã hóa, gắn với thiết bị, có thể yêu cầu Face/Touch ID)
Android  → Keystore / EncryptedSharedPreferences
React Native → expo-secure-store / react-native-keychain (bọc hai cái trên)
KHÔNG dùng: AsyncStorage / SharedPreferences thường (plaintext, app khác/đọc được khi root)
```

| Nên | Tránh |
|-----|-------|
| Keychain (iOS) / Keystore (Android) | `AsyncStorage`, `UserDefaults`, file plaintext |
| Refresh token trong secure storage | Hardcode token trong code/biến build |
| Cân nhắc yêu cầu sinh trắc học mở khóa token nhạy cảm | Lưu token trong log/crash report |
| Certificate pinning + chỉ HTTPS | Tin tự động mọi CA của hệ điều hành |

> [!TIP]
> Trên mobile, access token vẫn nên giữ ngắn hạn trong memory, refresh token lưu ở Keychain/Keystore. Lưu ý cert pinning + chỉ gọi HTTPS để chống man-in-the-middle khi truyền token. Vì mobile không có khái niệm "cookie HttpOnly", refresh token *do code đọc được* — bù lại bằng kho mã hóa của OS và (tùy mức nhạy cảm) khóa sinh trắc học. Chi tiết: [SPA & Mobile Auth](/implementation/spa-and-mobile-auth/).

---

## 13. Edge cases thực tế — những lỗi khó debug

### 13.1 Proxy/CDN cắt header quá dài

```diagram
Token RS256 có payload lớn (nhiều claim/role) → Authorization header > giới hạn proxy
  Nginx mặc định: large_client_header_buffers 4 8k  → header > 8KB bị từ chối/cắt
  Hậu quả: server nhận token thiếu → "malformed token" → 401 khó hiểu
Khắc phục: giảm claim trong token (đẩy chi tiết sang lookup theo sub), hoặc nới buffer proxy.
```

### 13.2 Cookie không gửi vì SameSite/secure sai môi trường

```diagram
Triệu chứng: login OK, nhưng /auth/refresh luôn 401 "missing cookie"
Nguyên nhân thường gặp:
  - Secure: true nhưng dev chạy http://localhost (cookie Secure không set qua HTTP) → cookie biến mất
  - SameSite: 'none' nhưng quên Secure → trình duyệt loại bỏ cookie
  - Frontend khác site với API nhưng cookie SameSite=Lax → cookie không gửi cross-site
Cách soi: DevTools → Application → Cookies, và tab Network xem cookie có trong request không.
```

### 13.3 Token đúng nhưng "biến mất" sau reload

Đây là *hành vi mong muốn* của mẫu access-ở-memory, không phải bug: reload xóa biến JS → access mất → `bootstrapSession()` gọi `/auth/refresh` để lấy lại. Nếu app báo "đăng xuất sau mỗi F5", kiểm tra đã gọi silent refresh lúc khởi động chưa (xem [SPA & Mobile Auth](/implementation/spa-and-mobile-auth/)).

### 13.4 `Referrer-Policy` rò token cũ

Nếu hệ thống *từng* để token trên URL (legacy), kể cả sau khi sửa, các URL cũ có thể còn trong log/bookmark. Đặt `Referrer-Policy: strict-origin-when-cross-origin` (hoặc `no-referrer` cho trang nhạy cảm) để giảm rò, **và** thu hồi mọi token từng xuất hiện trên URL.

### 13.5 Multi-tab và refresh đua nhau

Khi người dùng mở nhiều tab, mỗi tab có biến `accessToken` riêng (memory không chia sẻ giữa tab). Cùng lúc nhiều tab gặp 401 → nhiều lần gọi `/auth/refresh` → có thể kích hoạt reuse-detection. Giải pháp: dùng `BroadcastChannel`/`localStorage` event để đồng bộ thời điểm refresh giữa các tab, hoặc chấp nhận rotation và để server xử lý grace window (xem [Revocation & Logout](/lifecycle/revocation-and-logout/)).

---

## 14. Anti-patterns cần tránh

| Anti-pattern | Vì sao nguy hiểm | Thay bằng |
|--------------|------------------|-----------|
| Token (nhất là refresh) trong `localStorage` | XSS đọc được toàn bộ | Access→memory, refresh→cookie HttpOnly |
| Token trên URL/query string | Rò qua log, Referer, history | `Authorization` header / cookie |
| Cookie token thiếu `HttpOnly`/`Secure` | XSS đọc / nghe lén | Bật cả hai, dùng `__Host-` |
| `Access-Control-Allow-Origin: *` + credentials | Bị chặn hoặc lộ rộng | Allowlist origin cụ thể |
| Phản chiếu `Origin` vào ACAO không kiểm tra | Bất kỳ site nào cũng gọi được kèm cookie | Kiểm allowlist trước khi echo |
| Nhận token ở cổng HTTP "để redirect" | Lộ token ở request đầu | Chỉ HTTPS + HSTS + cờ Secure |
| `SameSite=None` mà không chống CSRF | Cookie tự gửi cross-site | Thêm double-submit/synchronizer |
| Set `Domain=.example.com` không cần thiết | Subdomain bị chiếm đọc được cookie | Cookie host-only (không set Domain) |
| Mobile lưu token vào `AsyncStorage` | Plaintext, app khác đọc khi root | Keychain/Keystore |

---

## 15. Câu hỏi thường gặp

<Accordions>

<Accordion title="Vậy rốt cuộc localStorage có bao giờ dùng được cho token không?">
Với token *nhạy cảm* (access/refresh) thì không nên. Lý do duy nhất localStorage hấp dẫn là "bền qua reload" — nhưng silent refresh giải quyết việc đó mà không phải đánh đổi an toàn. Nếu bạn buộc phải dùng localStorage (ràng buộc kỹ thuật), hãy giảm thiệt hại: token TTL cực ngắn, CSP chặt, không có script bên thứ ba, và chấp nhận rủi ro có ý thức.
</Accordion>

<Accordion title="Cookie HttpOnly đã chống XSS rồi, sao còn cần lo CSRF?">
Vì HttpOnly chỉ ngăn JS *đọc* cookie — nó không ngăn trình duyệt *tự gửi* cookie. CSRF không cần đọc token; nó lợi dụng đúng việc cookie tự gửi để khiến nạn nhân thực hiện hành động ngoài ý muốn. Đó là lý do cookie cần thêm `SameSite` và (khi cross-site) chống CSRF, trong khi `Authorization: Bearer` thì miễn CSRF tự nhiên.
</Accordion>

<Accordion title="Frontend và API cùng domain thì có cần CORS không?">
Cùng *origin* (scheme + host + port giống hệt) thì không cần CORS. Nếu khác subdomain (`app.example.com` vs `api.example.com`) thì vẫn là cross-origin và cần CORS. Đặt cả hai sau một reverse proxy chung origin là cách đơn giản nhất để tránh cả CORS lẫn cross-site cookie.
</Accordion>

<Accordion title="Có nên dùng Bearer cho cả refresh token không?">
Không nên cho web. Refresh sống lâu, nếu để nơi JS đọc được (để gắn Bearer) thì XSS lấy được — rất nguy hiểm. Hãy để refresh trong cookie HttpOnly để JS không bao giờ chạm tới. Trên mobile (không có cookie HttpOnly) thì refresh nằm trong Keychain/Keystore và code đọc để gọi refresh.
</Accordion>

</Accordions>

---

## 16. Checklist transport & storage

```diagram
TRUYỀN:
□ Access token gửi qua Authorization: Bearer (không qua URL/query)
□ Refresh token gửi qua cookie HttpOnly (path giới hạn; cân nhắc __Host-/__Secure-)
□ Mọi token chỉ đi qua HTTPS/TLS; bật HSTS (includeSubDomains)
□ KHÔNG bao giờ đặt token trên URL/query string
□ Không nhận token ở cổng HTTP (kể cả để redirect)

COOKIE (nếu dùng):
□ HttpOnly + Secure + SameSite (Lax mặc định; None chỉ khi cross-site + kèm Secure)
□ Path giới hạn; maxAge ~ TTL token; cân nhắc tiền tố __Host-
□ KHÔNG set Domain rộng nếu không cần share subdomain
□ SameSite=None ⇒ thêm chống CSRF (double-submit/synchronizer)

LƯU:
□ Access token ở memory (biến JS), KHÔNG localStorage/sessionStorage/IndexedDB
□ Refresh token ở cookie HttpOnly, KHÔNG localStorage/sessionStorage
□ Mobile: Keychain/Keystore, không plaintext storage
□ Có silent refresh để khôi phục access sau reload

CROSS-ORIGIN:
□ CORS origin allowlist cụ thể (không '*' khi credentials; không reflect mù Origin)
□ credentials: true ở server + credentials:'include' ở client nếu dùng cookie
□ Trả đúng Allow-Headers cho header tùy chỉnh; cache preflight (maxAge)

CHỐNG MỐI ĐE DỌA:
□ XSS: HttpOnly cookie + CSP + escape/sanitize input (đừng để token nơi JS đọc được)
□ CSRF: SameSite + (Authorization header tránh CSRF tự nhiên) + double-submit khi cross-site
□ Nghe lén: TLS + HSTS; cờ Secure cho mọi cookie token
```

<Callout type="success" title="Một câu để nhớ">
<b>Access token → Authorization Bearer + memory; refresh token → cookie HttpOnly+Secure+SameSite (ưu tiên __Host-).</b> Không bao giờ để token trên URL, không bao giờ để token (nhất là refresh) trong localStorage, và mọi thứ đi qua HTTPS+HSTS. Mẫu này phòng cả XSS (refresh không cho JS chạm), CSRF (access không tự gửi), lẫn nghe lén (TLS).
</Callout>

---

## Tài liệu tham khảo

- [Secure Storage](/security/secure-storage/) — phân tích sâu nơi lưu token & XSS
- [Common Vulnerabilities](/security/common-vulnerabilities/) — XSS, CSRF, token leakage
- [JWT Threat Model](/security/jwt-threat-model/) — các mối đe dọa khi truyền/lưu
- [Backend API Auth](/implementation/backend-api-auth/) — server đọc & verify Bearer
- [SPA & Mobile Auth](/implementation/spa-and-mobile-auth/) — lưu token ở client, silent refresh có queue
- [Access vs Refresh Token](/lifecycle/access-token-vs-refresh-token/) — vì sao tách hai loại
- [Revocation & Logout](/lifecycle/revocation-and-logout/) — rotation, reuse detection
- [Production Checklist](/operations/production-checklist/) — mục transport/storage là P0
- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 6265bis — Cookies (SameSite, __Host-)](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
