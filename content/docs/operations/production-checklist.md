---
title: "Production Checklist"
description: "Danh sách kiểm tra trước khi đưa JWT authentication lên production: gom theo nhóm (thuật toán & khóa, cấp, truyền, lưu, verify, thu hồi, vận hành, vận hành sự cố) với mức độ ưu tiên P0/P1/P2, cấu hình mẫu, và tiêu chí Go/No-Go rõ ràng."
---

# Production Checklist

## Mục lục

- [Tổng quan](#tổng-quan)
- [Cách dùng checklist này](#cách-dùng-checklist-này)
- [P0 — Chặn release nếu thiếu](#p0--chặn-release-nếu-thiếu)
- [1. Thuật toán & khóa](#1-thuật-toán--khóa)
- [2. Cấp token](#2-cấp-token)
- [3. Truyền token](#3-truyền-token)
- [4. Lưu token](#4-lưu-token)
- [5. Verify token](#5-verify-token)
- [6. Thu hồi & logout](#6-thu-hồi--logout)
- [7. Observability & vận hành](#7-observability--vận-hành)
- [8. Sẵn sàng ứng phó sự cố](#8-sẵn-sàng-ứng-phó-sự-cố)
- [9. Bảng Go / No-Go](#9-bảng-go--no-go)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan

Đây là cổng kiểm tra cuối cùng trước khi auth JWT phục vụ người dùng thật. Khác với [Security Best Practices](/security/security-best-practices/) (giải thích *vì sao*), doc này là **danh sách hành động** để rà soát theo nhóm và quyết định **Go / No-Go**.

```
   Mỗi mục được gắn ưu tiên:
   ┌──────┬────────────────────────────────────────────────────────┐
   │ P0   │ Thiếu = LỖ HỔNG → CHẶN release                          │
   │ P1   │ Nên có trước launch; thiếu = nợ kỹ thuật rủi ro cao      │
   │ P2   │ Tốt để có; lên kế hoạch sau launch                       │
   └──────┴────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Quy tắc Go/No-Go: **mọi mục P0 phải ✅ thì mới được release.** Một mục P0 chưa đạt (vd verify không có allowlist thuật toán) là lỗ hổng có thể bị khai thác ngay — không có ngoại lệ "để sau". P1/P2 có thể vào backlog có thời hạn.

---

## Cách dùng checklist này

<Steps>
<Step>
### Rà từng nhóm

Đi qua mục 1→8, đánh dấu từng dòng ✅/❌/N/A. Mỗi dòng ghi rõ ưu tiên.
</Step>
<Step>
### Tổng hợp P0

Gom mọi P0. Còn một P0 ❌ → **No-Go**, sửa rồi rà lại.
</Step>
<Step>
### Quyết định P1/P2

P1 thiếu → cần lý do + ngày khắc phục. P2 → backlog.
</Step>
<Step>
### Ký Go/No-Go

Điền [bảng Go/No-Go](#9-bảng-go--no-go), người chịu trách nhiệm ký xác nhận.
</Step>
</Steps>

---

## P0 — Chặn release nếu thiếu

Bản rút gọn để xem nhanh — chi tiết từng mục ở các phần dưới:

```
□ [P0] TLS bắt buộc mọi chặng (không có HTTP trần)
□ [P0] Verify dùng allowlist thuật toán cố định (vd ['RS256']) — KHÔNG đọc alg từ token
□ [P0] Verify kiểm exp + iss + aud (không bỏ cổng nào)
□ [P0] Dùng verify (không dùng decode) cho MỌI quyết định phân quyền
□ [P0] Secret HMAC ≥256-bit ngẫu nhiên / private key trong KMS — KHÔNG commit vào repo
□ [P0] Access token TTL ngắn (5–15') ; refresh revoke được
□ [P0] Refresh token KHÔNG ở localStorage (cookie HttpOnly hoặc tương đương)
□ [P0] KHÔNG log token / KHÔNG đặt token trên URL
□ [P0] Negative test (alg:none, sai chữ ký, hết hạn, sai aud) PASS trong CI
```

<Callout type="error" title="Tuyệt đối không launch nếu">
(1) <code>verify</code> không truyền <code>algorithms</code> → dính <code>alg:none</code>/confusion; (2) dùng <code>decode</code> để phân quyền; (3) secret/khóa hardcode trong repo; (4) refresh token nằm ở <code>localStorage</code>; (5) chạy HTTP không TLS. Mỗi cái là một lỗ hổng khai thác được ngay.
</Callout>

---

## 1. Thuật toán & khóa

```
□ [P0] Thuật toán phù hợp kiến trúc:
        • 1 bên ký+verify (monolith)   → HS256 chấp nhận được
        • nhiều verifier (phân tán)    → RS256/ES256/EdDSA (verifier chỉ cần PUBLIC key)
□ [P0] HMAC secret ≥256-bit NGẪU NHIÊN (randomBytes(32)); RSA ≥2048-bit
□ [P0] Khóa/secret nạp từ secret manager / KMS — KHÔNG hardcode, KHÔNG commit
□ [P1] Private key giữ trong KMS/HSM, không export ra app khi có thể
□ [P1] Mỗi khóa có kid; quy trình xoay khóa định kỳ + khẩn cấp (overlap window)
□ [P2] Diễn tập (drill) xoay khóa khẩn đã chạy thử ít nhất 1 lần
```

> [!TIP]
> Quy tắc chọn alg: *một bên ký, nhiều bên verify → bất đối xứng (RS/ES/EdDSA)*. Verifier chỉ giữ public key nên lộ cũng không ký giả được — phù hợp microservices. Chi tiết: [HMAC vs RSA vs ECDSA](/cryptography/hmac-vs-rsa-vs-ecdsa/), [Key Rotation](/cryptography/key-rotation/).

---

## 2. Cấp token

```
□ [P0] Chỉ cấp SAU khi xác thực chắc chắn (mật khẩu + MFA nếu bật); fail → KHÔNG ký gì
□ [P0] Claims TỐI THIỂU: iss/sub/aud/iat/exp/jti + scope/roles — KHÔNG PII/secret
□ [P0] Issuer CỐ ĐỊNH alg + TTL phía server — KHÔNG để client chọn
□ [P1] sub = id ổn định (không email/PII); aud ghim đúng dịch vụ tiêu thụ
□ [P1] jti từ CSPRNG ≥128-bit (revoke/log/anti-replay); gắn kid đang active
□ [P1] Đọc quyền TƯƠI khi cấp (không cache quyền cũ → tránh stale claim)
□ [P2] Cấp idempotent (Idempotency-Key) → không nhân bản refresh
```

```javascript
// Cấu hình cấp mẫu (jose) — đối chiếu checklist
new SignJWT({ scope, roles })
  .setProtectedHeader({ alg: 'RS256', kid: ACTIVE_KID })  // alg+kid cố định phía server
  .setIssuer('https://auth.example.com')
  .setSubject(userId)                                      // id, không PII
  .setAudience('api.orders')                               // ghim audience
  .setIssuedAt()
  .setExpirationTime('15m')                                // TTL ngắn
  .setJti(crypto.randomBytes(16).toString('hex'))          // 128-bit
  .sign(privateKey);
```

---

## 3. Truyền token

```
□ [P0] TLS (HTTPS) BẮT BUỘC mọi chặng; bật HSTS
□ [P0] Token KHÔNG nằm trên URL/query string (rò qua log/Referer/lịch sử)
□ [P0] KHÔNG log token ở client/server/proxy/CDN
□ [P1] Access token gửi qua Authorization: Bearer header
□ [P1] Cookie token: Secure + Path hẹp (vd /token)
□ [P2] Giới hạn kích thước token chấp nhận (chống JWT bomb/DoS)
```

<Callout type="warn">
Token trong URL là rò rỉ âm thầm phổ biến nhất: lọt vào access log mọi tầng (LB, CDN, app), lịch sử trình duyệt, và header <code>Referer</code> khi tải tài nguyên ngoài. Luôn đặt token ở header. Chi tiết: <a href="/security/xss-csrf-token-theft/">XSS/CSRF Token Theft</a>.
</Callout>

---

## 4. Lưu token

```
□ [P0] Refresh token KHÔNG ở localStorage/sessionStorage/IndexedDB
□ [P0] Refresh token → cookie HttpOnly + Secure + SameSite=Strict/Lax (web)
□ [P1] Access token → memory (biến JS), gửi qua Authorization header
□ [P1] Mobile: refresh → Keychain (iOS)/Keystore (Android), không prefs plaintext
□ [P1] KHÔNG persist token qua redux-persist/vuex-persist
□ [P2] Hệ nhạy cảm cao → cân nhắc BFF (token giữ ở server)
```

> [!NOTE]
> Quy luật bất biến: *nơi nào JS đọc được thì XSS đọc được*. Vì vậy loại `localStorage`/`sessionStorage`/`IndexedDB` khỏi danh sách lưu token. Cây quyết định đầy đủ: [Secure Storage](/security/secure-storage/).

---

## 5. Verify token

Nơi tập trung nhiều lỗ hổng nhất — verify là **nhiều cổng**, thiếu cổng nào là lỗ hổng:

```
□ [P0] algorithms: [...] ALLOWLIST cố định (vd ['RS256']) — KHÔNG đọc alg từ token
        → chặn alg:none + algorithm confusion cùng lúc
□ [P0] LUÔN verify (KHÔNG decode) cho mọi quyết định phân quyền
□ [P0] Bắt buộc & kiểm exp (+leeway 30–60s cho clock skew)
□ [P0] Ghim issuer (iss) + audience (aud) = chính dịch vụ này
□ [P1] Khóa verify từ NGUỒN TIN CẬY cấu hình sẵn (JWKS của đúng issuer)
        → KHÔNG tin jwk/jku/x5u trong header
□ [P1] kid tra qua allowlist/prepared statement — KHÔNG readFile(kid)/nối chuỗi SQL
□ [P1] Validate SCHEMA claim sau verify (kiểu + ràng buộc; aud có thể là mảng)
□ [P1] FAIL CLOSED: verify lỗi/khóa không lấy được/claim lạ → 401, không "cho qua"
□ [P2] Cache JWKS + cooldown + jitter; giới hạn refetch theo kid lạ (chống storm)
```

```javascript
// Cấu hình verify mẫu (jose) — đối chiếu checklist
const { payload } = await jwtVerify(token, jwks, {
  algorithms: ['RS256'],                  // [P0] allowlist
  issuer: 'https://auth.example.com',     // [P0] ghim iss
  audience: 'api.orders',                 // [P0] ghim aud
  clockTolerance: '30s',                  // [P0] leeway clock skew
  requiredClaims: ['exp', 'sub', 'aud'],  // [P0] bắt buộc exp
});
```

> [!IMPORTANT]
> 80% giá trị phòng thủ verify nằm ở hai dòng: `algorithms: ['RS256']` + `{ issuer, audience }`, cộng "luôn verify không decode". Pipeline 7 cổng đầy đủ: [Luồng xác thực JWT](/internals/token-validation-flow/).

---

## 6. Thu hồi & logout

```
□ [P0] Access TTL NGẮN → giới hạn cửa sổ rủi ro & độ trễ thu hồi mặc định
□ [P1] Refresh revoke được (opaque + store) → logout 1 thiết bị vô hiệu session đó
□ [P1] "Logout mọi thiết bị"/đổi mật khẩu → tokensValidAfter=now (hoặc tokenVersion++)
□ [P1] Refresh rotation + reuse detection (phát hiện token bị trộm)
□ [P2] Denylist theo jti (nếu cần hủy 1 access NGAY): entry TTL = exp − now
□ [P2] Lộ khóa → quy trình xoay khẩn (overlap) sẵn sàng
```

> [!NOTE]
> JWT stateless không có "nút hủy" sẵn — mọi thu hồi tức thì đều tốn thêm trạng thái server. Chọn ít-nhất-đủ-dùng theo mức nhạy cảm. Chi tiết: [Revocation & Logout](/lifecycle/revocation-and-logout/), [Blacklist vs Whitelist](/lifecycle/blacklist-whitelist/).

---

## 7. Observability & vận hành

```
□ [P0] KHÔNG log token/secret; redact Authorization tự động ở tầng logger
□ [P1] Metric: jwt_issued_total, verify_failures{reason}, refresh_reuse_detected_total
□ [P1] Cảnh báo: reuse detection > 0 (nghi trộm); verify_failures tăng đột biến
□ [P1] Audit log thao tác nhạy cảm (jti/sub/action/ts), append-only
□ [P1] NTP đồng bộ mọi node (tránh clock skew gây 401 hàng loạt)
□ [P2] Dashboard auth + runbook điều tra sẵn
□ [P2] Tracing gắn sub/jti vào span (không gắn token)
```

> [!TIP]
> Hai tín hiệu giá trị nhất cần có trước launch: `refresh_reuse_detected_total` (token bị trộm) và `verify_failures{reason}` (tấn công/cấu hình sai). Chi tiết: [Observability và Audit](/operations/observability-and-audit/).

---

## 8. Sẵn sàng ứng phó sự cố

Không chỉ "cấu hình đúng" mà còn "khi có sự cố thì làm gì":

```
□ [P1] Runbook: lộ khóa ký → xoay khẩn (overlap), gỡ khóa cũ, buộc re-login nếu cần
□ [P1] Runbook: nghi token bị trộm hàng loạt → tokensValidAfter=now cho user/đối tượng
□ [P1] Runbook: rollback an toàn nếu deploy auth gây 401 hàng loạt
□ [P2] Bài tập tabletop: ai bấm nút gì, liên hệ ai, thông báo user thế nào
□ [P2] Kiểm thử khả năng chịu tải /login, /refresh, JWKS endpoint
```

<Callout type="info">
Tham chiếu kịch bản thực tế ở <a href="/case-studies/incident-response-leaked-token/">Incident Response — Leaked Token</a>. Runbook viết sẵn lúc bình yên đáng giá gấp nhiều lần lúc đang cháy.
</Callout>

---

## 9. Bảng Go / No-Go

| Nhóm | P0 đạt? | P1 đạt / có kế hoạch? | Ghi chú |
|------|---------|------------------------|---------|
| 1. Thuật toán & khóa | ☐ | ☐ | |
| 2. Cấp token | ☐ | ☐ | |
| 3. Truyền token | ☐ | ☐ | |
| 4. Lưu token | ☐ | ☐ | |
| 5. Verify token | ☐ | ☐ | |
| 6. Thu hồi & logout | ☐ | ☐ | |
| 7. Observability | ☐ | ☐ | |
| 8. Ứng phó sự cố | ☐ | ☐ | |

```
QUYẾT ĐỊNH:
  • Mọi P0 ✅           → GO
  • Còn P0 ❌           → NO-GO (sửa rồi rà lại)
  • P1 thiếu             → GO có điều kiện (ghi lý do + ngày khắc phục)

Người chịu trách nhiệm: __________   Ngày: ________   Quyết định: GO / NO-GO
```

> [!WARNING]
> Đừng biến checklist thành nghi thức đánh dấu cho có. Mỗi P0 ✅ phải có **bằng chứng**: link cấu hình verify, kết quả negative test trong CI, ảnh chụp secret nằm trong KMS (không phải repo). "Tôi nghĩ là có" không phải là ✅.

---

## Tài liệu tham khảo

- [Security Best Practices — Deep Dive](/security/security-best-practices/) — vì sao của từng mục
- [Luồng xác thực JWT](/internals/token-validation-flow/) — các cổng verify
- [Secure Storage](/security/secure-storage/) — lưu token đúng chuẩn
- [Key Rotation](/cryptography/key-rotation/) — xoay khóa không downtime
- [Testing Auth Flow](/operations/testing-auth-flow/) — negative test cho CI
- [Observability và Audit](/operations/observability-and-audit/) — metric & cảnh báo
- [Migration Strategy](/operations/migration-strategy/) — nếu đang chuyển từ hệ cũ
- [Incident Response — Leaked Token](/case-studies/incident-response-leaked-token/)
