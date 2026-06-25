---
title: "JWT Security Best Practices — Deep Dive"
description: "Checklist tổng hợp bảo mật JWT toàn vòng đời, tổ chức theo nguyên tắc (least privilege, defense-in-depth, secure-by-default, fail-closed) và theo từng giai đoạn (chọn thuật toán → cấp → truyền → lưu → verify → thu hồi → vận hành). Mỗi mục giải thích VÌ SAO + cách kiểm, kèm cấu hình mẫu an toàn, ma trận sai-lầm↔khắc-phục, checklist review PR và phân tầng ưu tiên theo mức nhạy cảm hệ thống."
---

# JWT Security Best Practices — Deep Dive

## Mục lục

- [1. Bốn nguyên tắc nền tảng](#1-bốn-nguyên-tắc-nền-tảng)
- [2. Chọn thuật toán & quản lý khóa](#2-chọn-thuật-toán--quản-lý-khóa)
- [3. Khi cấp token](#3-khi-cấp-token)
- [4. Khi truyền token](#4-khi-truyền-token)
- [5. Khi lưu token](#5-khi-lưu-token)
- [6. Khi verify token](#6-khi-verify-token)
- [7. Khi thu hồi & logout](#7-khi-thu-hồi--logout)
- [8. Vận hành: log, giám sát, xoay khóa](#8-vận-hành-log-giám-sát-xoay-khóa)
- [9. Cấu hình mẫu an toàn (end-to-end)](#9-cấu-hình-mẫu-an-toàn-end-to-end)
- [10. Phân tầng ưu tiên theo mức nhạy cảm](#10-phân-tầng-ưu-tiên-theo-mức-nhạy-cảm)
- [11. Ma trận sai lầm ↔ khắc phục](#11-ma-trận-sai-lầm--khắc-phục)
- [12. Nâng cấp bảo mật cho hệ đang chạy](#12-nâng-cấp-bảo-mật-cho-hệ-đang-chạy)
- [13. Checklist review PR](#13-checklist-review-pr)
- [14. Tóm tắt — Cheat sheet](#14-tóm-tắt--cheat-sheet)

---

## 1. Bốn nguyên tắc nền tảng

Mọi mục cụ thể bên dưới đều là hệ quả của bốn nguyên tắc. Hiểu nguyên tắc thì suy ra được best practice cho cả tình huống chưa liệt kê.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  ① LEAST PRIVILEGE (đặc quyền tối thiểu)                                   │
│     token mang đúng-đủ quyền & sống đúng-đủ lâu cho việc cần. Không hơn.    │
│     → scope hẹp, TTL ngắn, aud đúng dịch vụ, claims tối thiểu.              │
│                                                                             │
│  ② DEFENSE IN DEPTH (phòng thủ nhiều lớp)                                  │
│     không một biện pháp nào là tường thành duy nhất. Lớp này thủng còn lớp │
│     kia. → TLS + chữ ký + verify đủ cổng + storage đúng + revoke + giám sát.│
│                                                                             │
│  ③ SECURE BY DEFAULT (an toàn mặc định)                                    │
│     cấu hình mặc định phải an toàn; muốn nới lỏng phải CHỦ ĐỘNG & có lý do. │
│     → allowlist alg, cookie đủ cờ, từ chối token thiếu exp...               │
│                                                                             │
│  ④ FAIL CLOSED (lỗi thì từ chối)                                          │
│     nghi ngờ/không chắc → TỪ CHỐI, không "cho qua cho chắc chạy".           │
│     → verify lỗi/khóa không lấy được/claim lạ → 401, không fallback "cho qua"│
└───────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Khi gặp một quyết định bảo mật không có trong checklist, hỏi bốn câu: *quyền này có tối thiểu chưa? có lớp phòng thủ nào khác đỡ không? mặc định đã an toàn chưa? lỗi thì có fail-closed không?* — đây là cách suy luận mọi best practice thay vì học thuộc danh sách. Bài này tổng hợp toàn bộ chuỗi Security ([Threat Model](/security/jwt-threat-model/), [Common Vulnerabilities](/security/common-vulnerabilities/), [Algorithm Confusion](/security/algorithm-confusion-deep-dive/), [XSS/CSRF](/security/xss-csrf-token-theft/), [Secure Storage](/security/secure-storage/)).

---

## 2. Chọn thuật toán & quản lý khóa

```
□ Dùng thuật toán mạnh, phù hợp kiến trúc:
   • monolith (issuer = verifier) → HS256 chấp nhận được (secret chung)
   • phân tán (nhiều verifier)    → RS256/ES256/EdDSA (verifier chỉ cần PUBLIC key)
   VÌ SAO: bất đối xứng → verifier lộ key cũng KHÔNG ký giả được; phù hợp microservices.

□ HMAC secret ≥ 256-bit NGẪU NHIÊN (randomBytes(32)), KHÔNG từ điển/cụm từ
   VÌ SAO: brute-force HMAC là OFFLINE; secret yếu vỡ trong mili-giây (xem Common Vulns §3).

□ Khóa ký giữ trong KMS/HSM khi có thể (private key KHÔNG export ra ứng dụng)
   VÌ SAO: khóa ký là tài sản tối thượng — lộ = giả MỌI token (xem Threat Model §2).

□ Mỗi khóa có kid; có quy trình XOAY KHÓA định kỳ + khẩn cấp (overlap window)
   VÌ SAO: xoay được mà không downtime; thu hồi nhanh khi nghi lộ (xem Key Rotation).

□ KHÔNG commit khóa/secret vào repo; nạp từ secret manager; xoay khi nghi lộ.
```

> [!TIP]
> Quy tắc ngón tay cái chọn alg: **một bên ký, nhiều bên verify → bất đối xứng (RS/ES/EdDSA)**; chỉ một bên vừa ký vừa verify → HS256 đủ. Chi tiết so sánh ở [HMAC vs RSA vs ECDSA](/cryptography/hmac-vs-rsa-vs-ecdsa/).

---

## 3. Khi cấp token

```
□ Chỉ cấp SAU khi xác thực chắc chắn (mật khẩu + MFA nếu bật). Fail → KHÔNG ký gì.
□ Đọc quyền TƯƠI tại thời điểm cấp (không cache quyền cũ → tránh stale claim).
□ Claims TỐI THIỂU: iss/sub/aud/iat/exp/jti + scope/roles. KHÔNG PII/secret/dữ liệu lớn.
   VÌ SAO: payload base64url = công khai; claim thừa = lộ + stale + phình token.
□ sub = id ổn định (KHÔNG email/PII). Ghim aud = dịch vụ tiêu thụ.
□ TTL NGẮN cho access (5–15'); refresh dài nhưng OPAQUE + revoke được.
□ jti từ CSPRNG ≥128-bit (revoke/log/anti-replay). Gắn kid ĐANG ACTIVE.
□ Issuer CỐ ĐỊNH alg + TTL — KHÔNG để client chọn (chống algorithm confusion).
□ Cấp idempotent (Idempotency-Key / upsert theo sessionId) → không nhân bản refresh.
```

```
Áp nguyên tắc:
   ① least privilege → scope hẹp + TTL ngắn + claims tối thiểu
   ③ secure default  → alg/TTL cố định phía issuer, không nhận từ request
```

> [!NOTE]
> Chi tiết pipeline cấp và lý do từng claim ở [Issuing Token — Deep Dive](/lifecycle/issuing-token/). Điểm dễ sai nhất: **cache quyền cũ** khi cấp lại (stale claim) và **TTL quá dài "cho tiện"** (khuếch đại mọi rủi ro).

---

## 4. Khi truyền token

```
□ TLS BẮT BUỘC (HTTPS) ở mọi chặng; bật HSTS.
   VÌ SAO: HTTP trần → sniff/MITM trộm token nguyên vẹn.
□ Token ở Authorization: Bearer header — KHÔNG ở URL/query string.
   VÌ SAO: URL rò vào log, lịch sử trình duyệt, header Referer gửi bên thứ ba.
□ KHÔNG log token (access/refresh) ở client/server/proxy/CDN.
□ Cookie token: Secure (chỉ HTTPS) + Path hẹp (vd /token) → giảm nơi token đi qua.
□ Giới hạn KÍCH THƯỚC token chấp nhận (chống JWT bomb/DoS).
```

> [!WARNING]
> Token trong URL là rò rỉ âm thầm phổ biến: nó lọt vào access log của mọi tầng (LB, CDN, app), vào lịch sử trình duyệt, và vào `Referer` khi trang tải tài nguyên ngoài. Luôn đặt token ở header. Xem scenario rò token ở [XSS/CSRF §11](/security/xss-csrf-token-theft/).

---

## 5. Khi lưu token

```
□ access token  → MEMORY (biến JS) + gửi qua Authorization header.
□ refresh token → cookie HttpOnly + Secure + SameSite=Strict/Lax, Path=/token.
□ KHÔNG lưu token ở localStorage/sessionStorage/IndexedDB (JS đọc được → XSS trộm).
□ KHÔNG persist token qua redux-persist/vuex-persist (vô tình ghi ra storage).
□ Mobile: refresh → Keychain (iOS)/Keystore (Android); KHÔNG prefs plaintext.
□ Nhạy cảm cao → cân nhắc BFF (token giữ ở server, trình duyệt chỉ có cookie phiên).
```

```
Áp nguyên tắc:
   ② defense in depth → storage đúng + CSP chống XSS + rotation giảm thiệt hại
   token NGUY HIỂM NHẤT (refresh) che KỸ NHẤT (httpOnly/Keychain).
```

> [!TIP]
> Chi tiết và cây quyết định ở [Secure Storage — Deep Dive](/security/secure-storage/). Quy luật bất biến cần nhớ: *nơi nào JS đọc được thì XSS đọc được* → loại localStorage/sessionStorage/IndexedDB khỏi danh sách lưu token.

---

## 6. Khi verify token

Đây là nơi tập trung nhiều lỗ hổng nhất — verify là **nhiều cổng**, bỏ cổng nào là lỗ hổng:

```
□ algorithms: [...] ALLOWLIST cố định (vd ['RS256']). KHÔNG đọc alg từ token để quyết.
   → chặn alg:none và algorithm confusion cùng lúc.
□ Khóa verify từ NGUỒN TIN CẬY cấu hình sẵn (JWKS của đúng issuer).
   → KHÔNG tin jwk/jku/x5u trong header để chọn khóa.
□ kid: tra qua allowlist / prepared statement; KHÔNG readFile(kid)/nối chuỗi SQL.
□ LUÔN verify chữ ký (KHÔNG dùng decode) cho mọi quyết định phân quyền.
□ Bắt buộc & kiểm exp (+leeway 30–60s cho clock skew); kiểm nbf nếu có.
□ Ghim issuer (iss) + audience (aud) = chính dịch vụ này.
□ Validate SCHEMA claim sau verify (kiểu + ràng buộc; aud có thể là mảng).
□ FAIL CLOSED: verify lỗi / khóa không lấy được / claim bất thường → 401, không "cho qua".
□ So sánh chữ ký bằng hàm CONSTANT-TIME (thư viện chuẩn lo việc này).
```

```
Áp nguyên tắc:
   ③ secure default → allowlist alg, bắt buộc exp/aud/iss
   ④ fail closed    → mọi nghi ngờ → từ chối
```

> [!IMPORTANT]
> 80% giá trị phòng thủ verify nằm ở hai dòng cấu hình: `algorithms: ['RS256']` + `{ issuer, audience }`, cộng "luôn `verify` không `decode`". Pipeline verify đầy đủ 6 cổng ở [Token Validation — Deep Dive](/internals/token-validation-deep-dive/); các lỗ hổng tương ứng ở [Common Vulnerabilities](/security/common-vulnerabilities/).

---

## 7. Khi thu hồi & logout

```
□ Access TTL NGẮN → giới hạn cửa sổ rủi ro & độ trễ thu hồi mặc định.
□ Refresh OPAQUE + lưu store → revoke tức thì + ROTATION + REUSE DETECTION.
□ Logout 1 thiết bị → revoke refresh của session đó (TTL access lo phần còn lại).
□ Logout mọi thiết bị / đổi mật khẩu → tokensValidAfter=now (hoặc tokenVersion++)
   + revoke MỌI refresh của user.
□ Denylist theo jti (nếu cần hủy 1 access NGAY): entry TTL = exp − now (không phình).
□ Lộ khóa → xoay khóa khẩn (overlap), gỡ khóa cũ, buộc re-login nếu cần.
```

```
Áp nguyên tắc:
   ② defense in depth → TTL ngắn + denylist + rotation + valid_after (nhiều lớp revoke)
```

> [!NOTE]
> Chi tiết chiến lược thu hồi ở [Revocation & Logout](/lifecycle/revocation-and-logout/) và mô hình denylist/allowlist ở [Blacklist vs Whitelist](/lifecycle/blacklist-whitelist/). Nhớ: JWT stateless không có "nút hủy" sẵn — mọi thu hồi tức thì đều tốn thêm trạng thái server, chọn ít-nhất-đủ-dùng.

---

## 8. Vận hành: log, giám sát, xoay khóa

```
□ Log AUDIT (KHÔNG log token): jti, sub, iat, ip, action cho thao tác nhạy cảm.
   VÌ SAO: chống chối bỏ (repudiation) + điều tra sự cố (truy về token/phiên nào).
□ Metric: jwt_issued_total, jwt_issue_errors, verify_failures{reason},
   refresh_reuse_detected_total, jwks_refetch_total — theo kid/aud.
□ Cảnh báo: reuse detection bắn (nghi trộm), verify_failures tăng vọt (tấn công/cấu hình sai),
   jwks refetch storm (DoS), issue spike (brute-force /token).
□ Cache JWKS + cooldown + jitter; giới hạn refetch theo kid lạ (chống storm).
□ Xoay khóa định kỳ (vd quý) + diễn tập xoay khẩn (runbook sẵn).
□ Đánh giá lại threat model khi kiến trúc đổi (thêm verifier/client/nơi lưu mới).
```

> [!TIP]
> `refresh_reuse_detected_total` và `verify_failures{reason}` là hai tín hiệu bảo mật giá trị nhất: cái đầu gợi ý token bị trộm, cái sau lộ tấn công đang diễn ra (alg lạ, kid lạ, chữ ký sai hàng loạt). Gắn cảnh báo cho cả hai.

---

## 9. Cấu hình mẫu an toàn (end-to-end)

### Issuer (Node/`jose`)

```javascript
new SignJWT({ scope, roles })
  .setProtectedHeader({ alg: 'RS256', kid: ACTIVE_KID })   // alg cố định + kid active
  .setIssuer('https://auth.example.com')
  .setSubject(userId)                                       // id, không PII
  .setAudience('api.payments')                              // ghim audience
  .setIssuedAt()
  .setExpirationTime('15m')                                 // TTL ngắn
  .setJti(randomBytes(16).toString('hex'))                  // 128-bit
  .sign(privateKey);
```

### Verifier (Node/`jose`)

```javascript
const { payload } = await jwtVerify(token, jwks, {
  algorithms: ['RS256'],                 // allowlist → chặn none/confusion
  issuer: 'https://auth.example.com',    // ghim issuer
  audience: 'api.payments',              // ghim audience = chính tôi
  clockTolerance: '30s',                 // leeway cho clock skew
  requiredClaims: ['exp', 'sub', 'aud'], // bắt buộc có exp
});
// validate schema thêm nếu cần (kiểu roles/scope) rồi mới dùng để authz
```

### Cookie refresh + CSP

```
Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/token; Max-Age=604800

Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
                         base-uri 'self'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

> [!WARNING]
> Đây là điểm khởi đầu an toàn, không phải "dán vào là xong". Điều chỉnh `issuer`/`audience`/TTL theo hệ của bạn, và đảm bảo CSP không kèm `'unsafe-inline'` (sẽ vô hiệu phần lớn tác dụng chống XSS).

---

## 10. Phân tầng ưu tiên theo mức nhạy cảm

Không phải hệ nào cũng cần mọi biện pháp. Phân tầng để đầu tư đúng chỗ:

| Biện pháp | App thường | Có dữ liệu cá nhân | Tài chính/Y tế |
|-----------|------------|---------------------|-----------------|
| TLS + allowlist alg + verify đủ cổng | ✅ bắt buộc | ✅ | ✅ |
| Secret mạnh / RS256 + KMS | ✅ | ✅ | ✅ |
| access memory + refresh httpOnly | ✅ | ✅ | ✅ |
| Rotation + reuse detection | nên | ✅ | ✅ |
| TTL access ngắn (5–15') | ✅ | ✅ | rất ngắn (1–5') |
| Denylist + valid_after (revoke tức thì) | tùy | nên | ✅ |
| BFF (token không chạm trình duyệt) | — | cân nhắc | ✅ nên |
| Device binding / DPoP / mTLS | — | — | ✅ cân nhắc |
| Step-up auth cho action nhạy cảm | — | nên | ✅ |
| Audit log đầy đủ + giám sát realtime | nên | ✅ | ✅ |

```
Đọc bảng:
   • cột trái (TLS, verify đúng, secret mạnh, storage đúng) = NỀN cho MỌI hệ
   • càng nhạy cảm → thêm lớp: rotation → denylist → BFF → device binding → step-up
   • áp ① least privilege: hệ thường KHÔNG cần BFF/DPoP — đừng over-engineer
```

> [!TIP]
> Đừng áp dụng mù mọi best practice — đó cũng là một dạng lãng phí và đôi khi tạo phức tạp sinh lỗi. Bắt đầu từ nền (cột trái), rồi leo thang theo mức nhạy cảm thực tế của dữ liệu/nghiệp vụ.

---

## 11. Ma trận sai lầm ↔ khắc phục

Tổng hợp những sai lầm hay gặp nhất xuyên suốt chuỗi Security, kèm hậu quả và cách sửa — dùng như bảng tra cứu nhanh khi audit một hệ thống:

| Sai lầm | Giai đoạn | Hậu quả | Khắc phục |
|---------|-----------|---------|-----------|
| `jwt.decode` dùng để phân quyền | verify | Tin payload chưa kiểm → giả tùy ý | Luôn `verify` (ký+alg+exp+aud) |
| `verify(token, key)` không truyền `algorithms` | verify | alg:none / RS→HS confusion | `algorithms: ['RS256']` allowlist |
| Bỏ kiểm `aud` ở microservice | verify | Token dùng nhầm dịch vụ → leo quyền | Ghim `audience` = chính service |
| Token thiếu `exp` được coi "không hết hạn" | cấp/verify | Token sống mãi, revoke vô dụng | Issuer luôn set exp; verifier bắt buộc exp |
| `exp = Date.now()` (mili-giây) | cấp | TTL sai ~1700 năm | `Math.floor(Date.now()/1000)+ttl` |
| Secret HMAC là từ/cụm từ ngắn | khóa | Brute-force offline trong mili-giây | ≥256-bit ngẫu nhiên / RS256 |
| Secret/khóa commit vào repo | khóa | Lộ vĩnh viễn trong lịch sử Git | Secret manager; xoay khi lộ; quét repo |
| `kid` dùng làm path/SQL không khử trùng | verify | Path traversal / SQLi → giả token | Allowlist kid; prepared statement |
| Tin `jwk`/`jku`/`x5u` trong header | verify | Attacker tự cấp khóa verify | Khóa từ nguồn tin cậy cấu hình sẵn |
| Token (refresh) ở `localStorage` | lưu | XSS trộm → phiên dài hạn | Refresh→httpOnly cookie; access→memory |
| Cookie token thiếu `SameSite` | lưu | CSRF | SameSite=Strict/Lax + anti-CSRF |
| `Domain=.example.com` rộng | lưu | Subdomain yếu chạm cookie chính | Host-only / `__Host-` prefix |
| Token trong URL/query | truyền | Rò qua log/Referer/lịch sử | Token ở Authorization header |
| Không TLS / thiếu `Secure` | truyền | Sniff/MITM | TLS + HSTS + Secure cookie |
| `script-src 'unsafe-inline'` | lưu/XSS | CSP gần như vô dụng | Bỏ unsafe-inline; nonce/hash |
| PII/secret trong payload | cấp | Lộ khi token bị đọc | Claims tối thiểu; JWE nếu cần bí mật |
| TTL access dài "cho tiện" | cấp | Khuếch đại mọi rủi ro, revoke chậm | Access 5–15' + silent refresh |
| Refresh không rotation | thu hồi | Trộm refresh = phiên dài, khó phát hiện | Rotation + reuse detection |
| Verify lỗi → fallback "cho qua" | verify | Fail-open → bypass | Fail-closed (401) mọi nghi ngờ |
| Cache quyền cũ khi cấp lại | cấp | Stale claim giữ quyền đã thu hồi | Đọc quyền tươi + TTL ngắn |

> [!TIP]
> Khi audit một hệ thống JWT lạ, quét theo cột "Sai lầm" của bảng này như một checklist tấn công ngược: với mỗi dòng, hỏi "hệ thống này có dính không?". Hầu hết sự cố production là tổ hợp 2–3 dòng trong bảng (vd: secret yếu + thiếu allowlist alg, hoặc token ở localStorage + refresh TTL dài).

---

## 12. Nâng cấp bảo mật cho hệ đang chạy

Áp best practice vào dự án mới thì dễ; vá một hệ đang chạy (có người dùng thật, không được downtime) cần lộ trình cẩn thận để **không đá toàn bộ user ra ngoài**.

```
LỘ TRÌNH NÂNG CẤP (ưu tiên rủi ro cao trước, làm dần không downtime):

  GIAI ĐOẠN 1 — vá lỗ hổng "giả token" (rủi ro cao nhất, sửa được không phá UX):
    □ thêm algorithms allowlist vào MỌI chỗ verify          ← không ảnh hưởng token hợp lệ
    □ thêm kiểm issuer + audience                            ← kiểm tra token hiện hành có
                                                               aud/iss đúng trước khi siết
    □ thay decode→verify ở mọi chỗ phân quyền
    □ nếu HS256 secret yếu → đổi secret (xem GIAI ĐOẠN khóa)

  GIAI ĐOẠN 2 — siết thời gian & thu hồi (cần lộ trình vì đụng token đang sống):
    □ rút TTL access dần (vd 24h → 1h → 15') qua vài đợt deploy, theo dõi lỗi 401
    □ bật refresh rotation + reuse detection (token cũ vẫn chấp nhận trong cửa sổ
      chuyển tiếp, rồi siết)
    □ thêm tokensValidAfter / denylist cho thu hồi tức thì

  GIAI ĐOẠN 3 — chuyển nơi lưu (đụng client, cần phối hợp FE):
    □ chuyển refresh từ localStorage → httpOnly cookie (hỗ trợ cả hai trong cửa sổ
      chuyển tiếp; khi client mới phổ biến thì gỡ đường cũ)
    □ access → memory + silent refresh

  XOAY KHÓA / ĐỔI SECRET (không downtime — dùng overlap):
    □ thêm khóa MỚI (kid mới) song song khóa cũ; verifier chấp nhận CẢ HAI
    □ issuer chuyển sang ký bằng khóa mới
    □ chờ mọi token ký bằng khóa cũ hết hạn (qua TTL) → gỡ khóa cũ
    → xem chi tiết overlap window ở Key Rotation
```

```
┌───────────────────────────────────────────────────────────────────────────┐
│  NGUYÊN TẮC NÂNG CẤP KHÔNG DOWNTIME:                                       │
│    "chấp nhận CŨ + MỚI trong cửa sổ chuyển tiếp → khi mới phổ biến thì gỡ   │
│     cũ". Áp cho khóa (overlap kid), nơi lưu (hỗ trợ cả 2), TTL (siết dần).  │
│  RỦI RO: siết quá nhanh → user bị 401 hàng loạt; siết quá chậm → lỗ hổng    │
│     tồn tại lâu. Theo dõi metric verify_failures trong mỗi đợt siết.        │
└───────────────────────────────────────────────────────────────────────────┘
```

> [!WARNING]
> Cám dỗ lớn nhất khi vá hệ đang chạy là "đổi hết một lúc cho xong". Với thay đổi đụng token đang sống (rút TTL, đổi nơi lưu, xoay khóa), làm đột ngột sẽ đá toàn bộ user ra (401 hàng loạt) hoặc mất phiên. Luôn dùng **cửa sổ chuyển tiếp chấp nhận cả cũ lẫn mới**, theo dõi `verify_failures`, rồi gỡ đường cũ khi an toàn. Ngoại lệ: nếu đang bị tấn công chủ động (khóa lộ), xoay khẩn + buộc re-login là chấp nhận được dù gây gián đoạn.

---

## 13. Checklist review PR

```
KHI REVIEW CODE LIÊN QUAN JWT, SOÁT:
□ Có chỗ nào dùng jwt.decode/jwtDecode để PHÂN QUYỀN (thay vì verify)? → CHẶN
□ verify có algorithms allowlist? có issuer + audience? có kiểm exp? → THIẾU = block
□ alg/TTL có bị lấy từ request/biến client không? → CHẶN
□ kid có bị dùng làm path/SQL không tham số hóa? → CHẶN
□ Khóa verify có lấy từ jwk/jku/x5u trong token không? → CHẶN
□ Token có bị log / đưa vào URL không? → CHẶN
□ Token có bị ghi vào localStorage/sessionStorage/persist không? → CHẶN
□ Cookie token có đủ HttpOnly+Secure+SameSite không?
□ Có PII/secret trong payload không?
□ Secret HMAC có hardcode/commit không? có đủ entropy không?
□ Lỗi verify có fail-closed (401) không, hay fallback "cho qua"?
```

> [!IMPORTANT]
> Phần lớn lỗ hổng JWT vào production qua những dòng nhỏ dễ lọt review: một `jwt.decode` dùng để authz, một `localStorage.setItem('token', ...)` để debug, một verify thiếu `audience`. Checklist này biến việc soát thành cơ học, khó sót.

---

## 14. Tóm tắt — Cheat sheet

```
╭──────────────────────────────────────────────────────────────────────────╮
│  4 NGUYÊN TẮC: ① least privilege ② defense in depth                       │
│               ③ secure by default ④ fail closed                          │
│                                                                            │
│  THEO GIAI ĐOẠN:                                                          │
│   KHÓA   : RS/ES cho phân tán; secret ≥256-bit; KMS/HSM; kid + xoay khóa  │
│   CẤP    : sau xác thực; quyền tươi; claims tối thiểu; TTL ngắn; alg cố định│
│   TRUYỀN : TLS+HSTS; token ở header (KHÔNG URL); không log token          │
│   LƯU    : access→memory; refresh→httpOnly+Secure+SameSite; KHÔNG localStorage│
│   VERIFY : allowlist alg; ghim iss+aud; bắt buộc exp+leeway; verify≠decode;│
│            khóa từ nguồn tin cậy; fail-closed                             │
│   THU HỒI: TTL ngắn + refresh rotation/reuse + denylist + valid_after     │
│   VẬN HÀNH: audit log (không token); metric+cảnh báo; cache JWKS; xoay khóa│
│                                                                            │
│  80/20 VERIFY: algorithms:['RS256'] + {issuer,audience} + luôn verify     │
│  PHÂN TẦNG: nền cho mọi hệ; leo thang (rotation→denylist→BFF→DPoP) theo   │
│             mức nhạy cảm — đừng over-engineer hệ thường.                  │
╰──────────────────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Best practice là hệ quả của 4 nguyên tắc, không phải danh sách học thuộc.** Least privilege + defense in depth + secure by default + fail closed suy ra được cách xử lý cả tình huống chưa liệt kê.
2. **Phòng thủ là nhiều lớp xuyên suốt vòng đời — không có viên đạn bạc.** TLS, chữ ký, verify đủ cổng, storage đúng, thu hồi, giám sát: mỗi lớp đỡ cho lớp khác khi thủng.
3. **Đầu tư theo mức nhạy cảm, ưu tiên khóa ký + verify đúng.** Nền (TLS/verify/secret/storage) cho mọi hệ; leo thang biện pháp nặng (BFF, DPoP, step-up) chỉ khi dữ liệu/nghiệp vụ thực sự đòi hỏi.

Đọc lại toàn cụm: [Threat Model](/security/jwt-threat-model/) · [Common Vulnerabilities](/security/common-vulnerabilities/) · [Algorithm Confusion](/security/algorithm-confusion-deep-dive/) · [XSS/CSRF & Token Theft](/security/xss-csrf-token-theft/) · [Secure Storage](/security/secure-storage/).
