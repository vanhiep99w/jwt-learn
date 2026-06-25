---
title: "Production Checklist"
description: "Danh sách kiểm tra chi tiết trước khi đưa hệ JWT lên production: khung ưu tiên P0/P1/P2, từng mục kèm cách XÁC MINH (lệnh/test/cấu hình cụ thể) theo 8 nhóm — thuật toán & khóa, cấp, truyền, lưu, verify, thu hồi, observability, ứng phó sự cố — cùng cấu hình mẫu an toàn, sự cố production thường gặp, diễn tập rollback, và bảng Go/No-Go."
---

# Production Checklist

## Mục lục

- [Tổng quan](#tổng-quan)
- [1. Khung ưu tiên P0/P1/P2](#1-khung-ưu-tiên-p0p1p2)
- [2. P0 — chặn release (rà nhanh)](#2-p0--chặn-release-rà-nhanh)
- [3. Thuật toán & khóa](#3-thuật-toán--khóa)
- [4. Cấp token (issuance)](#4-cấp-token-issuance)
- [5. Truyền token (transport)](#5-truyền-token-transport)
- [6. Lưu token (storage)](#6-lưu-token-storage)
- [7. Verify (xác minh)](#7-verify-xác-minh)
- [8. Thu hồi & vòng đời](#8-thu-hồi--vòng-đời)
- [9. Observability & ứng phó sự cố](#9-observability--ứng-phó-sự-cố)
- [10. Cấu hình mẫu an toàn](#10-cấu-hình-mẫu-an-toàn)
- [11. Sự cố production thường gặp](#11-sự-cố-production-thường-gặp)
- [12. Diễn tập rollback & DR](#12-diễn-tập-rollback--dr)
- [13. Bảng Go / No-Go](#13-bảng-go--no-go)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan

Doc này là **cổng cuối** trước khi hệ JWT lên production. Khác với các checklist liệt kê suông, ở đây mỗi mục gắn **mức ưu tiên** và **cách xác minh cụ thể** (lệnh, test, hoặc cấu hình) — để review không dừng ở "đánh dấu cho có" mà thật sự chứng minh được từng điểm.

```diagram
   Mục tiêu: không có lỗ hổng "im lặng" nào lọt qua launch
   ┌──────────────────────────────────────────────────────────────┐
   │  P0  ┃ thiếu = HỦY release (lỗ hổng/mất an toàn cơ bản)        │
   │  P1  ┃ thiếu = rủi ro cao, vá ngay tuần đầu                     │
   │  P2  ┃ tăng cường, lên kế hoạch sau launch                      │
   └──────────────────────────────────────────────────────────────┘
   Mỗi mục: [ ] điều cần đạt   →   "Xác minh: <lệnh/test/cấu hình>"
```

> [!IMPORTANT]
> Một mục **P0 chưa đạt = No-Go**, không có ngoại lệ. P0 không phải "tốt nếu có" mà là ranh giới giữa "hệ an toàn" và "hệ có lỗ hổng đã biết". Trước khi bàn P1/P2, hãy chắc **toàn bộ P0** ở [mục 2](#2-p0--chặn-release-rà-nhanh) đều xanh và **có bằng chứng**.

---

## 1. Khung ưu tiên P0/P1/P2

| Mức | Ý nghĩa | Quy tắc release | Ví dụ |
|-----|---------|-----------------|-------|
| **P0** | Lỗ hổng/mất an toàn cơ bản | Thiếu 1 mục = **No-Go** | Không allowlist `alg`; secret hardcode; không kiểm `exp` |
| **P1** | Rủi ro cao nhưng có thể giảm thiểu tạm | Launch được nhưng vá trong tuần đầu | Chưa có reuse detection; chưa xoay khóa định kỳ |
| **P2** | Tăng cường, chiều sâu phòng thủ | Lên kế hoạch sau launch | DPoP/token binding; phân tích bất thường nâng cao |

> [!TIP]
> Khi review, ghi **bằng chứng** cạnh mỗi mục (link test pass, ảnh cấu hình, output lệnh) thay vì chỉ tick. "Đã có allowlist alg" yếu hơn nhiều so với "test `alg:none` → 401 pass: <link CI>". Bằng chứng biến checklist từ nghi thức thành cổng kiểm soát thật.

---

## 2. P0 — chặn release (rà nhanh)

Chín mục dưới đây thiếu bất kỳ mục nào = **không được lên production**:

```diagram
□ P0-1  Allowlist thuật toán cố định ở verifier (vd ['RS256']); KHÔNG đọc alg từ token
□ P0-2  alg:none và algorithm confusion bị từ chối (có test chứng minh)
□ P0-3  Verify ĐẦY ĐỦ: chữ ký + exp + nbf + iss + aud (không bỏ cổng nào)
□ P0-4  Secret/private key trong secret manager — KHÔNG hardcode, KHÔNG trong repo/env commit
□ P0-5  Mọi token truyền qua HTTPS/TLS; cookie có Secure + HttpOnly + SameSite
□ P0-6  Refresh token KHÔNG ở localStorage (dùng cookie HttpOnly)
□ P0-7  Access token TTL ngắn (5-15') + có cơ chế refresh
□ P0-8  KHÔNG dùng decode để phân quyền (chỉ verify mới ra quyết định)
□ P0-9  KHÔNG log token/secret; redact tự động ở logger
```

Phần sau giải thích **cách xác minh** từng nhóm.

---

## 3. Thuật toán & khóa

```diagram
[P0] Verifier có allowlist alg CỐ ĐỊNH, không đọc alg từ token
     Xác minh: grep cấu hình verify có `algorithms: [...]`; test alg:none + confusion → 401
[P0] Secret HS / private key RS nằm trong secret manager (KMS/Vault/SM)
     Xác minh: grep repo không thấy key; gitleaks pass; key load từ env/secret manager runtime
[P0] HS256: secret ≥ 256-bit ngẫu nhiên (không phải "secret"/"changeme")
     Xác minh: kiểm độ dài & nguồn sinh; không có default secret trong code
[P1] RS256/ES256 cho hệ phân tán nhiều verifier (verifier chỉ cần public key)
     Xác minh: kiến trúc — verifier không giữ khóa ký
[P1] Có quy trình xoay khóa qua kid + JWKS (overlap window)
     Xác minh: JWKS trả >1 kid khi xoay; verifier chọn theo kid
[P2] Lịch xoay khóa định kỳ tự động + runbook xoay khẩn cấp
```

<Callout type="error" title="P0 — sai lầm chí mạng">
Đọc <code>alg</code> từ header rồi dùng luôn để verify (thay vì allowlist cố định) là gốc của <b>alg:none</b> và <b>algorithm confusion</b> — cho phép giả token tùy ý. Đây là lỗ hổng phổ biến và nguy hiểm nhất. Verifier phải cố định <code>algorithms: ['RS256']</code> bất kể token khai báo gì. Chi tiết: <a href="/security/algorithm-confusion/">Algorithm Confusion</a>.
</Callout>

> [!WARNING]
> Secret/private key **không bao giờ** được hardcode trong code hay commit vào repo (kể cả file `.env` commit nhầm). Dùng secret manager (AWS Secrets Manager, Vault, GCP Secret Manager), nạp lúc runtime, và chạy `gitleaks`/scan để bắt rò rỉ. Lộ khóa ký = kẻ tấn công giả được **mọi** token.

---

## 4. Cấp token (issuance)

```diagram
[P0] Access TTL ngắn 5-15'; refresh TTL dài hơn nhưng có hạn (vd 7-30 ngày)
     Xác minh: decode token cấp ra, kiểm exp - iat
[P0] Mọi token có exp; access có iat; nên có jti (truy vết/thu hồi)
     Xác minh: decode kiểm claim bắt buộc
[P0] Đặt iss và aud rõ ràng, đúng môi trường/đối tượng
     Xác minh: token prod có iss=prod, aud=service đích
[P1] Payload tối thiểu: không nhồi PII/dữ liệu nhạy cảm vào claim
     Xác minh: decode payload, soát không có email/sđt/secret
[P1] Refresh token rotation (mỗi lần dùng cấp refresh mới, vô hiệu cái cũ)
     Xác minh: test rotation; dùng lại refresh cũ → 401
[P2] Phân biệt typ (at+jwt cho access) nếu cần tránh nhầm loại token
```

> [!NOTE]
> TTL access ngắn là **cơ chế thu hồi mặc định** của JWT stateless: vì không thể "xóa" token đã cấp, hạn ngắn giới hạn cửa sổ thiệt hại nếu token bị trộm. 5–15 phút là khoảng cân bằng phổ biến giữa an toàn và số lần refresh. Chi tiết vòng đời: [Access vs Refresh Token](/lifecycle/access-token-vs-refresh-token/).

---

## 5. Truyền token (transport)

```diagram
[P0] HTTPS/TLS bắt buộc trên mọi đường truyền token (kể cả nội bộ service-to-service)
     Xác minh: không có endpoint HTTP nhận token; HSTS bật
[P0] Cookie chứa token: Secure + HttpOnly + SameSite (Lax/Strict)
     Xác minh: kiểm Set-Cookie response có đủ 3 thuộc tính
[P0] Access token gửi qua header Authorization: Bearer, KHÔNG qua URL/query
     Xác minh: grep không thấy token trong query string (URL bị log → rò rỉ)
[P1] CORS cấu hình chặt (origin allowlist), không '*' với credentials
     Xác minh: kiểm header Access-Control-Allow-Origin không phải '*' khi gửi cookie
[P1] CSRF: nếu dùng cookie cho auth → có chống CSRF (SameSite + token/double-submit)
```

<Callout type="warn">
Đặt token vào <b>URL/query string</b> (vd <code>?token=eyJ...</code>) là rò rỉ kinh điển: URL bị ghi vào access log của server/proxy, lịch sử trình duyệt, và header <code>Referer</code> gửi sang bên thứ ba. Token luôn đi qua header <code>Authorization</code> hoặc cookie <code>HttpOnly</code>, không bao giờ qua URL.
</Callout>

---

## 6. Lưu token (storage)

```diagram
[P0] Refresh token KHÔNG ở localStorage/sessionStorage (XSS đọc được)
     Xác minh: E2E kiểm localStorage không chứa chuỗi JWT; refresh là cookie HttpOnly
[P1] Access token: ưu tiên memory (biến JS), tránh lưu lâu dài ở storage XSS đọc được
[P1] Mobile: lưu ở Keychain (iOS)/Keystore (Android), không plain storage
[P2] Cân nhắc token binding/DPoP để token bị trộm cũng khó dùng nơi khác
```

| Nơi lưu | XSS đọc được? | Phù hợp |
|---------|----------------|---------|
| `localStorage` | ✅ (nguy hiểm) | ❌ Không cho token nhạy cảm |
| Cookie `HttpOnly` | ❌ | ✅ Refresh token |
| Memory (biến JS) | Chỉ khi đang chạy | ✅ Access token (mất khi reload, refresh lại) |
| Keychain/Keystore | Theo OS | ✅ Mobile |

> [!TIP]
> Mẫu an toàn phổ biến cho web: **access token ở memory** (mất khi reload, dùng silent refresh để lấy lại) + **refresh token ở cookie `HttpOnly`+`Secure`+`SameSite`** (JS không đọc được, chống XSS). Chi tiết và đánh đổi: [Secure Storage](/security/secure-storage/).

---

## 7. Verify (xác minh)

```diagram
[P0] Verify chữ ký bằng đúng khóa + allowlist alg
     Xác minh: test sửa payload/chữ ký → 401
[P0] Kiểm exp (hết hạn) và nbf (chưa hiệu lực)
     Xác minh: test token exp quá khứ → 401; nbf tương lai → 401
[P0] Kiểm iss và aud khớp cấu hình service
     Xác minh: test sai iss/aud → 401
[P0] Bắt buộc claim cần thiết (exp, sub, aud) — thiếu → từ chối
     Xác minh: test token thiếu exp → 401
[P1] clockTolerance 30-60s cho lệch đồng hồ; KHÔNG kéo dài TTL để che skew
     Xác minh: test token vừa hết hạn trong leeway → vẫn nhận
[P1] JWKS có cache + xử lý kid lạ không crash (trả 401, không 500)
     Xác minh: test kid lạ → 401; kiểm cache TTL JWKS
[P1] Token méo/rỗng → 401, không 500 (không crash verifier)
```

> [!NOTE]
> Verify phải kiểm **tất cả** các cổng — bỏ một cổng là một lỗ hổng. Pipeline đầy đủ 7 cổng với code minh họa: [Luồng xác thực JWT](/internals/token-validation-flow/). Bộ test chứng minh từng cổng từ chối token sai: [Testing Auth Flow](/operations/testing-auth-flow/).

---

## 8. Thu hồi & vòng đời

```diagram
[P0] Có cách thu hồi: TTL ngắn (mặc định) + cơ chế logout hiệu quả
     Xác minh: logout → token cũ không dùng được (qua denylist hoặc hết hạn ngắn)
[P1] Refresh reuse detection: dùng lại refresh đã rotate → thu hồi cả family
     Xác minh: test reuse → 401 + family bị thu hồi
[P1] "Logout all devices": tokensValidAfter / token version per user
     Xác minh: tăng version → mọi token cũ của user bị từ chối
[P1] Denylist (nếu cần thu hồi tức thì) lưu ở store nhanh (Redis), TTL = exp token
     Xác minh: revoke jti → request với jti đó → 401
[P2] Tự động thu hồi khi đổi mật khẩu / phát hiện bất thường
```

<Callout type="info">
JWT stateless không "xóa" được token đã cấp, nên chiến lược thu hồi là kết hợp: <b>TTL ngắn</b> (cửa sổ thiệt hại nhỏ) + <b>denylist theo jti</b> cho thu hồi tức thì + <b>tokensValidAfter</b> cho "đăng xuất mọi thiết bị". Chi tiết: <a href="/lifecycle/revocation-and-logout/">Revocation & Logout</a>.
</Callout>

---

## 9. Observability & ứng phó sự cố

```diagram
[P0] KHÔNG log token/secret; redact tự động ở tầng logger
     Xác minh: grep log không có chuỗi token; cấu hình redact "authorization"/"cookie"
[P1] Metric: jwt_verify_failures_total{reason}, refresh_reuse_detected_total
     Xác minh: /metrics expose; dashboard có 2 biểu đồ này
[P1] Cảnh báo: reuse>0 (critical); verify_failures tăng đột biến; alg lạ
     Xác minh: alert rule tồn tại + đã test bắn thử
[P1] Audit log append-only cho login/issue/sensitive_action/revoke/key_rotation
[P1] Runbook ứng phó: token bị lộ → tokensValidAfter; khóa bị lộ → xoay khẩn cấp
     Xác minh: runbook tồn tại + đã diễn tập
[P2] Tracing trace_id xuyên service, gắn sub/jti (không token) vào span
```

> [!TIP]
> Trước launch, hãy **diễn tập** ít nhất hai kịch bản: (1) một token bị lộ → chạy `tokensValidAfter` cho user đó; (2) khóa ký nghi lộ → xoay khóa khẩn cấp. Có runbook mà chưa bấm thử thì khi sự cố thật vẫn lúng túng. Chi tiết log/metric: [Observability và Audit](/operations/observability-and-audit/).

---

## 10. Cấu hình mẫu an toàn

Cấp token (`jose`):

```javascript
import { SignJWT } from 'jose';

const token = await new SignJWT({ sub: user.id, scope: user.scope })  // payload tối thiểu, không PII
  .setProtectedHeader({ alg: 'RS256', kid: currentKid })   // alg cố định + kid để xoay khóa
  .setIssuer('https://auth.example.com')                   // P0: iss
  .setAudience('api.orders')                               // P0: aud
  .setIssuedAt()
  .setExpirationTime('15m')                                // P0: TTL ngắn
  .setJti(crypto.randomUUID())                             // truy vết/thu hồi
  .sign(privateKey);
```

Verify token (`jose`) — cấu hình an toàn đầy đủ:

```javascript
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

const { payload } = await jwtVerify(token, JWKS, {
  algorithms: ['RS256'],                  // P0: allowlist cố định (chặn none/confusion)
  issuer: 'https://auth.example.com',     // P0: ghim iss
  audience: 'api.orders',                 // P0: ghim aud
  clockTolerance: '30s',                  // P1: leeway clock skew
  requiredClaims: ['exp', 'sub', 'aud'],  // P0: bắt buộc claim
});
```

Cookie chứa refresh token:

```javascript
res.cookie('refresh_token', refresh, {
  httpOnly: true,    // P0: JS không đọc được (chống XSS)
  secure: true,      // P0: chỉ gửi qua HTTPS
  sameSite: 'lax',   // P1: giảm CSRF
  maxAge: 7 * 24 * 3600 * 1000,
  path: '/auth/refresh',
});
```

---

## 11. Sự cố production thường gặp

| Triệu chứng sau launch | Nguyên nhân gốc | Phòng ngừa (mục checklist) |
|-------------------------|------------------|-----------------------------|
| 401 hàng loạt ngay sau deploy | Đổi `aud`/`iss`/secret không có cửa sổ chuyển tiếp | P0-3; xem [Migration](/operations/migration-strategy/) |
| 401 "không hết hạn mà vẫn expired" | Clock skew giữa các node | P1 clockTolerance + NTP |
| 401 chập chờn | JWKS cache lệch giữa các replica | P1 JWKS cache + xoay khóa overlap |
| Token bị lộ nhưng không phát hiện | Không có reuse detection / cảnh báo | P1 reuse detection + alert |
| Lộ token qua log | Log nguyên token/header | P0-9 redact tự động |
| Verifier 500 với input rác | Không xử lý token méo | P1 token méo → 401 không 500 |
| Tài khoản bị chiếm dù đã đổi MK | Không thu hồi token cũ khi đổi MK | P2 auto-revoke on password change |

---

## 12. Diễn tập rollback & DR

```diagram
TRƯỚC LAUNCH, DIỄN TẬP:
□ Rollback cấu hình verify (vd lỡ đổi aud) → có thể lui nhanh không cần redeploy? (feature flag)
□ Xoay khóa khẩn cấp: thêm kid mới → ký bằng mới → gỡ kid lộ; đo thời gian thực hiện
□ tokensValidAfter cho 1 user: kiểm mọi token cũ bị từ chối tức thì
□ JWKS endpoint down: verifier còn cache có sống sót không? (đừng để JWKS là SPOF)
□ Secret manager down: service khởi động lại có nạp được key không? (cache key an toàn?)
```

<Callout type="warn">
<b>JWKS endpoint và secret manager là single point of failure tiềm tàng.</b> Nếu mọi verify đều gọi JWKS realtime và endpoint đó chết → toàn hệ thống không xác thực được. Bắt buộc cache JWKS (TTL hợp lý) và kiểm thử kịch bản "JWKS/secret manager tạm thời không truy cập được" trước khi launch.
</Callout>

---

## 13. Bảng Go / No-Go

| Hạng mục | Điều kiện Go | Nếu thiếu |
|----------|--------------|-----------|
| Thuật toán & khóa | Allowlist alg cố định; key trong secret manager; test none/confusion pass | **No-Go** (P0) |
| Verify | Kiểm đủ chữ ký+exp+nbf+iss+aud; claim bắt buộc | **No-Go** (P0) |
| Truyền | HTTPS bắt buộc; cookie Secure+HttpOnly+SameSite; không token trên URL | **No-Go** (P0) |
| Lưu | Refresh không ở localStorage | **No-Go** (P0) |
| Cấp | Access TTL ngắn + refresh có hạn; có exp/iss/aud | **No-Go** (P0) |
| Decode vs authz | Chỉ verify mới ra quyết định phân quyền | **No-Go** (P0) |
| Log | Không log token; redact tự động | **No-Go** (P0) |
| Thu hồi | Có cơ chế thu hồi hiệu quả | Go có điều kiện (vá tuần đầu) nếu chỉ thiếu reuse detection (P1) |
| Observability | Metric + cảnh báo reuse/verify_failures | Go có điều kiện (P1) |
| Rollback/DR | Đã diễn tập rollback + xoay khóa khẩn | Go có điều kiện (P1) |

<Callout type="success" title="Quy tắc quyết định">
<b>Go</b> chỉ khi <b>toàn bộ P0 xanh và có bằng chứng</b>. Thiếu một P0 = <b>No-Go</b> tuyệt đối. Thiếu P1 = Go có điều kiện với cam kết vá trong tuần đầu. P2 = roadmap sau launch. Đừng để áp lực thời hạn biến một P0 thành "để sau" — đó chính là cách lỗ hổng đã biết lọt lên production.
</Callout>

---

## Tài liệu tham khảo

- [Security Best Practices](/security/security-best-practices/) — nền tảng cho phần lớn mục P0
- [Algorithm Confusion](/security/algorithm-confusion/) — vì sao allowlist alg là P0
- [Secure Storage](/security/secure-storage/) — lưu token đúng chuẩn
- [Luồng xác thực JWT](/internals/token-validation-flow/) — các cổng verify cần kiểm
- [Access vs Refresh Token](/lifecycle/access-token-vs-refresh-token/) — TTL & refresh
- [Revocation & Logout](/lifecycle/revocation-and-logout/) — chiến lược thu hồi
- [Key Rotation](/cryptography/key-rotation/) — xoay khóa & DR
- [Observability và Audit](/operations/observability-and-audit/) — log/metric/cảnh báo
- [Testing Auth Flow](/operations/testing-auth-flow/) — bằng chứng cho mục verify
- [Migration Strategy](/operations/migration-strategy/) — tránh 401 hàng loạt khi đổi cấu hình
