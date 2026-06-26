---
title: "Backend API Authentication"
description: "Triển khai JWT đầy đủ cho REST API: kiến trúc tầng auth, đọc Bearer đúng cách, verify đủ claim (alg allowlist, iss/aud/exp/nbf), nạp khóa JWKS có cache + xoay khóa, phân biệt 401 vs 403, mô hình phân quyền RBAC/ABAC/scope, xử lý lỗi an toàn, revocation, rate limit, code chạy được cho Express + Fastify + NestJS, edge cases, anti-patterns và checklist."
---

# Backend API Authentication

## Mục lục

- [1. Bối cảnh: ba lỗ hổng kinh điển ở tầng verify](#1-bối-cảnh-ba-lỗ-hổng-kinh-điển-ở-tầng-verify)
- [2. Tổng quan: decode ≠ verify ≠ authorize](#2-tổng-quan-decode--verify--authorize)
- [3. Kiến trúc tầng auth trong API](#3-kiến-trúc-tầng-auth-trong-api)
- [4. Middleware xác thực (authenticate)](#4-middleware-xác-thực-authenticate)
  - [4.1 Đọc Bearer token đúng cách](#41-đọc-bearer-token-đúng-cách)
  - [4.2 Verify đủ claim](#42-verify-đủ-claim)
  - [4.3 Vì sao mỗi tham số bắt buộc](#43-vì-sao-mỗi-tham-số-bắt-buộc)
- [5. Nạp khóa: JWKS có cache & xoay khóa](#5-nạp-khóa-jwks-có-cache--xoay-khóa)
- [6. 401 vs 403: xác thực khác phân quyền](#6-401-vs-403-xác-thực-khác-phân-quyền)
- [7. Mô hình phân quyền: scope, RBAC, ABAC](#7-mô-hình-phân-quyền-scope-rbac-abac)
- [8. Xử lý lỗi an toàn](#8-xử-lý-lỗi-an-toàn)
- [9. Revocation & kiểm tra bổ sung](#9-revocation--kiểm-tra-bổ-sung)
- [10. Mẫu đầy đủ theo framework](#10-mẫu-đầy-đủ-theo-framework)
  - [10.1 Express](#101-express)
  - [10.2 Fastify](#102-fastify)
  - [10.3 NestJS](#103-nestjs)
- [11. Edge cases thực tế — những lỗi khó debug](#11-edge-cases-thực-tế--những-lỗi-khó-debug)
- [12. Anti-patterns & lỗi triển khai thường gặp](#12-anti-patterns--lỗi-triển-khai-thường-gặp)
- [13. Câu hỏi thường gặp](#13-câu-hỏi-thường-gặp)
- [14. Checklist backend API auth](#14-checklist-backend-api-auth)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## 1. Bối cảnh: ba lỗ hổng kinh điển ở tầng verify

Một service "có verify JWT" chưa chắc an toàn. Đây là ba sự cố thật, đều bắt nguồn từ verify *thiếu*:

```text
Sự cố A — alg:none
  Service dùng thư viện verify nhưng KHÔNG truyền allowlist algorithms.
  Attacker gửi token với header {"alg":"none"} và không có chữ ký.
  → Thư viện "tôn trọng" alg=none, bỏ qua verify chữ ký → token giả được chấp nhận.

Sự cố B — quên kiểm aud
  Token do IdP cấp cho service "billing" lại được service "admin" chấp nhận
  vì admin không kiểm `aud`. Một user thường có token billing hợp lệ
  → dùng luôn được API admin.

Sự cố C — tin header client
  Code đọc quyền từ req.headers['x-user-role'] thay vì từ claim đã verify.
  Attacker chỉ cần gửi `X-User-Role: admin`.
```

Cả ba đều "verify được signature" trên jwt.io, đều "có code auth", nhưng đều thủng. Bài học: verify JWT là một **danh sách kiểm bắt buộc**, không phải một lời gọi hàm duy nhất. Doc này dựng tầng auth cho REST API theo nguyên tắc rõ ràng: **authenticate** (bạn là ai — verify token) tách bạch khỏi **authorize** (bạn được làm gì — kiểm scope/role).

---

## 2. Tổng quan: decode ≠ verify ≠ authorize

```diagram
╭──────────────────────────────────────────────────────────────────────────╮
│  BA TẦNG KHÁC NHAU — đừng nhầm lẫn                                        │
│                                                                          │
│  DECODE   →  Base64URL giải mã payload. Cho biết token "tự nhận" là gì.   │
│              KHÔNG chứng minh gì cả. Ai cũng decode được.                 │
│                                                                          │
│  VERIFY   →  Kiểm chữ ký + alg allowlist + iss + aud + exp + nbf.         │
│              Chứng minh token THẬT, do đúng IdP cấp, cho ĐÚNG service,    │
│              còn hạn. Kết quả: "tôi tin bạn là sub=U123".                 │
│                                                                          │
│  AUTHORIZE→  Token thật rồi, nhưng U123 có được làm việc này không?       │
│              Kiểm scope/role/policy. Kết quả: cho phép hay 403.           │
╰──────────────────────────────────────────────────────────────────────────╯
```

> [!IMPORTANT]
> Quy tắc bất biến: **decode ≠ verify ≠ authorize**. Giải mã payload chỉ cho bạn *nội dung token tự nhận*; phải `verify` chữ ký + claim mới biết token *thật*; và verify xong vẫn phải kiểm *scope/role* mới biết được phép làm gì. Bỏ bất kỳ bước nào là một lớp lỗ hổng. Sự cố A bỏ verify chữ ký, B bỏ verify `aud`, C bỏ luôn cả verify (đọc header).

---

## 3. Kiến trúc tầng auth trong API

```diagram
┌──────────────────────────────────────────────────────────────┐
│  HTTP request: Authorization: Bearer <jwt>                     │
└───────────────┬──────────────────────────────────────────────┘
                ▼
   ┌─────────────────────────┐   thất bại verify
   │ 1. authenticate          │ ───────────────▶ 401 Unauthorized
   │   - đọc Bearer           │
   │   - verify(jwt, JWKS, …) │
   │   - gắn req.user         │
   └───────────┬─────────────┘
               ▼
   ┌─────────────────────────┐   thiếu scope/role
   │ 2. authorize             │ ───────────────▶ 403 Forbidden
   │   - kiểm scope/role      │
   └───────────┬─────────────┘
               ▼
   ┌─────────────────────────┐
   │ 3. handler (business)    │ ───────────────▶ 200 + data
   └─────────────────────────┘
```

Tách thành các tầng giúp: (1) test từng tầng độc lập, (2) tái dùng `authenticate` cho mọi route, (3) đặt `authorize` khác nhau cho mỗi route mà không lặp logic verify. Quan trọng hơn: nó buộc bạn **suy nghĩ tách bạch** "bạn là ai" và "bạn được làm gì" — gốc rễ của việc trả đúng 401 vs 403.

---

## 4. Middleware xác thực (authenticate)

### 4.1 Đọc Bearer token đúng cách

```javascript
// Đọc token từ header Authorization: Bearer <token>
function extractBearer(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const parts = header.split(' ');
  if (parts.length !== 2) return null;               // đúng "Bearer <token>", không thừa
  const [scheme, token] = parts;
  if (scheme !== 'Bearer' || !token) return null;    // đúng scheme + có token
  return token.trim();
}
```

> [!WARNING]
> Đừng dùng `header.replace('Bearer ', '')` cẩu thả — nó sẽ "ăn" chuỗi "Bearer " ở bất kỳ đâu và bỏ qua trường hợp sai scheme (vd `Basic`). Hãy tách theo space, kiểm đúng 2 phần và `scheme === 'Bearer'` tường minh. Cũng đừng đọc token từ query string (`?token=`) — token không được nằm trên URL ([lý do](/implementation/http-transport-and-storage/)).

### 4.2 Verify đủ claim

Đây là trái tim của tầng auth. Mọi tham số dưới đây đều bắt buộc:

```javascript
import { jwtVerify } from 'jose';

const VERIFY_OPTS = {
  algorithms: ['RS256'],                       // ALLOWLIST — chặn alg:none & confusion
  issuer: 'https://auth.example.com',          // đúng nơi cấp
  audience: 'api.orders',                       // token dành cho ĐÚNG service này
  clockTolerance: '30s',                        // dung sai lệch giờ máy chủ
  requiredClaims: ['exp', 'sub', 'aud', 'iss'], // bắt buộc có mặt
  maxTokenAge: '30m',                           // (tùy chọn) chặn token cũ dù chưa hết hạn
};

async function authenticate(req, res, next) {
  const token = extractBearer(req);
  if (!token) return res.status(401).json({ error: 'missing_token' });
  try {
    const { payload } = await jwtVerify(token, JWKS, VERIFY_OPTS);
    req.user = {
      id: payload.sub,
      scope: payload.scope ?? '',
      roles: payload.roles ?? [],
      tenant: payload.tenant,
    };
    next();
  } catch (err) {
    // KHÔNG lộ chi tiết; log nội bộ, trả 401 chung
    req.log?.warn({ code: err.code }, 'jwt verify failed');
    return res.status(401).json({ error: 'invalid_token' });
  }
}
```

### 4.3 Vì sao mỗi tham số bắt buộc

| Tham số | Vì sao bắt buộc | Bỏ qua = lỗ hổng |
|---------|------------------|-------------------|
| `algorithms` (allowlist) | Cố định thuật toán mong đợi | `alg:none`, RS256→HS256 confusion (Sự cố A) |
| `issuer` | Chỉ tin token từ đúng IdP | Chấp nhận token IdP khác cấp |
| `audience` | Token đúng dành cho service này | Token service A dùng được ở service B (Sự cố B) |
| `exp` (+ requiredClaims) | Token hết hạn bị từ chối | Token sống mãi |
| `nbf` | Token chưa tới hiệu lực bị từ chối | Token "tương lai" được dùng sớm |
| `clockTolerance` | Tránh false-negative do lệch giờ | 401 chập chờn giữa các máy |
| `maxTokenAge` | Chặn token quá cũ dù `exp` còn | Giảm cửa sổ lạm dụng token bị rò |

```diagram
THỨ TỰ KIỂM (jose tự lo, nhưng nên hiểu):
  1) parse 3 phần  → sai cấu trúc → reject
  2) đọc header.alg, ÉP nằm trong allowlist (KHÔNG tin giá trị này để chọn cách verify
     ngoài allowlist) → ngoài allowlist → reject
  3) chọn key theo kid (JWKS) → không có key → reject
  4) verify chữ ký bằng key đó → sai → reject
  5) kiểm iss, aud, exp, nbf, requiredClaims → bất kỳ cái nào fail → reject
  → qua hết → payload tin được
```

<Callout type="error" title="Sai lầm chí mạng: tin alg trong header">
Tuyệt đối <b>không</b> lấy thuật toán từ <code>header.alg</code> của chính token để rồi verify theo đó. Kẻ tấn công sẽ đặt <code>alg:none</code> hoặc đổi RS256→HS256 (dùng public key làm "secret" HMAC) để bỏ qua/giả chữ ký. Luôn truyền <code>algorithms</code> allowlist cứng từ phía server. Xem <a href="/security/algorithm-confusion-deep-dive/">Algorithm Confusion</a>.
</Callout>

---

## 5. Nạp khóa: JWKS có cache & xoay khóa

Với RS256/ES256, server cần khóa công khai của IdP. Lấy từ JWKS endpoint, chọn khóa theo `kid`, và **cache** để không gọi mạng mỗi request.

```javascript
import { createRemoteJWKSet } from 'jose';

// jose tự: chọn key theo kid, cache, refetch khi gặp kid lạ (có cooldown)
const JWKS = createRemoteJWKSet(
  new URL('https://auth.example.com/.well-known/jwks.json'),
  {
    cooldownDuration: 30_000,    // tối thiểu 30s giữa hai lần refetch (chống spam)
    cacheMaxAge: 600_000,        // làm tươi cache mỗi 10 phút
    timeoutDuration: 5_000,      // timeout gọi mạng
  },
);
```

```diagram
Request có kid=key-2025  ─▶  JWKS cache có key-2025?
                                  │ có → dùng ngay (0 gọi mạng)
                                  │ không → refetch JWKS (1 lần, có cooldown)
                                          │ thấy → dùng
                                          │ vẫn không → verify fail → 401

Khi IdP xoay khóa (thêm key-2026 cạnh key-2025):
   cửa sổ overlap: JWKS công bố CẢ HAI một thời gian
   → token cũ (key-2025) vẫn verify được tới khi hết hạn hết
   → token mới (key-2026) verify được ngay khi gateway refetch
```

| Vấn đề | Triệu chứng | Khắc phục |
|--------|-------------|-----------|
| Gọi JWKS mỗi request | Chậm, quá tải IdP | Cache + cooldown |
| Cache cứng, không refetch | Token mới (kid mới) 401 hàng loạt sau xoay khóa | Refetch theo kid lạ + cacheMaxAge |
| IdP đổi khóa không overlap | Đứt gãy lúc chuyển | IdP giữ cả khóa cũ+mới một thời gian |
| JWKS endpoint sập | Verify fail toàn bộ → tưởng "token sai" | Cache còn hạn vẫn dùng; phân biệt lỗi hạ tầng (mục 8) |

> [!TIP]
> Cache JWKS là bắt buộc cho hiệu năng (mỗi request gọi mạng lấy khóa sẽ giết throughput) nhưng phải cho phép **refetch khi gặp `kid` lạ** — nếu không, ngay khi IdP xoay khóa, mọi token mới sẽ 401 cho đến khi cache hết hạn. `createRemoteJWKSet` xử lý sẵn cả hai. Với HS256 (secret đối xứng) thì nạp secret từ secret manager, không có JWKS — và cân nhắc tránh HS256 cho hệ phân tán (xem [Algorithm Confusion](/security/algorithm-confusion-deep-dive/)).

---

## 6. 401 vs 403: xác thực khác phân quyền

Trộn lẫn hai mã này gây rò rỉ thông tin và khó debug.

| | 401 Unauthorized | 403 Forbidden |
|---|------------------|---------------|
| Ý nghĩa | "Tôi **không biết bạn là ai**" | "Tôi biết bạn, nhưng **bạn không được phép**" |
| Nguyên nhân | Thiếu token, token sai/hết hạn/chữ ký hỏng | Token hợp lệ nhưng thiếu scope/role |
| Tầng phát sinh | `authenticate` | `authorize` |
| Client nên làm | Đăng nhập lại / refresh token | Không thử lại — thật sự không có quyền |
| `WWW-Authenticate` header | Nên có (`Bearer error="invalid_token"`) | Không áp dụng |

```diagram
Không có/token hỏng ────▶ 401  (đi refresh/login)
Token OK + thiếu scope ──▶ 403  (đừng refresh, vô ích)
```

> [!NOTE]
> Phân biệt đúng giúp client cư xử đúng: gặp **401** thì thử refresh token rồi gọi lại; gặp **403** thì biết là vô vọng, không nên refresh. Trả nhầm 403 cho token hết hạn khiến client không refresh và người dùng bị "kẹt"; trả nhầm 401 cho thiếu quyền khiến client refresh vô ích rồi vẫn 401, dễ rơi vào vòng lặp. Theo RFC 6750, nên kèm `WWW-Authenticate: Bearer error="invalid_token"` cho 401 để client/biết lý do ở mức chung.

---

## 7. Mô hình phân quyền: scope, RBAC, ABAC

Sau khi `authenticate` gắn `req.user`, dùng guard nhỏ kiểm quyền cho từng route. Có ba mô hình phổ biến, thường kết hợp:

```diagram
SCOPE (OAuth)      → quyền dạng "động từ:tài nguyên": orders:read, orders:write
                     hợp với API; client xin scope nào, token mang scope đó
RBAC (role-based)  → gán quyền theo vai trò: admin, editor, viewer
                     đơn giản, dễ hiểu; kém linh hoạt khi nhiều ngoại lệ
ABAC (attribute)   → quyết định theo thuộc tính: "owner mới sửa được resource của mình",
                     "chỉ trong giờ làm việc", "cùng tenant" → linh hoạt nhất, phức tạp nhất
```

```javascript
// Guard: yêu cầu có đủ scope (OAuth scope)
function requireScope(...needed) {
  return (req, res, next) => {
    const have = new Set((req.user?.scope ?? '').split(' ').filter(Boolean));
    const ok = needed.every((s) => have.has(s));
    if (!ok) return res.status(403).json({ error: 'insufficient_scope', needed });
    next();
  };
}

// Guard: yêu cầu role (RBAC)
function requireRole(...roles) {
  return (req, res, next) => {
    const have = new Set(req.user?.roles ?? []);
    if (!roles.some((r) => have.has(r))) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// Guard: kiểm quyền theo thuộc tính (ABAC) — vd chỉ owner mới sửa
function requireOwnership(loadResource) {
  return async (req, res, next) => {
    const resource = await loadResource(req.params.id);
    if (!resource) return res.status(404).json({ error: 'not_found' });
    if (resource.ownerId !== req.user.id) {
      return res.status(403).json({ error: 'not_owner' });
    }
    req.resource = resource;       // tái dùng ở handler, tránh load lại
    next();
  };
}

// Dùng: xác thực trước, rồi phân quyền theo route
app.get('/orders',          authenticate, requireScope('orders:read'),  listOrders);
app.delete('/orders/:id',   authenticate, requireScope('orders:write'),
                            requireOwnership(loadOrder),                deleteOrder);
app.get('/admin/metrics',   authenticate, requireRole('admin'),         metrics);
```

<Callout type="warn">
Quyền hạn phải lấy từ claim đã <b>verify</b> (<code>req.user</code>), không bao giờ từ input client gửi (header tùy ý, body, query). Một lỗi kinh điển là tin <code>X-User-Role</code> do client đặt — kẻ tấn công chỉ việc đặt <code>X-User-Role: admin</code> (Sự cố C). Với ABAC, kiểm quyền sở hữu (ownership) ở tầng server bằng dữ liệu thật — đừng tin "ownerId" client gửi lên.
</Callout>

> [!TIP]
> Đừng nhồi quá nhiều quyền chi tiết vào token (token phình to, khó thu hồi khi đổi quyền). Mẫu thực dụng: token mang `roles`/`scope` *thô*, còn quyền chi tiết (ABAC) tra ở service tại thời điểm request. Khi quyền đổi, bạn không phải chờ token hết hạn. Xem [Authorization Patterns](/security/authorization-patterns/) nếu có.

---

## 8. Xử lý lỗi an toàn

```javascript
// KHÔNG trả chi tiết vì sao verify fail ra ngoài; chỉ log nội bộ
function onAuthError(err, req, res) {
  const code = err?.code || err?.name;       // vd ERR_JWT_EXPIRED, ERR_JWS_SIGNATURE_VERIFICATION_FAILED
  // Phân biệt lỗi client (token sai) vs lỗi hạ tầng (JWKS không nạp được)
  if (code === 'ERR_JWKS_TIMEOUT' || code === 'ERR_JWKS_NO_MATCHING_KEY' && jwksLikelyDown()) {
    req.log?.error({ code }, 'jwks infra error');
    return res.status(503).json({ error: 'auth_unavailable' });   // hạ tầng, KHÔNG phải token sai
  }
  req.log?.warn({ code, kid: tryReadKid(req) }, 'auth failed');   // KHÔNG log cả token
  return res.status(401).json({ error: 'invalid_token' });         // thông điệp chung
}
```

| Nên | Tránh |
|-----|-------|
| Trả thông điệp chung (`invalid_token`) | Trả `signature mismatch`/`wrong audience` (giúp kẻ tấn công dò) |
| Log `err.code` + `kid` nội bộ | Log nguyên token/secret/khóa |
| Trả 401/403 đúng ngữ nghĩa | Trả 500 cho lỗi xác thực (che giấu bug nhưng gây nhiễu alert) |
| Phân biệt lỗi token (4xx) vs hạ tầng khóa (503) | Bắt chung mọi lỗi thành 401 |

> [!TIP]
> Phân biệt **lỗi client** (token sai → 401/403) với **lỗi hệ thống** (JWKS không nạp được, secret manager sập → 500/503). Một bug hay gặp là JWKS gọi mạng lỗi nhưng code bắt chung thành 401 → cả hệ thống "đột nhiên token sai hàng loạt", trong khi thật ra hạ tầng khóa đang lỗi. Trả 503 cho lỗi hạ tầng giúp alert đúng và client biết để thử lại thay vì bắt người dùng đăng nhập lại. Xem [Debugging JWT](/operations/debugging-jwt/).

---

## 9. Revocation & kiểm tra bổ sung

JWT là stateless — verify chữ ký không cho biết token đã bị **thu hồi** chưa. Với hành động nhạy cảm, thêm kiểm tra:

```javascript
// Sau verify, kiểm token chưa bị thu hồi (denylist theo jti, hoặc tokensValidAfter theo user)
async function checkNotRevoked(req, res, next) {
  const { jti, sub, iat } = req.authPayload;            // payload đã verify ở bước trước
  if (jti && await denylist.has(jti)) {                 // token cụ thể bị thu hồi
    return res.status(401).json({ error: 'token_revoked' });
  }
  const validAfter = await getTokensValidAfter(sub);    // mốc "đăng xuất mọi nơi" của user
  if (validAfter && iat < validAfter) {                 // token cấp trước mốc → vô hiệu
    return res.status(401).json({ error: 'token_revoked' });
  }
  next();
}
```

```diagram
HAI KIỂU THU HỒI:
  denylist theo jti        → thu hồi MỘT token cụ thể (vd phát hiện rò)
  tokensValidAfter theo sub→ thu hồi MỌI token của user (đăng xuất mọi nơi, đổi mật khẩu)
ĐÁNH ĐỔI: thêm kiểm tra = thêm tra cứu (Redis) mỗi request → chỉ áp cho route nhạy cảm,
          hoặc giữ access TTL ngắn để revocation "tự nhiên" qua hết hạn.
```

> [!NOTE]
> Kiểm revocation phá tính stateless và thêm độ trễ — nên cân nhắc: access token TTL ngắn (vài phút) khiến cửa sổ lạm dụng nhỏ, nhiều hệ chấp nhận "thu hồi mềm" bằng TTL ngắn thay vì denylist mỗi request. Chỉ kiểm denylist cho hành động nhạy cảm (chuyển tiền, đổi cấu hình). Chi tiết: [Revocation & Logout](/lifecycle/revocation-and-logout/).

---

## 10. Mẫu đầy đủ theo framework

### 10.1 Express

```javascript
import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express();
const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

const VERIFY_OPTS = {
  algorithms: ['RS256'], issuer: 'https://auth.example.com',
  audience: 'api.orders', clockTolerance: '30s',
  requiredClaims: ['exp', 'sub', 'aud'],
};

async function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? '').split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'missing_token' });
  try {
    const { payload } = await jwtVerify(token, JWKS, VERIFY_OPTS);
    req.user = { id: payload.sub, scope: payload.scope ?? '', roles: payload.roles ?? [] };
    next();
  } catch (err) {
    req.log?.warn({ code: err.code }, 'verify failed');
    res.status(401).json({ error: 'invalid_token' });
  }
}

const requireScope = (...needed) => (req, res, next) => {
  const have = new Set((req.user?.scope ?? '').split(' ').filter(Boolean));
  if (!needed.every((s) => have.has(s))) return res.status(403).json({ error: 'insufficient_scope' });
  next();
};

app.get('/orders', authenticate, requireScope('orders:read'), (req, res) => res.json({ user: req.user.id }));
app.listen(3000);
```

### 10.2 Fastify

```javascript
import Fastify from 'fastify';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = Fastify();
const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

app.decorate('authenticate', async (req, reply) => {
  const [scheme, token] = (req.headers.authorization ?? '').split(' ');
  if (scheme !== 'Bearer' || !token) return reply.code(401).send({ error: 'missing_token' });
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ['RS256'], issuer: 'https://auth.example.com', audience: 'api.orders',
    });
    req.user = { id: payload.sub, scope: payload.scope ?? '' };
  } catch {
    return reply.code(401).send({ error: 'invalid_token' });
  }
});

app.decorate('requireScope', (...needed) => async (req, reply) => {
  const have = new Set((req.user?.scope ?? '').split(' ').filter(Boolean));
  if (!needed.every((s) => have.has(s))) return reply.code(403).send({ error: 'insufficient_scope' });
});

app.get('/orders',
  { preHandler: [app.authenticate, app.requireScope('orders:read')] },
  async (req) => ({ user: req.user.id }));
app.listen({ port: 3000 });
```

### 10.3 NestJS

```typescript
// jwt.guard.ts — authenticate
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

@Injectable()
export class JwtGuard implements CanActivate {
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const [scheme, token] = (req.headers.authorization ?? '').split(' ');
    if (scheme !== 'Bearer' || !token) throw new UnauthorizedException('missing_token');
    try {
      const { payload } = await jwtVerify(token, JWKS, {
        algorithms: ['RS256'], issuer: 'https://auth.example.com', audience: 'api.orders',
      });
      req.user = { id: payload.sub, scope: payload.scope ?? '', roles: payload.roles ?? [] };
      return true;
    } catch {
      throw new UnauthorizedException('invalid_token');
    }
  }
}
```

```typescript
// scopes.guard.ts — authorize (đọc metadata @Scopes('orders:read'))
import { CanActivate, ExecutionContext, Injectable, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SetMetadata } from '@nestjs/common';

export const Scopes = (...s: string[]) => SetMetadata('scopes', s);

@Injectable()
export class ScopesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext): boolean {
    const needed = this.reflector.get<string[]>('scopes', ctx.getHandler()) ?? [];
    const req = ctx.switchToHttp().getRequest();
    const have = new Set((req.user?.scope ?? '').split(' ').filter(Boolean));
    if (!needed.every((s) => have.has(s))) throw new ForbiddenException('insufficient_scope');
    return true;
  }
}

// controller: @UseGuards(JwtGuard, ScopesGuard) + @Scopes('orders:read')
```

> [!NOTE]
> Dù framework khác nhau, cấu trúc luôn giống: **đọc Bearer → verify với allowlist + iss/aud/exp → gắn user → để guard riêng lo scope/role**. Đừng dùng thư viện "tự động" mà không cấu hình allowlist `algorithms` — nhiều thư viện mặc định lỏng lẻo (chấp nhận nhiều alg, không kiểm `aud`).

---

## 11. Edge cases thực tế — những lỗi khó debug

### 11.1 Clock skew giữa auth server và API

```diagram
Auth server cấp token: iat=10:00:00, exp=10:05:00
API server đồng hồ NHANH 90s: now=10:06:30 khi nhận token vừa cấp 30s trước
  → now > exp → 401 "token expired" dù token mới tinh
Khắc phục: clockTolerance 30–60s + đồng bộ NTP mọi máy. Đừng đặt tolerance quá lớn (vài phút)
           vì nó nới rộng cửa sổ dùng token hết hạn.
```

### 11.2 `aud` là chuỗi vs mảng

`aud` có thể là string `"api.orders"` hoặc mảng `["api.orders","api.web"]`. Thư viện verify thường xử lý cả hai, nhưng code tự viết hay quên: so sánh `payload.aud === 'api.orders'` sẽ fail khi `aud` là mảng. Dùng thư viện (jose) để khỏi tự xử lý, hoặc kiểm "có chứa" thay vì "bằng".

### 11.3 Token verify được nhưng thiếu claim mong đợi

Verify chữ ký + iss/aud/exp thành công, nhưng `payload.scope`/`payload.roles` `undefined` vì IdP cấu hình không phát claim đó. Hậu quả: guard `requireScope` luôn 403. Soi bằng cách log claim đã verify (không log token) khi 403 bất thường, và xác nhận IdP có map claim vào token.

### 11.4 Hai service chung audience

Nếu nhiều service dùng chung `aud="api"`, token của service này dùng được ở service kia (Sự cố B ở mức nhẹ). Đặt `aud` riêng cho từng service (`api.orders`, `api.billing`) để phân tách tin cậy. Xem [Audience / Issuer / Subject](/internals/audience-issuer-subject/).

### 11.5 Header `Authorization` bị proxy/loadbalancer xóa

Một số cấu hình proxy strip hoặc đổi tên header `Authorization`. Triệu chứng: client gửi token, server thấy "missing_token". Kiểm tra cấu hình proxy (`proxy_set_header Authorization $http_authorization;` với Nginx) và đảm bảo không có middleware nào xóa header.

---

## 12. Anti-patterns & lỗi triển khai thường gặp

| Lỗi | Hậu quả | Khắc phục |
|-----|---------|-----------|
| Không truyền `algorithms` allowlist | alg:none / confusion | Luôn `algorithms: ['RS256']` |
| Quên kiểm `aud` | Token service khác dùng được | Đặt `audience` riêng từng service |
| Quên kiểm `iss` | Token IdP khác được chấp nhận | Đặt `issuer` |
| Dùng `decode` thay `verify` | Nhận token giả/giả mạo | Luôn `jwtVerify` |
| Đọc quyền/identity từ header client | Leo thang đặc quyền | Lấy từ payload đã verify |
| Gọi JWKS mỗi request | Chậm, quá tải IdP | Cache + refetch theo `kid` |
| Trả 403 cho token hết hạn | Client không refresh, kẹt | 401 cho lỗi token, 403 cho thiếu quyền |
| Bắt mọi lỗi thành 401 | Che lỗi hạ tầng JWKS | Phân biệt 4xx token vs 503 hạ tầng |
| Lộ chi tiết lỗi verify ra client | Hỗ trợ kẻ tấn công dò | Thông điệp chung + log nội bộ |
| Nhồi quá nhiều quyền vào token | Token phình, khó thu hồi khi đổi quyền | Quyền thô trong token, chi tiết tra ở service |
| Tin "token nội bộ nên khỏi verify" | Lateral movement | Mỗi service verify (zero-trust) — xem microservices |

---

## 13. Câu hỏi thường gặp

<Accordions>

<Accordion title="Có cần verify lại token ở mỗi service nếu gateway đã verify?">
Với hệ nhạy cảm: nên (zero-trust). Gateway verify chặn rác ở biên, nhưng một service bị xâm nhập không nên gọi tự do các service khác. Verify lại rẻ khi cache JWKS. Nếu chọn tin gateway, phải đảm bảo service chỉ nhận traffic qua gateway (network policy/mTLS). Xem [Microservices Auth](/implementation/microservices-auth/) và [API Gateway Auth](/implementation/api-gateway-auth/).
</Accordion>

<Accordion title="Nên dùng HS256 hay RS256 cho backend?">
RS256 (bất đối xứng) cho hệ phân tán: IdP giữ private key ký, các service chỉ cần public key để verify — không service nào ký được token giả. HS256 dùng chung secret, mọi bên verify được cũng ký được, và rủi ro confusion cao. Dùng HS256 chỉ khi một service vừa cấp vừa verify token của chính nó.
</Accordion>

<Accordion title="Có nên kiểm revocation cho mọi request?">
Không nhất thiết. Kiểm denylist mỗi request thêm độ trễ và phá stateless. Mẫu thực dụng: access TTL ngắn (vài phút) để revocation "tự nhiên" qua hết hạn, chỉ kiểm denylist cho hành động nhạy cảm. Xem mục 9 và [Revocation & Logout](/lifecycle/revocation-and-logout/).
</Accordion>

<Accordion title="Vì sao không trả lý do verify fail cụ thể cho client?">
Vì nó giúp kẻ tấn công dò (vd "wrong audience" tiết lộ token đúng chữ ký nhưng sai aud → chúng biết đang đi đúng hướng). Trả `invalid_token` chung, log chi tiết (err.code, kid) nội bộ để bạn vẫn debug được.
</Accordion>

</Accordions>

---

## 14. Checklist backend API auth

```diagram
XÁC THỰC (authenticate):
□ Đọc Bearer đúng (tách scheme; đúng 2 phần; không đọc từ URL)
□ jwtVerify với algorithms allowlist (KHÔNG tin header.alg)
□ Kiểm issuer + audience + exp + nbf (+ requiredClaims)
□ clockTolerance hợp lý (vd 30s) + đồng bộ NTP
□ JWKS cache + refetch theo kid (RS256) / secret từ manager (HS256)
□ Gắn req.user từ claim ĐÃ verify

PHÂN QUYỀN (authorize):
□ Guard scope/role/ownership riêng, sau authenticate
□ Quyền lấy từ req.user (claim verify), KHÔNG từ input client
□ 401 = không biết bạn; 403 = biết nhưng không đủ quyền
□ Không nhồi quá nhiều quyền chi tiết vào token

LỖI & QUAN SÁT:
□ Thông điệp lỗi chung; log err.code + kid nội bộ (không log token)
□ Phân biệt lỗi token (401/403) vs lỗi hạ tầng khóa (503)
□ Kèm WWW-Authenticate cho 401
□ Metric verify_failures_total{reason} để theo dõi

NÂNG CAO:
□ Revocation (denylist jti / tokensValidAfter) cho route nhạy cảm
□ Rate limit theo sub (sau verify)
□ aud riêng từng service để phân tách tin cậy
```

<Callout type="success" title="Một câu để nhớ">
<b>Đọc Bearer → verify đủ (allowlist + iss/aud/exp/nbf) → gắn user → guard scope/role/ownership.</b> Authenticate trả 401, authorize trả 403, lỗi hạ tầng trả 503, và quyền hạn luôn đến từ claim đã verify chứ không từ input client.
</Callout>

---

## Tài liệu tham khảo

- [HTTP Transport & Storage](/implementation/http-transport-and-storage/) — đọc Bearer, không để token trên URL
- [Token Validation Deep Dive](/internals/token-validation-deep-dive/) — pipeline verify chi tiết
- [Algorithm Confusion](/security/algorithm-confusion-deep-dive/) — vì sao allowlist `algorithms`
- [Audience / Issuer / Subject](/internals/audience-issuer-subject/) — ý nghĩa claim aud/iss/sub
- [API Gateway Auth](/implementation/api-gateway-auth/) — verify tập trung ở gateway
- [Microservices Auth](/implementation/microservices-auth/) — verify ở mỗi service (zero-trust)
- [Revocation & Logout](/lifecycle/revocation-and-logout/) — thu hồi token, tokensValidAfter
- [Security Best Practices](/security/security-best-practices/) — chuẩn cấu hình verify
- [Debugging JWT](/operations/debugging-jwt/) — chẩn đoán 401/403
- [Testing Auth Flow](/operations/testing-auth-flow/) — test negative cases cho tầng verify
- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
