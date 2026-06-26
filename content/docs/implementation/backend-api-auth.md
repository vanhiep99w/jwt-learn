---
title: "Backend API Authentication"
description: "Triển khai JWT đầy đủ cho REST API: middleware xác thực tách khỏi authorization, đọc Bearer đúng cách, verify đủ claim (alg allowlist, iss/aud/exp), nạp khóa JWKS có cache, phân biệt 401 vs 403, guard theo scope/role, xử lý lỗi an toàn, và mẫu code chạy được cho Express + Fastify + NestJS."
---

# Backend API Authentication

## Mục lục

- [Tổng quan](#tổng-quan)
- [1. Kiến trúc tầng auth trong API](#1-kiến-trúc-tầng-auth-trong-api)
- [2. Middleware xác thực (authenticate)](#2-middleware-xác-thực-authenticate)
  - [2.1 Đọc Bearer token đúng cách](#21-đọc-bearer-token-đúng-cách)
  - [2.2 Verify đủ claim](#22-verify-đủ-claim)
- [3. Nạp khóa: JWKS có cache](#3-nạp-khóa-jwks-có-cache)
- [4. 401 vs 403: xác thực khác phân quyền](#4-401-vs-403-xác-thực-khác-phân-quyền)
- [5. Authorization: guard theo scope/role](#5-authorization-guard-theo-scoperole)
- [6. Xử lý lỗi an toàn](#6-xử-lý-lỗi-an-toàn)
- [7. Mẫu đầy đủ theo framework](#7-mẫu-đầy-đủ-theo-framework)
  - [7.1 Express](#71-express)
  - [7.2 Fastify](#72-fastify)
  - [7.3 NestJS](#73-nestjs)
- [8. Những lỗi triển khai thường gặp](#8-những-lỗi-triển-khai-thường-gặp)
- [9. Checklist backend API auth](#9-checklist-backend-api-auth)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan

Backend API là nơi JWT được **verify** — và là nơi nhiều lỗ hổng nghiêm trọng phát sinh: chấp nhận `alg` tùy ý, quên kiểm `aud`/`iss`, nhầm "giải mã được" thành "đã xác thực", hoặc trộn lẫn xác thực với phân quyền thành một mớ khó kiểm. Doc này dựng tầng auth cho REST API theo nguyên tắc rõ ràng: **authenticate** (bạn là ai — verify token) tách bạch khỏi **authorize** (bạn được làm gì — kiểm scope/role).

```diagram
Request ─▶ [authenticate] ─▶ [authorize] ─▶ [handler]
            verify token       kiểm scope     business logic
            sai → 401          sai → 403       trả dữ liệu
            (chưa biết bạn)    (biết bạn,
                                không đủ quyền)
```

> [!IMPORTANT]
> Quy tắc bất biến: **decode ≠ verify ≠ authorize**. Giải mã payload chỉ cho bạn *nội dung token tự nhận*; phải `verify` chữ ký + claim mới biết token *thật*; và verify xong vẫn phải kiểm *scope/role* mới biết được phép làm gì. Bỏ bất kỳ bước nào là một lớp lỗ hổng.

---

## 1. Kiến trúc tầng auth trong API

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

Tách thành các tầng giúp: (1) test từng tầng độc lập, (2) tái dùng `authenticate` cho mọi route, (3) đặt `authorize` khác nhau cho mỗi route mà không lặp logic verify.

---

## 2. Middleware xác thực (authenticate)

### 2.1 Đọc Bearer token đúng cách

```javascript
// Đọc token từ header Authorization: Bearer <token>
function extractBearer(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return null;   // đúng scheme + có token
  return token.trim();
}
```

> [!WARNING]
> Đừng dùng `header.replace('Bearer ', '')` cẩu thả — nó sẽ "ăn" chuỗi "Bearer " ở bất kỳ đâu và bỏ qua trường hợp sai scheme. Hãy tách theo space và kiểm `scheme === 'Bearer'` tường minh. Cũng đừng đọc token từ query string (`?token=`) — token không được nằm trên URL ([lý do](/implementation/http-transport-and-storage/)).

### 2.2 Verify đủ claim

Đây là trái tim của tầng auth. Mọi tham số dưới đây đều bắt buộc:

```javascript
import { jwtVerify } from 'jose';

const VERIFY_OPTS = {
  algorithms: ['RS256'],                       // ALLOWLIST — chặn alg:none & confusion
  issuer: 'https://auth.example.com',          // đúng nơi cấp
  audience: 'api.orders',                       // token dành cho ĐÚNG service này
  clockTolerance: '30s',                        // dung sai lệch giờ máy chủ
  requiredClaims: ['exp', 'sub', 'aud', 'iss'], // bắt buộc có mặt
};

async function authenticate(req, res, next) {
  const token = extractBearer(req);
  if (!token) return res.status(401).json({ error: 'missing_token' });
  try {
    const { payload } = await jwtVerify(token, JWKS, VERIFY_OPTS);
    req.user = { id: payload.sub, scope: payload.scope, roles: payload.roles ?? [] };
    next();
  } catch (err) {
    // KHÔNG lộ chi tiết; log nội bộ, trả 401 chung
    req.log?.warn({ code: err.code }, 'jwt verify failed');
    return res.status(401).json({ error: 'invalid_token' });
  }
}
```

| Tham số | Vì sao bắt buộc | Bỏ qua = lỗ hổng |
|---------|------------------|-------------------|
| `algorithms` (allowlist) | Cố định thuật toán mong đợi | `alg:none`, RS256→HS256 confusion |
| `issuer` | Chỉ tin token từ đúng IdP | Chấp nhận token IdP khác cấp |
| `audience` | Token đúng dành cho service này | Token của service A dùng được ở service B |
| `exp` (+ tự kiểm) | Token hết hạn bị từ chối | Token sống mãi |
| `clockTolerance` | Tránh false-negative do lệch giờ | 401 chập chờn giữa các máy |

<Callout type="error" title="Sai lầm chí mạng: tin alg trong header">
Tuyệt đối <b>không</b> lấy thuật toán từ <code>header.alg</code> của chính token để rồi verify theo đó. Kẻ tấn công sẽ đặt <code>alg:none</code> hoặc đổi RS256→HS256 để bỏ qua/giả chữ ký. Luôn truyền <code>algorithms</code> allowlist cứng từ phía server. Xem <a href="/security/algorithm-confusion-deep-dive/">Algorithm Confusion</a>.
</Callout>

---

## 3. Nạp khóa: JWKS có cache

Với RS256/ES256, server cần khóa công khai của IdP. Lấy từ JWKS endpoint, chọn khóa theo `kid`, và **cache** để không gọi mạng mỗi request.

```javascript
import { createRemoteJWKSet } from 'jose';

// jose tự: chọn key theo kid, cache, refetch khi gặp kid lạ (có cooldown)
const JWKS = createRemoteJWKSet(
  new URL('https://auth.example.com/.well-known/jwks.json'),
  { cooldownDuration: 30_000, cacheMaxAge: 600_000 },
);
```

```diagram
Request có kid=key-2025  ─▶  JWKS cache có key-2025?
                                  │ có → dùng ngay (0 gọi mạng)
                                  │ không → refetch JWKS (1 lần, có cooldown)
                                          │ thấy → dùng
                                          │ vẫn không → verify fail → 401
```

> [!TIP]
> Cache JWKS là bắt buộc cho hiệu năng (mỗi request gọi mạng lấy khóa sẽ giết throughput) nhưng phải cho phép **refetch khi gặp `kid` lạ** — nếu không, ngay khi IdP xoay khóa, mọi token mới sẽ 401 cho đến khi cache hết hạn. `createRemoteJWKSet` xử lý sẵn cả hai. Với HS256 (secret đối xứng) thì nạp secret từ secret manager, không có JWKS.

---

## 4. 401 vs 403: xác thực khác phân quyền

Trộn lẫn hai mã này gây rò rỉ thông tin và khó debug.

| | 401 Unauthorized | 403 Forbidden |
|---|------------------|---------------|
| Ý nghĩa | "Tôi **không biết bạn là ai**" | "Tôi biết bạn, nhưng **bạn không được phép**" |
| Nguyên nhân | Thiếu token, token sai/hết hạn/chữ ký hỏng | Token hợp lệ nhưng thiếu scope/role |
| Tầng phát sinh | `authenticate` | `authorize` |
| Client nên làm | Đăng nhập lại / refresh token | Không thử lại — thật sự không có quyền |

```diagram
Không có/﻿token hỏng ────▶ 401  (đi refresh/login)
Token OK + thiếu scope ──▶ 403  (đừng refresh, vô ích)
```

> [!NOTE]
> Phân biệt đúng giúp client cư xử đúng: gặp **401** thì thử refresh token rồi gọi lại; gặp **403** thì biết là vô vọng, không nên refresh. Trả nhầm 403 cho token hết hạn khiến client không refresh và người dùng bị "kẹt".

---

## 5. Authorization: guard theo scope/role

Sau khi `authenticate` gắn `req.user`, dùng guard nhỏ kiểm quyền cho từng route:

```javascript
// Guard: yêu cầu có đủ scope
function requireScope(...needed) {
  return (req, res, next) => {
    const have = new Set((req.user?.scope ?? '').split(' '));
    const ok = needed.every((s) => have.has(s));
    if (!ok) return res.status(403).json({ error: 'insufficient_scope', needed });
    next();
  };
}

// Guard: yêu cầu role
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user?.roles?.includes(role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// Dùng: xác thực trước, rồi phân quyền theo route
app.get('/orders',            authenticate, requireScope('orders:read'),  listOrders);
app.delete('/orders/:id',     authenticate, requireScope('orders:write'), deleteOrder);
app.get('/admin/metrics',     authenticate, requireRole('admin'),         metrics);
```

<Callout type="warn">
Quyền hạn phải lấy từ claim đã <b>verify</b> (<code>req.user</code>), không bao giờ từ input client gửi (header tùy ý, body, query). Một lỗi kinh điển là tin <code>X-User-Role</code> do client đặt — kẻ tấn công chỉ việc đặt <code>X-User-Role: admin</code>.
</Callout>

---

## 6. Xử lý lỗi an toàn

```javascript
// KHÔNG trả chi tiết vì sao verify fail ra ngoài; chỉ log nội bộ
catch (err) {
  const code = err?.code || err?.name;       // vd ERR_JWT_EXPIRED
  req.log?.warn({ code, kid: tryReadKid(token) }, 'auth failed');  // KHÔNG log cả token
  return res.status(401).json({ error: 'invalid_token' });          // thông điệp chung
}
```

| Nên | Tránh |
|-----|-------|
| Trả thông điệp chung (`invalid_token`) | Trả `signature mismatch`/`wrong audience` (giúp kẻ tấn công dò) |
| Log `err.code` + `kid` nội bộ | Log nguyên token/secret/khóa |
| Trả 401/403 đúng ngữ nghĩa | Trả 500 cho lỗi xác thực (che giấu bug nhưng gây nhiễu alert) |

> [!TIP]
> Phân biệt **lỗi client** (token sai → 401/403) với **lỗi hệ thống** (JWKS không nạp được, secret manager sập → 500/503). Một bug hay gặp là JWKS gọi mạng lỗi nhưng code bắt chung thành 401 → cả hệ thống "đột nhiên token sai hàng loạt", trong khi thật ra hạ tầng khóa đang lỗi. Xem [Debugging JWT](/operations/debugging-jwt/).

---

## 7. Mẫu đầy đủ theo framework

### 7.1 Express

```javascript
import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express();
const JWKS = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));

async function authenticate(req, res, next) {
  const h = req.headers.authorization;
  const [scheme, token] = (h ?? '').split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'missing_token' });
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ['RS256'], issuer: 'https://auth.example.com',
      audience: 'api.orders', clockTolerance: '30s',
      requiredClaims: ['exp', 'sub', 'aud'],
    });
    req.user = { id: payload.sub, scope: payload.scope ?? '', roles: payload.roles ?? [] };
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
}

app.get('/orders', authenticate, (req, res) => res.json({ user: req.user.id }));
app.listen(3000);
```

### 7.2 Fastify

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

app.get('/orders', { preHandler: [app.authenticate] }, async (req) => ({ user: req.user.id }));
app.listen({ port: 3000 });
```

### 7.3 NestJS

```typescript
// jwt.guard.ts
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
      req.user = { id: payload.sub, scope: payload.scope ?? '' };
      return true;
    } catch {
      throw new UnauthorizedException('invalid_token');
    }
  }
}

// dùng: @UseGuards(JwtGuard) trên controller/route
```

> [!NOTE]
> Dù framework khác nhau, cấu trúc luôn giống: **đọc Bearer → verify với allowlist + iss/aud/exp → gắn user → để guard riêng lo scope/role**. Đừng dùng thư viện "tự động" mà không cấu hình allowlist `algorithms` — nhiều thư viện mặc định lỏng lẻo.

---

## 8. Những lỗi triển khai thường gặp

| Lỗi | Hậu quả | Khắc phục |
|-----|---------|-----------|
| Không truyền `algorithms` allowlist | alg:none / confusion | Luôn `algorithms: ['RS256']` |
| Quên kiểm `aud` | Token service khác dùng được | Đặt `audience` |
| Quên kiểm `iss` | Token IdP khác được chấp nhận | Đặt `issuer` |
| Dùng `decode` thay `verify` | Nhận token giả/giả mạo | Luôn `jwtVerify` |
| Tin role từ header client | Leo thang đặc quyền | Lấy role từ payload đã verify |
| Gọi JWKS mỗi request | Chậm, quá tải IdP | Cache + refetch theo `kid` |
| Trả 403 cho token hết hạn | Client không refresh, kẹt | 401 cho lỗi token, 403 cho thiếu quyền |
| Lộ chi tiết lỗi verify | Hỗ trợ kẻ tấn công dò | Thông điệp chung + log nội bộ |

---

## 9. Checklist backend API auth

```diagram
XÁC THỰC (authenticate):
□ Đọc Bearer đúng (tách scheme; không đọc từ URL)
□ jwtVerify với algorithms allowlist (KHÔNG tin header.alg)
□ Kiểm issuer + audience + exp (+ requiredClaims)
□ clockTolerance hợp lý (vd 30s)
□ JWKS cache + refetch theo kid (RS256) / secret từ manager (HS256)
□ Gắn req.user từ claim ĐÃ verify

PHÂN QUYỀN (authorize):
□ Guard scope/role riêng, sau authenticate
□ Quyền lấy từ req.user (claim verify), KHÔNG từ input client
□ 401 = không biết bạn; 403 = biết nhưng không đủ quyền

LỖI & QUAN SÁT:
□ Thông điệp lỗi chung; log err.code + kid nội bộ (không log token)
□ Phân biệt lỗi token (401/403) vs lỗi hạ tầng khóa (500/503)
□ Metric verify_failures_total{reason} để theo dõi
```

<Callout type="success" title="Một câu để nhớ">
<b>Đọc Bearer → verify đủ (allowlist + iss/aud/exp) → gắn user → guard scope/role.</b> Authenticate trả 401, authorize trả 403, và quyền hạn luôn đến từ claim đã verify chứ không từ input client.
</Callout>

---

## Tài liệu tham khảo

- [HTTP Transport & Storage](/implementation/http-transport-and-storage/) — đọc Bearer, không để token trên URL
- [Token Validation Deep Dive](/internals/token-validation-deep-dive/) — pipeline verify chi tiết
- [Algorithm Confusion](/security/algorithm-confusion-deep-dive/) — vì sao allowlist `algorithms`
- [Audience / Issuer / Subject](/internals/audience-issuer-subject/) — ý nghĩa claim aud/iss/sub
- [API Gateway Auth](/implementation/api-gateway-auth/) — verify tập trung ở gateway
- [Security Best Practices](/security/security-best-practices/) — chuẩn cấu hình verify
- [Debugging JWT](/operations/debugging-jwt/) — chẩn đoán 401/403
- [Testing Auth Flow](/operations/testing-auth-flow/) — test negative cases cho tầng verify
