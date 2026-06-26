---
title: "Testing Auth Flow"
description: "Chiến lược test chi tiết cho luồng xác thực JWT: kim tự tháp test, ma trận phủ 7 cổng verify, bộ negative case bắt buộc kèm code đầy đủ (alg:none, RS→HS confusion, sửa chữ ký, hết hạn, sai aud/iss, replay refresh), helper sign/verify, mock JWKS bằng msw, integration test middleware bằng supertest, E2E Playwright, và CI gate chặn anti-pattern."
---

# Testing Auth Flow

## Mục lục

- [Tổng quan](#tổng-quan)
- [1. Vì sao test auth khác test thường](#1-vì-sao-test-auth-khác-test-thường)
- [2. Kim tự tháp test cho JWT](#2-kim-tự-tháp-test-cho-jwt)
- [3. Ma trận phủ test theo cổng verify](#3-ma-trận-phủ-test-theo-cổng-verify)
- [4. Test fixtures & helper](#4-test-fixtures--helper)
- [5. Unit test: từng cổng verify](#5-unit-test-từng-cổng-verify)
- [6. Negative cases BẮT BUỘC (kèm code)](#6-negative-cases-bắt-buộc-kèm-code)
  - [6.1 alg:none](#61-algnone)
  - [6.2 Algorithm confusion RS256 → HS256](#62-algorithm-confusion-rs256--hs256)
  - [6.3 Sửa chữ ký / payload](#63-sửa-chữ-ký--payload)
  - [6.4 Hết hạn & chưa hiệu lực](#64-hết-hạn--chưa-hiệu-lực)
  - [6.5 Sai aud / iss / thiếu exp](#65-sai-aud--iss--thiếu-exp)
- [7. Giả lập thời gian & khóa](#7-giả-lập-thời-gian--khóa)
- [8. Mock JWKS endpoint](#8-mock-jwks-endpoint)
- [9. Integration test middleware](#9-integration-test-middleware)
- [10. Test refresh & rotation/reuse](#10-test-refresh--rotationreuse)
- [11. E2E luồng đăng nhập](#11-e2e-luồng-đăng-nhập)
- [12. CI gate cho bảo mật token](#12-ci-gate-cho-bảo-mật-token)
- [13. Checklist test auth](#13-checklist-test-auth)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan

Test auth flow không chỉ là "đăng nhập thành công thì trả token". Phần lớn giá trị nằm ở **negative test** — đảm bảo token sai, hết hạn, giả mạo, hoặc đã thu hồi đều **bị từ chối**. Một hệ auth có 100% test "happy path" pass vẫn có thể dính `alg:none` hoặc lặng lẽ chấp nhận token hết hạn.

```diagram
   Test "happy path" trả lời:   "Người dùng ĐÚNG có vào được không?"
   Negative test trả lời:        "Người dùng SAI có bị CHẶN không?"   ← quan trọng hơn

   Bug happy path  → người dùng kêu ngay → phát hiện nhanh
   Bug negative    → IM LẶNG → đến khi bị khai thác mới biết
```

> [!IMPORTANT]
> Với auth, **negative test quan trọng hơn positive test**. Một bug làm login thất bại bị phát hiện ngay (người dùng phàn nàn). Một bug làm hệ thống *chấp nhận token không hợp lệ* thì im lặng cho đến khi bị khai thác. Mọi cổng trong [pipeline verify 7 cổng](/internals/token-validation-flow/) phải có ít nhất một test chứng minh "token sai cổng này → 401".

---

## 1. Vì sao test auth khác test thường

| Đặc điểm | Test logic thường | Test auth flow |
|----------|-------------------|----------------|
| Trọng tâm | Output đúng với input đúng | Input SAI bị TỪ CHỐI đúng cách |
| Phụ thuộc thời gian | Hiếm | Cao (`exp`, `nbf`, rotation, clock skew) |
| Phụ thuộc khóa | Không | Có (keypair test, JWKS giả) |
| Tiêu chí "đậu" | Trả đúng giá trị | Trả đúng **mã lỗi** (401 vs 403) và **không rò** thông tin |
| Rủi ro khi sai | Bug chức năng | Lỗ hổng bảo mật im lặng |
| Tính tất định | Thường tất định | Dễ flaky vì thời gian/async → phải kiểm soát đồng hồ |

<Callout type="warn">
Phân biệt rõ <b>401 (Unauthorized)</b> — không xác thực được (token sai/thiếu/hết hạn) — với <b>403 (Forbidden)</b> — xác thực OK nhưng không đủ quyền. Test phải assert đúng mã, vì nhầm lẫn hai mã này thường che giấu lỗi logic phân quyền và làm sai luồng retry/refresh ở client.
</Callout>

---

## 2. Kim tự tháp test cho JWT

```diagram
                  ╱╲
                 ╱  ╲   E2E (ít): login UI → gọi API thật → silent refresh → logout
                ╱────╲       chậm, dễ vỡ, chỉ phủ luồng quan trọng nhất
               ╱      ╲
              ╱  INTEG ╲  Integration (vừa): middleware verify + route bảo vệ
             ╱──────────╲      + store refresh/denylist (in-memory / testcontainer)
            ╱            ╲
           ╱    UNIT      ╲ Unit (nhiều): sign/verify, kiểm từng claim, parse header,
          ╱────────────────╲    denylist lookup — nhanh, tất định, phủ mọi negative case
```

| Tầng | Test cái gì | Tốc độ / số lượng |
|------|-------------|--------------------|
| **Unit** | `signToken`, `verifyToken`, từng claim, parse header, denylist lookup | Nhanh nhất, nhiều nhất |
| **Integration** | Middleware verify + route được bảo vệ + store (Redis/DB giả) | Vừa |
| **E2E** | Login → token → gọi API → refresh → logout qua HTTP/UI thật | Chậm, ít nhất |

> [!TIP]
> Phần lớn negative case bảo mật (`alg:none`, sai chữ ký, hết hạn) nên test ở tầng **unit/integration** vì nhanh và tất định. Chỉ đẩy lên E2E những luồng end-to-end thực sự cần (đăng nhập đầy đủ, silent refresh trong trình duyệt). Đẩy negative case lên E2E vừa chậm vừa khó tái hiện ổn định.

---

## 3. Ma trận phủ test theo cổng verify

Mỗi cổng verify cần cả case PASS và case FAIL. Dùng bảng này như định nghĩa "đã phủ đủ":

| Cổng verify | Case PASS | Case FAIL (negative) |
|-------------|-----------|----------------------|
| Định dạng (3 phần) | token chuẩn | rỗng, `"abc"`, thiếu/thừa phần |
| Thuật toán (allowlist) | `RS256` đúng | `alg:none`, `HS256` confusion, `alg` lạ |
| Chữ ký | ký bằng đúng key | sửa payload, sai key, sai `kid` |
| `exp` | còn hạn | quá khứ; thiếu `exp` |
| `nbf` | đã tới | tương lai |
| `iss` | đúng issuer | issuer khác |
| `aud` | đúng audience | service khác; `aud` mảng không chứa |
| Thu hồi | chưa revoke | trong denylist; trước `tokensValidAfter`; replay refresh |
| Authorization | đủ `scope`/`role` → 200 | thiếu quyền → **403** (không phải 401) |

> [!NOTE]
> Một cách kiểm "đã đủ test chưa" trong review PR: mở bảng này, mỗi dòng cột FAIL hỏi *"có test nào chứng minh điều này bị từ chối không?"*. Thiếu dòng nào = lỗ hổng tiềm tàng ở cổng đó.

---

## 4. Test fixtures & helper

Đặt nền tảng: keypair test riêng, hàm `signTestToken` để tạo token với claim tùy biến (kể cả token "xấu"):

```javascript
// test/helpers/jwt.js
import { generateKeyPair, SignJWT, exportJWK } from 'jose';

export const ISS = 'https://auth.test';
export const AUD = 'api.orders';
export const nowSec = () => Math.floor(Date.now() / 1000);

// Sinh keypair RS256 cho cả suite (KHÔNG dùng khóa prod)
export async function makeKeys() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-kid', alg: 'RS256', use: 'sig' };
  return { publicKey, privateKey, jwks: { keys: [jwk] } };
}

// Ký token hợp lệ — cho phép override để tạo token "xấu" trong negative test
export async function signTestToken(privateKey, override = {}) {
  const claims = { sub: 'u1', aud: AUD, iss: ISS, ...override.claims };
  const exp = override.exp ?? nowSec() + 900;   // mặc định còn hạn 15'
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid', ...override.header })
    .setIssuedAt(override.iat ?? nowSec())
    .setExpirationTime(exp);
  if (override.nbf) jwt.setNotBefore(override.nbf);
  if (override.jti) jwt.setJti(override.jti);
  return jwt.sign(override.signKey ?? privateKey);
}

// Tạo nhanh một chuỗi 3-phần Base64URL thủ công (cho test alg:none / confusion)
export const b64url = (obj) =>
  Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj)).toString('base64url');
```

<Callout type="info">
Một <code>signTestToken</code> linh hoạt (cho override <code>header</code>, <code>claims</code>, <code>exp</code>, <code>nbf</code>, <code>signKey</code>) là "vũ khí" chính để viết negative test: bạn tạo được token hết hạn, sai <code>aud</code>, ký bằng khóa lạ... chỉ bằng một dòng. Đầu tư cho helper này trước, các test sau sẽ rất ngắn.
</Callout>

---

## 5. Unit test: từng cổng verify

```javascript
import { describe, it, expect, beforeAll } from 'vitest';
import { jwtVerify } from 'jose';
import { makeKeys, signTestToken, ISS, AUD } from './helpers/jwt.js';

let K;
const verify = (token) =>
  jwtVerify(token, K.publicKey, { algorithms: ['RS256'], issuer: ISS, audience: AUD });

beforeAll(async () => { K = await makeKeys(); });

describe('verifyToken — happy path', () => {
  it('chấp nhận token hợp lệ', async () => {
    const token = await signTestToken(K.privateKey);
    const { payload } = await verify(token);
    expect(payload.sub).toBe('u1');
    expect(payload.aud).toBe(AUD);
  });
});
```

---

## 6. Negative cases BẮT BUỘC (kèm code)

Đây là phần cốt lõi. Mỗi case dưới đây phải có một test chứng minh hệ thống **từ chối**.

```diagram
□ alg:none           — header {"alg":"none"}, không chữ ký           → PHẢI 401
□ Algorithm confusion — token RS256 ký lại bằng HS256 với public key  → PHẢI 401
□ Sửa chữ ký/payload  — đổi 1 ký tự, giữ phần còn lại                → PHẢI 401
□ Hết hạn             — exp ở quá khứ                                → PHẢI 401
□ Chưa hiệu lực       — nbf ở tương lai                              → PHẢI 401
□ Sai issuer          — iss = "https://evil.test"                    → PHẢI 401
□ Sai audience        — aud = "service-khác"                         → PHẢI 401
□ Thiếu exp           — token không có exp                           → PHẢI 401 (không coi vĩnh viễn)
□ Token rỗng/méo      — "", "abc", thiếu/thừa phần                   → PHẢI 401 (không crash)
□ Token đã revoke     — jti trong denylist / trước tokensValidAfter  → PHẢI 401
□ Replay refresh      — dùng lại refresh đã rotate                   → PHẢI 401 + thu hồi family
□ kid lạ              — kid không có trong JWKS                       → PHẢI 401 (không crash)
```

### 6.1 alg:none

`alg:none` là token không có chữ ký — kẻ tấn công khai báo "tôi không cần ký". Verifier phải từ chối nhờ allowlist:

```javascript
it('từ chối alg:none', async () => {
  const header = b64url({ alg: 'none', typ: 'JWT' });
  const payload = b64url({ sub: 'u1', role: 'admin', aud: AUD, iss: ISS });
  const fakeNone = `${header}.${payload}.`;   // phần signature rỗng
  await expect(verify(fakeNone)).rejects.toThrow();  // allowlist ['RS256'] chặn
});
```

### 6.2 Algorithm confusion RS256 → HS256

Kẻ tấn công lấy **public key** (vốn công khai) dùng làm "secret" HMAC để ký token `HS256` giả. Nếu verifier đọc `alg` từ token (thay vì cố định allowlist) thì bị lừa:

```javascript
import { SignJWT } from 'jose';
import { exportSPKI } from 'jose';

it('từ chối token RS256 bị ký lại bằng HS256 với public key', async () => {
  // attacker dùng PEM của public key làm secret HMAC
  const pubPem = await exportSPKI(K.publicKey);
  const forged = await new SignJWT({ sub: 'attacker', role: 'admin', aud: AUD, iss: ISS })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('15m')
    .sign(new TextEncoder().encode(pubPem));   // ký HS256 bằng public key

  // verifier allowlist ['RS256'] → từ chối ngay vì alg không khớp
  await expect(verify(forged)).rejects.toThrow(/alg/i);
});
```

> [!WARNING]
> Test `alg:none` và **algorithm confusion** là bắt buộc với bất kỳ hệ JWT nào — đây là hai lỗ hổng kinh điển nhất. Nếu thư viện/cấu hình của bạn *pass* (chấp nhận) một trong hai token trên, hệ thống đang có lỗ hổng nghiêm trọng cho phép giả token tùy ý. Cơ chế tấn công chi tiết: [Algorithm Confusion](/security/algorithm-confusion/).

### 6.3 Sửa chữ ký / payload

```javascript
it('từ chối khi payload bị sửa sau khi ký', async () => {
  const token = await signTestToken(K.privateKey, { claims: { role: 'user' } });
  const [h, , s] = token.split('.');
  const tamperedPayload = b64url({ sub: 'u1', role: 'admin', aud: AUD, iss: ISS });
  const tampered = `${h}.${tamperedPayload}.${s}`;   // payload mới + chữ ký cũ
  await expect(verify(tampered)).rejects.toThrow();   // chữ ký không còn khớp
});

it('từ chối khi chữ ký bị đổi', async () => {
  const token = await signTestToken(K.privateKey);
  await expect(verify(token.slice(0, -3) + 'AAA')).rejects.toThrow();
});
```

### 6.4 Hết hạn & chưa hiệu lực

```javascript
it('từ chối token hết hạn', async () => {
  const token = await signTestToken(K.privateKey, { exp: nowSec() - 60 });
  await expect(verify(token)).rejects.toMatchObject({ code: 'ERR_JWT_EXPIRED' });
});

it('từ chối token chưa tới nbf', async () => {
  const token = await signTestToken(K.privateKey, { nbf: nowSec() + 300 });
  await expect(verify(token)).rejects.toThrow();
});
```

### 6.5 Sai aud / iss / thiếu exp

```javascript
it('từ chối sai audience', async () => {
  const token = await signTestToken(K.privateKey, { claims: { aud: 'api.billing' } });
  await expect(verify(token)).rejects.toThrow(/audience/i);
});

it('từ chối sai issuer', async () => {
  const token = await signTestToken(K.privateKey, { claims: { iss: 'https://evil.test' } });
  await expect(verify(token)).rejects.toThrow(/issuer/i);
});

it('từ chối token rỗng/méo mà KHÔNG crash', async () => {
  for (const bad of ['', 'abc', 'a.b', 'a.b.c.d']) {
    await expect(verify(bad)).rejects.toThrow();
  }
});
```

> [!TIP]
> Với "thiếu `exp`", cấu hình verifier bắt buộc claim này (`requiredClaims: ['exp']` trong `jose`, hoặc kiểm thủ công) rồi test rằng token không có `exp` bị từ chối. Một token không `exp` mà được coi là "không bao giờ hết hạn" là lỗ hổng — revoke qua TTL trở nên vô dụng.

---

## 7. Giả lập thời gian & khóa

### 7.1 Giả lập thời gian (test `exp`/`nbf`/clock skew)

Đừng `sleep()` chờ token hết hạn — chậm và flaky. Giả lập đồng hồ:

```javascript
import { vi } from 'vitest';

it('access hết hạn sau TTL', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
  const token = await signTestToken(K.privateKey, { exp: nowSec() + 900 });

  vi.advanceTimersByTime(16 * 60 * 1000);   // nhảy 16 phút
  await expect(verify(token)).rejects.toMatchObject({ code: 'ERR_JWT_EXPIRED' });
  vi.useRealTimers();
});

it('chấp nhận token vừa hết hạn 10s nếu có clockTolerance 30s', async () => {
  const token = await signTestToken(K.privateKey, { exp: nowSec() - 10 });
  const { payload } = await jwtVerify(token, K.publicKey, {
    algorithms: ['RS256'], issuer: ISS, audience: AUD, clockTolerance: '30s',
  });
  expect(payload.sub).toBe('u1');
});
```

<Callout type="info">
Nếu thư viện verify đọc giờ qua nguồn riêng (không phải <code>Date.now()</code>), truyền tham số <code>currentDate</code>/<code>clockTimestamp</code> thay vì fake timer toàn cục. Luôn có một test cho <b>clock skew</b> + <code>clockTolerance</code> — đây là nguyên nhân số một của 401 "khó hiểu" ở production (xem <a href="/operations/debugging-jwt/">Debugging JWT §7.1</a>).
</Callout>

### 7.2 Khóa test — đừng dùng khóa production

```diagram
□ Mỗi suite tự sinh keypair (generateKeyPair) — KHÔNG dùng khóa prod/staging
□ Không commit private key thật vào fixtures (gitleaks bắt được)
□ Test "kid lạ": token với kid không có trong JWKS → 401, KHÔNG crash
□ Test cả HS256 (nếu hỗ trợ) lẫn RS256 nếu hệ thống dùng cả hai trong migration
```

---

## 8. Mock JWKS endpoint

Khi verifier tải public key qua JWKS (RS256/ES256), mock endpoint để test offline và test cả case `kid` lạ:

```javascript
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';

const server = setupServer(
  http.get('https://auth.test/.well-known/jwks.json', () =>
    HttpResponse.json(K.jwks)),    // chỉ chứa kid "test-kid"
);
beforeAll(() => server.listen());
afterAll(() => server.close());

it('từ chối token có kid lạ (không có trong JWKS) mà không crash', async () => {
  const token = await signTestToken(K.privateKey, { header: { kid: 'unknown-kid' } });
  const JWKS = createRemoteJWKSet(new URL('https://auth.test/.well-known/jwks.json'));
  await expect(
    jwtVerify(token, JWKS, { algorithms: ['RS256'], issuer: ISS, audience: AUD }),
  ).rejects.toThrow();   // không tìm thấy kid → 401, không 500
});
```

> [!TIP]
> Mock JWKS còn cho phép test **xoay khóa**: ban đầu JWKS trả `kid=k1`, đổi handler sang `kid=k2`, kiểm verifier refetch và chấp nhận token mới trong khi vẫn nhận token cũ trong overlap window. Liên quan: [Key Rotation](/cryptography/key-rotation/), [Migration §4](/operations/migration-strategy/).

---

## 9. Integration test middleware

Test middleware verify gắn vào route thật bằng `supertest` — kiểm đúng status code và không rò thông tin:

```javascript
import request from 'supertest';
import { app } from '../src/app.js';   // express app có middleware requireAuth

describe('GET /orders (route bảo vệ)', () => {
  it('200 với access hợp lệ', async () => {
    const token = await signTestToken(K.privateKey);
    await request(app).get('/orders').set('Authorization', `Bearer ${token}`).expect(200);
  });

  it('401 khi thiếu header', async () => {
    await request(app).get('/orders').expect(401);
  });

  it('401 với token hết hạn', async () => {
    const token = await signTestToken(K.privateKey, { exp: nowSec() - 1 });
    await request(app).get('/orders').set('Authorization', `Bearer ${token}`).expect(401);
  });

  it('403 (không phải 401) khi thiếu scope', async () => {
    const token = await signTestToken(K.privateKey, { claims: { scope: 'read:profile' } });
    await request(app).get('/orders').set('Authorization', `Bearer ${token}`).expect(403);
  });

  it('không rò chi tiết lỗi nội bộ trong body 401', async () => {
    const res = await request(app).get('/orders').set('Authorization', 'Bearer abc').expect(401);
    expect(JSON.stringify(res.body)).not.toMatch(/stack|secret|key/i);
  });
});
```

---

## 10. Test refresh & rotation/reuse

Refresh token rotation + reuse detection là phần dễ sai nhất. Test ba kịch bản:

```diagram
KỊCH BẢN 1 — rotation bình thường:
  refresh(R1) → access mới + R2 ; R1 bị vô hiệu
  ✓ assert: dùng lại R1 → 401

KỊCH BẢN 2 — reuse detection (nghi trộm):
  refresh(R1) → R2 ; rồi lại refresh(R1)  ← R1 đã dùng
  ✓ assert: 401 + TOÀN BỘ family token của session bị thu hồi + ghi cảnh báo

KỊCH BẢN 3 — refresh sau logout:
  logout() → refresh(R_current) → 401
```

```javascript
it('phát hiện reuse refresh token đã rotate và thu hồi cả family', async () => {
  const { refresh: r1 } = await login();
  const { refresh: r2 } = await rotate(r1);     // r1 -> r2, r1 vô hiệu

  // kẻ trộm dùng lại r1 → phải bị chặn + thu hồi family
  await expect(rotate(r1)).rejects.toThrow(/reuse|revoked/i);
  await expect(rotate(r2)).rejects.toThrow();   // r2 cũng bị thu hồi theo
});

it('refresh sau logout bị từ chối', async () => {
  const { refresh } = await login();
  await logout(refresh);
  await expect(rotate(refresh)).rejects.toThrow();
});
```

> [!NOTE]
> Điểm phải test: khi phát hiện reuse, hệ thống thu hồi **cả family** (mọi token sinh ra từ phiên đó), không chỉ token bị dùng lại — đây là cách giảm thiệt hại khi refresh bị trộm. Cơ chế đầy đủ: [Access vs Refresh Token](/lifecycle/access-token-vs-refresh-token/), [Revocation & Logout](/lifecycle/revocation-and-logout/).

---

## 11. E2E luồng đăng nhập

E2E ít nhưng cần cho luồng quan trọng nhất. Với SPA, dùng Playwright:

```javascript
test('luồng đăng nhập đầy đủ', async ({ page }) => {
  await page.goto('/login');
  await page.fill('#email', 'user@example.com');
  await page.fill('#password', 'correct-horse');
  await page.click('button[type=submit]');
  await expect(page).toHaveURL('/dashboard');

  // BẢO MẬT: refresh token phải là cookie HttpOnly (JS không đọc được)
  const cookies = await page.context().cookies();
  const refresh = cookies.find(c => c.name === 'refresh_token');
  expect(refresh?.httpOnly).toBe(true);
  expect(refresh?.secure).toBe(true);

  // access token KHÔNG nằm ở localStorage (XSS đọc được)
  const ls = await page.evaluate(() => JSON.stringify(localStorage));
  expect(ls).not.toMatch(/eyJ/);   // không có chuỗi JWT trong localStorage

  await page.click('#load-orders');
  await expect(page.locator('.order-row')).toHaveCount(3);

  await page.click('#logout');
  await expect(page).toHaveURL('/login');
});
```

> [!TIP]
> Hai assert bảo mật giá trị nhất trong E2E: (1) refresh token là cookie `HttpOnly`+`Secure`; (2) **không** có chuỗi JWT trong `localStorage`. Chúng chứng minh storage đúng chuẩn ([Secure Storage](/security/secure-storage/)). Đừng để E2E phình to — chỉ phủ login/refresh/logout, đẩy mọi negative case xuống unit/integration.

---

## 12. CI gate cho bảo mật token

Biến negative test thành **rào chắn** — PR không pass thì không merge:

<Steps>
<Step>
### Tách & bắt buộc suite bảo mật

Gắn tag `@security` cho các negative test, chạy bắt buộc trong CI, cấm skip. Coi đây là blocking check.
</Step>
<Step>
### Bắt buộc phủ đủ cổng verify

Mỗi cổng trong [ma trận §3](#3-ma-trận-phủ-test-theo-cổng-verify) phải có ≥1 negative test. Review PR soát theo bảng.
</Step>
<Step>
### Chặn anti-pattern bằng grep/lint

Bắt `jwt.decode(`/`jwtDecode(` dùng để authz, và `verify(` thiếu `algorithms`. Phát hiện → fail build.
</Step>
<Step>
### SAST & quét secret

`npm audit` + `gitleaks` để bắt khóa/secret lỡ commit vào fixtures hoặc code.
</Step>
</Steps>

```yaml
# .github/workflows/auth-tests.yml (rút gọn)
jobs:
  auth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - name: Unit + integration auth tests
        run: npm test
      - name: Security negative cases (BẮT BUỘC, không skip)
        run: npm test -- --grep @security
      - name: Chặn decode dùng để authz
        run: |
          ! grep -rnE "(jwt\.decode|jwtDecode)\(" src/ --include='*.ts' \
            | grep -iv "test" || (echo "decode KHÔNG được dùng để phân quyền" && exit 1)
      - name: Chặn verify thiếu allowlist algorithms
        run: |
          ! grep -rnE "jwtVerify\(|jwt\.verify\(" src/ --include='*.ts' -A3 \
            | grep -L "algorithms" || true
      - name: Quét secret
        run: npx gitleaks detect --no-banner
```

---

## 13. Checklist test auth

```diagram
POSITIVE (happy path):
□ Login đúng credential → cấp token đủ claim (sub/exp/aud/iss/jti)
□ Access hợp lệ → API 200 ; refresh hợp lệ → access mới ; đủ scope → cho phép

NEGATIVE (bắt buộc — mỗi dòng ≥1 test):
□ alg:none → 401
□ algorithm confusion RS256→HS256 → 401
□ chữ ký bị sửa / payload bị sửa → 401
□ token hết hạn (exp quá khứ) → 401 ; chưa hiệu lực (nbf) → 401
□ sai iss → 401 ; sai aud → 401 ; thiếu exp → 401
□ token rỗng/méo/thiếu phần → 401 (KHÔNG crash 500)
□ token đã revoke → 401 ; replay refresh đã rotate → 401 + thu hồi family
□ kid lạ → 401 (không crash)
□ token hợp lệ nhưng thiếu quyền → 403 (KHÔNG 401)
□ body lỗi 401 không rò stack/secret/key

KỸ THUẬT:
□ giả lập thời gian (fake timer) thay vì sleep
□ test clock skew với clockTolerance
□ dùng keypair TEST, không phải khóa prod
□ mock JWKS; test kid lạ + xoay khóa
□ E2E: refresh là cookie HttpOnly+Secure; không có JWT trong localStorage

CI:
□ suite @security chạy bắt buộc, không skip
□ chặn decode-dùng-để-authz và verify thiếu allowlist
□ gitleaks + npm audit
```

<Callout type="success" title="Một câu để nhớ">
Hệ auth tốt được chứng minh bằng <b>những gì nó từ chối</b>, không phải những gì nó cho qua. Nếu suite test không có dòng nào assert "token sai → 401", bạn chưa thực sự test auth — bạn chỉ mới test rằng người dùng hợp lệ vào được.
</Callout>

---

## Tài liệu tham khảo

- [Luồng xác thực JWT — Deep Dive](/internals/token-validation-flow/) — các cổng cần phủ test
- [Algorithm Confusion](/security/algorithm-confusion/) — vì sao test alg:none/confusion
- [Access vs Refresh Token](/lifecycle/access-token-vs-refresh-token/) — luồng refresh
- [Revocation & Logout](/lifecycle/revocation-and-logout/) — test reuse detection
- [Secure Storage](/security/secure-storage/) — assert HttpOnly trong E2E
- [Key Rotation](/cryptography/key-rotation/) — test xoay khóa qua mock JWKS
- [Debugging JWT](/operations/debugging-jwt/) — khi test fail, debug thế nào
- [Production Checklist](/operations/production-checklist/) — negative test là một mục P0
