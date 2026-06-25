---
title: "HMAC vs RSA vs ECDSA — Deep Dive"
description: "Mổ xẻ ba họ thuật toán ký JWT — HMAC (đối xứng), RSA và ECDSA/EdDSA (bất đối xứng): mô hình tin cậy, kích thước key & chữ ký, hiệu năng ký/verify, độ an toàn tương đương, và cây quyết định chọn HS256/RS256/ES256/PS256/EdDSA cho từng kiến trúc. Kèm benchmark, code Node.js và anti-patterns."
---

# HMAC vs RSA vs ECDSA — Deep Dive

## Mục lục

- [Khi nào HS256 đủ, khi nào nó thành nợ kỹ thuật](#1-khi-nào-hs256-đủ-khi-nào-nó-thành-nợ-kỹ-thuật)
- [Hai thế giới: bí mật chung vs cặp khóa](#2-hai-thế-giới-bí-mật-chung-vs-cặp-khóa)
- [HMAC — một bí mật, cả hai đầu cùng giữ](#3-hmac--một-bí-mật-cả-hai-đầu-cùng-giữ)
- [RSA — khóa lớn, verify nhanh, ký chậm](#4-rsa--khóa-lớn-verify-nhanh-ký-chậm)
- [ECDSA & EdDSA — đường cong elliptic, khóa nhỏ](#5-ecdsa--eddsa--đường-cong-elliptic-khóa-nhỏ)
- [Độ an toàn tương đương — vì sao 256-bit EC ≈ 3072-bit RSA](#6-độ-an-toàn-tương-đương--vì-sao-256-bit-ec--3072-bit-rsa)
- [Kích thước & hiệu năng — bảng số thực tế](#7-kích-thước--hiệu-năng--bảng-số-thực-tế)
- [Bảng so sánh tổng hợp](#8-bảng-so-sánh-tổng-hợp)
- [Cây quyết định — chọn thuật toán nào](#9-cây-quyết-định--chọn-thuật-toán-nào)
- [Code thực chiến — sinh key & ký cho từng họ](#10-code-thực-chiến--sinh-key--ký-cho-từng-họ)
- [Anti-patterns cần tránh](#11-anti-patterns-cần-tránh)
- [Tóm tắt — Cheat sheet](#12-tóm-tắt--cheat-sheet)

---

## 1. Khi nào HS256 đủ, khi nào nó thành nợ kỹ thuật

Một monolith duy nhất phát hành và verify token bằng `HS256` — chạy hoàn hảo nhiều năm. Một biến môi trường `JWT_SECRET`, ký bằng nó, verify bằng nó. Đơn giản, nhanh, không có gì để chê.

Rồi đội tách monolith thành 8 microservice. Giờ cả 8 service đều cần *verify* token. Theo quán tính, secret `JWT_SECRET` được copy vào cả 8 service để chúng tự verify.

```diagram
       ┌─────────── JWT_SECRET (cùng một chuỗi) ───────────┐
       ▼            ▼            ▼            ▼     ... (×8)
   auth-svc     orders-svc   billing-svc   email-svc
   (PHÁT+verify) (verify)     (verify)      (verify)
```

Vấn đề lộ ra ngay: với HMAC, **khóa verify == khóa ký**. 8 service giữ secret nghĩa là 8 nơi có thể **giả** token. Service `email-svc` bị xâm nhập → kẻ tấn công lấy secret → tự ký token admin cho *mọi* service. Bề mặt tấn công nhân lên 8 lần, và không thể biết service nào làm lộ.

> [!IMPORTANT]
> Đây chính là ranh giới quyết định giữa HMAC và RSA/ECDSA: **HMAC dùng một bí mật chung cho cả ký lẫn verify; RSA/ECDSA tách private key (chỉ để ký) khỏi public key (ai verify cũng được mà không thể ký).** Chọn sai họ thuật toán không làm token "kém an toàn về toán học" — nó làm **mô hình phân phối khóa** sai, và đó mới là thứ sập trong thực tế.

Doc này mổ xẻ ba họ thuật toán để bạn chọn đúng theo *kiến trúc*, không theo quán tính.

---

## 2. Hai thế giới: bí mật chung vs cặp khóa

Mọi thuật toán ký JWT rơi vào đúng một trong hai thế giới:

```diagram
ĐỐI XỨNG (symmetric) — HMAC: HS256 / HS384 / HS512
   ┌──────────────┐                       ┌──────────────┐
   │   Người ký   │── cùng 1 secret K ───▶│  Người verify│
   └──────────────┘                       └──────────────┘
   Ký:    tag = HMAC(K, data)
   Verify: HMAC(K, data) == tag   ← cần CHÍNH secret K → verify được thì cũng ký được

BẤT ĐỐI XỨNG (asymmetric) — RSA: RS*/PS*  |  EC: ES*  |  EdDSA
   ┌──────────────┐   private key d        public key e   ┌──────────────┐
   │   Người ký   │── ký bằng d ──▶ token ──▶ verify bằng e│  Người verify│
   └──────────────┘   (giữ tuyệt mật)      (công khai)     └──────────────┘
   Ký:    sig = Sign(privKey, data)        ← chỉ ai có privKey mới ký được
   Verify: Verify(pubKey, data, sig)       ← public key KHÔNG ký được
```

Khác biệt cốt lõi chỉ nằm ở một câu: **người verify có ký lại được không?**

| | Đối xứng (HMAC) | Bất đối xứng (RSA/EC/EdDSA) |
|---|---|---|
| Khóa ký | secret K | private key (riêng) |
| Khóa verify | **cũng là** secret K | public key (công khai) |
| Verifier có thể giả token? | **CÓ** (có secret) | **KHÔNG** (chỉ có public key) |
| Hợp với | một bên vừa ký vừa verify | nhiều bên verify, một bên ký |

Toàn bộ phần còn lại của doc là chi tiết bên trong mỗi họ — nhưng nếu chỉ nhớ một điều, hãy nhớ cái bảng này.

---

## 3. HMAC — một bí mật, cả hai đầu cùng giữ

`HS256` = HMAC dùng SHA-256. Cơ chế HMAC (cấu trúc ipad/opad, hai vòng hash) đã mổ xẻ chi tiết trong [Chữ ký số JWT — Deep Dive](/internals/signature-deep-dive/). Ở đây ta nhìn nó dưới góc **vận hành & tin cậy**.

```diagram
tag = HMAC-SHA256(K, SigningInput)
    = SHA256( (K⊕opad) ‖ SHA256( (K⊕ipad) ‖ SigningInput ) )
```

### 3.1. Ưu điểm

- **Nhanh nhất** trong cả ba họ — chỉ là hai vòng băm, không có số học modulo lớn. Cả ký lẫn verify đều ở mức micro-giây.
- **Khóa gọn**: secret ngẫu nhiên ≥ 256 bit (32 byte) là đủ mạnh cho HS256.
- **Đơn giản**: không cần hạ tầng phân phối public key (JWKS), không quản lý cặp khóa.

### 3.2. Nhược điểm — đều xoay quanh "bí mật chung"

```diagram
1 bên ký + 1 bên verify (cùng tổ chức)  →  HMAC hoàn hảo
N bên verify khác nhau                  →  HMAC nguy hiểm:
        mỗi verifier phải giữ secret = mỗi verifier có thể GIẢ token
```

- **Không tách được vai trò**: ai verify được thì cũng ký được.
- **Phân phối secret khó an toàn**: càng nhiều nơi giữ, càng dễ lộ; lộ một nơi là lộ tất cả.
- **Không hợp bên thứ ba**: không thể đưa secret cho đối tác để họ verify token của bạn (đưa = trao quyền giả token).

> [!TIP]
> HS256 là lựa chọn **đúng** khi cùng một dịch vụ (hoặc cùng một ranh giới tin cậy) vừa phát vừa verify token — ví dụ một monolith, hoặc auth service tự verify session của chính nó. Yêu cầu duy nhất: secret phải **ngẫu nhiên mạnh** (≥ 32 byte từ CSPRNG), không phải một câu mật khẩu đoán được.

---

## 4. RSA — khóa lớn, verify nhanh, ký chậm

`RS256` = RSASSA-PKCS1-v1_5 + SHA-256. `PS256` = RSASSA-PSS + SHA-256 (padding ngẫu nhiên, hiện đại hơn). Cả hai dùng chung cặp khóa RSA.

### 4.1. Cặp khóa đến từ đâu

```diagram
Sinh khóa RSA:
   chọn 2 số nguyên tố lớn p, q   →  n = p·q   (modulus, vd 2048-bit)
   public key  = (n, e)   với e thường = 65537
   private key = (n, d)   với d = e⁻¹ mod φ(n)

An toàn dựa trên: biết n, RẤT khó phân tích lại p, q  (bài toán factoring)
```

### 4.2. Đặc tính bất đối xứng "lệch"

RSA có một tính chất vận hành quan trọng: **verify rẻ, ký đắt** — vì số mũ công khai `e` nhỏ (65537) còn số mũ riêng `d` rất lớn.

```diagram
Verify (dùng e nhỏ):   sigᵉ mod n   →  nhanh
Ký     (dùng d lớn):   hashᵈ mod n  →  chậm hơn nhiều (10–30×)
```

```diagram
Hệ quả thực tế:
   - Auth server KÝ (chậm) nhưng làm 1 lần/đăng nhập      → chấp nhận được
   - Resource server VERIFY (nhanh) làm mỗi request       → tối ưu đúng chiều
```

### 4.3. Giá phải trả: kích thước

- Khóa RSA-2048 → public key ~270 byte, private key ~1190 byte.
- **Chữ ký RSA luôn dài bằng modulus**: RSA-2048 → chữ ký 256 byte → sau base64url ~342 ký tự. Đây là phần làm token RS256 **phình to** so với ES256/EdDSA.

> [!NOTE]
> RS256 phổ biến nhất trong thực tế (OIDC, hầu hết identity provider) vì tương thích rộng. Nhưng nếu bắt đầu mới và stack hỗ trợ, `PS256` (RSA-PSS) được khuyến nghị hơn nhờ padding ngẫu nhiên — xem [Chữ ký số JWT — Deep Dive §7](/internals/signature-deep-dive/).

---

## 5. ECDSA & EdDSA — đường cong elliptic, khóa nhỏ

`ES256` = ECDSA trên đường cong P-256 + SHA-256. `EdDSA` = Ed25519 (đường cong Curve25519). Cả hai dựa trên bài toán **logarit rời rạc trên đường cong elliptic (ECDLP)** — khó hơn factoring trên mỗi bit, nên đạt cùng độ an toàn với khóa **nhỏ hơn nhiều**.

### 5.1. Vì sao khóa nhỏ mà vẫn mạnh

```diagram
RSA: an toàn dựa trên factoring → cần modulus LỚN (2048–3072 bit)
EC : an toàn dựa trên ECDLP     → 256-bit đã tương đương RSA-3072

   → private key EC chỉ là 1 số ~32 byte
   → public key EC là 1 điểm (x, y) trên đường cong ~64 byte
```

### 5.2. Chữ ký (r, s) và một bẫy chết người

ECDSA tạo chữ ký gồm hai số `(r, s)`. JWS nối chúng thành `r ‖ s` cố định độ dài (ES256 = 32+32 = 64 byte) — **không** phải DER. Chi tiết và bẫy DER ở [Chữ ký số JWT — Deep Dive §6](/internals/signature-deep-dive/).

> [!WARNING]
> ECDSA cần một số ngẫu nhiên `k` **bí mật và duy nhất** cho mỗi lần ký. Lặp lại `k` (hoặc `k` đoán được) → lộ private key (vụ Sony PS3 2010 là ví dụ kinh điển). Đây là lý do **EdDSA (Ed25519)** ra đời: nó sinh `k` **tất định** từ key + message (RFC 8032), loại bỏ hoàn toàn rủi ro RNG. Nếu được chọn mới, EdDSA an toàn-mặc-định hơn ECDSA.

### 5.3. Ưu điểm tổng hợp

- Khóa & chữ ký **nhỏ** → token gọn, băng thông thấp.
- Ký **nhanh** hơn RSA nhiều; verify cũng nhanh (dù RSA verify vẫn nhỉnh ở một số thư viện).
- EdDSA: tất định, nhanh, kháng side-channel tốt — lựa chọn hiện đại nếu stack hỗ trợ.

---

## 6. Độ an toàn tương đương — vì sao 256-bit EC ≈ 3072-bit RSA

"Số bit" của RSA và EC **không** so sánh trực tiếp được, vì chúng dựa trên hai bài toán khác nhau. Bảng tương đương (theo NIST SP 800-57):

| Mức an toàn đối xứng | RSA (modulus) | EC (kích thước khóa) | Ví dụ JWT |
|----------------------|---------------|----------------------|-----------|
| 112-bit | 2048 | 224 | RS256 (RSA-2048) |
| 128-bit | 3072 | 256 | ES256 (P-256), EdDSA |
| 192-bit | 7680 | 384 | ES384 (P-384) |
| 256-bit | 15360 | 521 | ES512 (P-521) |

```diagram
Đọc bảng: muốn mạnh ngang AES-128 (128-bit),
   RSA cần modulus 3072-bit  ──vs──  EC chỉ cần 256-bit
   → cùng độ mạnh, EC nhỏ hơn ~12 lần ở kích thước khóa
```

> [!NOTE]
> Đây là lý do gốc khiến ES256/EdDSA "đáng giá": đạt độ an toàn cao với khóa và chữ ký nhỏ hơn nhiều → token nhẹ, ký nhanh. Cái giá là khả năng tương thích (một số hệ thống cũ chỉ hỗ trợ RS256).

---

## 7. Kích thước & hiệu năng — bảng số thực tế

Con số dưới đây mang tính **bậc độ lớn** (tùy CPU/thư viện), đủ để ra quyết định:

| Thuật toán | Kích thước chữ ký (raw) | Chữ ký sau base64url | Ký (tương đối) | Verify (tương đối) |
|------------|-------------------------|----------------------|----------------|--------------------|
| HS256 | 32 byte | ~43 ký tự | ⚡⚡⚡ rất nhanh | ⚡⚡⚡ rất nhanh |
| ES256 | 64 byte | ~86 ký tự | ⚡⚡ nhanh | ⚡⚡ nhanh |
| EdDSA (Ed25519) | 64 byte | ~86 ký tự | ⚡⚡⚡ rất nhanh | ⚡⚡ nhanh |
| RS256 (2048) | 256 byte | ~342 ký tự | 🐢 chậm | ⚡⚡ nhanh |
| RS256 (4096) | 512 byte | ~683 ký tự | 🐢🐢 rất chậm | ⚡ trung bình |

```diagram
Độ dài token (phần signature) ảnh hưởng:
   - Header HTTP (Authorization: Bearer ...) — giới hạn ~8KB ở nhiều proxy
   - Cookie (giới hạn ~4KB)
   - Băng thông mỗi request (token gửi kèm mọi lần gọi API)

   RS256-4096 có thể khiến token + claims chạm trần header → ưu tiên ES256/EdDSA khi cần gọn
```

> [!IMPORTANT]
> Điểm hay bị quên: với bất đối xứng, **verify chạy nhiều hơn ký rất nhiều** (mỗi request đều verify, mỗi đăng nhập mới ký một lần). RSA verify nhanh là một lợi thế thực tế. Nhưng ECDSA/EdDSA cân bằng tốt cả hai chiều và cho token nhỏ hơn nhiều.

---

## 8. Bảng so sánh tổng hợp

| Tiêu chí | HMAC (HS*) | RSA (RS*/PS*) | ECDSA (ES*) | EdDSA |
|----------|-----------|---------------|-------------|-------|
| Loại | Đối xứng | Bất đối xứng | Bất đối xứng | Bất đối xứng |
| Khóa ký = khóa verify? | **Có** | Không | Không | Không |
| Verifier giả được token? | **Có** | Không | Không | Không |
| Kích thước khóa (128-bit sec) | 32 byte | 3072-bit | 256-bit | 256-bit |
| Kích thước chữ ký | nhỏ (32B) | lớn (256B+) | vừa (64B) | vừa (64B) |
| Tốc độ ký | rất nhanh | chậm | nhanh | rất nhanh |
| Tốc độ verify | rất nhanh | nhanh | nhanh | nhanh |
| Rủi ro RNG khi ký | không | không | **có** (k phải unique) | không (tất định) |
| Hợp nhiều verifier / bên thứ ba | ❌ | ✅ | ✅ | ✅ |
| Tương thích rộng | tốt | **tốt nhất** | tốt | đang tăng |
| Cần JWKS để phân phối key | không | nên | nên | nên |

---

## 9. Cây quyết định — chọn thuật toán nào

```diagram
Bạn có nhiều bên VERIFY token khác nhau không?
│
├─ KHÔNG (1 service vừa ký vừa verify, cùng ranh giới tin cậy)
│     └─▶ HS256   (đơn giản, nhanh; secret ≥ 32 byte ngẫu nhiên)
│
└─ CÓ (microservices, bên thứ ba, SPA/mobile verify, OIDC...)
      │  → BẮT BUỘC bất đối xứng (đừng phát tán secret HMAC)
      │
      ├─ Cần tương thích tối đa / nhiều hệ thống cũ (OIDC IdP)?
      │     └─▶ RS256   (phổ biến nhất; PS256 nếu được chọn padding hiện đại)
      │
      ├─ Cần token gọn / hiệu năng cân bằng, stack hỗ trợ EC?
      │     └─▶ ES256
      │
      └─ Bắt đầu mới, muốn an toàn-mặc-định (không lo RNG)?
            └─▶ EdDSA (Ed25519)
```

> [!IMPORTANT]
> Dù chọn gì, verifier **luôn** phải ghim danh sách thuật toán cho phép (`algorithms: ['RS256']`). Trộn HMAC và bất đối xứng trong cùng một verifier mà không ghim alg → mở cửa đòn **RS256→HS256 confusion**. Xem [Algorithm Confusion — Deep Dive](/security/algorithm-confusion-deep-dive/).

---

## 10. Code thực chiến — sinh key & ký cho từng họ

### 10.1. Sinh khóa (Node.js)

```bash
# HMAC: chỉ cần secret ngẫu nhiên mạnh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# RSA-2048
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-private.pem
openssl pkey -in rsa-private.pem -pubout -out rsa-public.pem

# EC P-256 (ES256)
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem

# Ed25519 (EdDSA)
openssl genpkey -algorithm ed25519 -out ed-private.pem
openssl pkey -in ed-private.pem -pubout -out ed-public.pem
```

### 10.2. Ký & verify với `jose`

```javascript
import { SignJWT, jwtVerify, generateKeyPair } from 'jose';

// Ví dụ ES256 (cặp khóa bất đối xứng)
const { privateKey, publicKey } = await generateKeyPair('ES256');

const token = await new SignJWT({ role: 'user' })
  .setProtectedHeader({ alg: 'ES256' })
  .setIssuedAt()
  .setExpirationTime('15m')
  .sign(privateKey);                 // ký bằng private key

const { payload } = await jwtVerify(token, publicKey, {
  algorithms: ['ES256'],             // ghim alg — bắt buộc
});
```

### 10.3. HS256 — đối xứng

```javascript
import { SignJWT, jwtVerify } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET); // ≥ 32 byte

const token = await new SignJWT({ role: 'user' })
  .setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('15m')
  .sign(secret);

const { payload } = await jwtVerify(token, secret, { algorithms: ['HS256'] });
// LƯU Ý: 'secret' này dùng cho cả ký và verify → đừng phát tán ra nhiều service
```

---

## 11. Anti-patterns cần tránh

| Anti-pattern | Hậu quả | Làm đúng |
|--------------|---------|----------|
| Dùng HS256 rồi copy secret ra N microservice | N nơi giả được token; lộ 1 = lộ hết | Chuyển sang RS256/ES256; chỉ auth server giữ private key |
| HS256 với secret là câu mật khẩu ngắn | Brute-force/dictionary ra secret | Secret ≥ 32 byte từ CSPRNG |
| Đưa HMAC secret cho bên thứ ba để họ verify | Trao luôn quyền giả token | Đưa public key (RS/ES), giữ private key |
| RSA-4096 cho mọi thứ "cho chắc" | Token phình, ký rất chậm | RSA-2048/3072 đủ; cần gọn thì ES256/EdDSA |
| Tự cài k cho ECDSA / tái dùng k | Lộ private key | Dùng thư viện chuẩn; ưu tiên EdDSA (k tất định) |
| Verifier không ghim `algorithms` | alg confusion (RS→HS) | Luôn truyền allowlist alg |
| Coi chữ ký là "mã hóa" | Lộ dữ liệu nhạy cảm trong payload | Ký ≠ mã hóa; cần bí mật thì dùng JWE |

---

## 12. Tóm tắt — Cheat sheet

```diagram
╭──────────────────────────────────────────────────────────────╮
│  CÂU HỎI GỐC:  có nhiều bên VERIFY khác nhau không?           │
│                                                                │
│  KHÔNG → HS256   (đối xứng, nhanh, secret ≥32B ngẫu nhiên)    │
│  CÓ    → bất đối xứng (private ký / public verify):           │
│            • RS256  — tương thích rộng nhất (OIDC)            │
│            • PS256  — RSA padding hiện đại (chọn mới)         │
│            • ES256  — token gọn, cân bằng hiệu năng           │
│            • EdDSA  — an toàn-mặc-định, không lo RNG          │
│                                                                │
│  Tương đương an toàn:  EC-256 ≈ RSA-3072 (128-bit)           │
│  Kích thước chữ ký:    HS(32) < ES/EdDSA(64) ≪ RS(256+)      │
│  RSA: verify nhanh, ký chậm.  EC/EdDSA: cân bằng + gọn.       │
│                                                                │
│  LUÔN: verifier ghim algorithms=[...]; ký ≠ mã hóa.          │
╰──────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Chọn theo mô hình tin cậy, không theo quán tính.** Một bên verify → HMAC; nhiều bên verify → bất đối xứng. Đây là quyết định kiến trúc, không phải "thuật toán nào mạnh hơn".
2. **Bất đối xứng để verifier không giả được token.** Public key phát đi thoải mái (qua JWKS); private key chỉ nằm ở nơi phát hành.
3. **EC/EdDSA cho token gọn & nhanh; RSA cho tương thích.** Và bất kể chọn gì, luôn ghim `algorithms` ở verifier.

Đọc tiếp: [JWK & JWKS — Deep Dive](/cryptography/jwk-and-jwks/) (phát public key cho nhiều verifier) và [Key Rotation — Deep Dive](/cryptography/key-rotation/) (xoay khóa không downtime).
