---
title: "HMAC vs RSA vs ECDSA — Deep Dive"
description: "Mổ xẻ ba họ thuật toán ký JWT — HMAC (đối xứng), RSA và ECDSA/EdDSA (bất đối xứng): mô hình tin cậy, ví dụ ký/verify tính TAY bằng số nhỏ, nội tại sinh khóa & vì sao bài toán nền khó, kích thước/hiệu năng (ops/sec), side-channel theo từng thuật toán, và cây quyết định chọn HS256/RS256/ES256/PS256/EdDSA. Kèm code Node.js thuần và anti-patterns."
---

# HMAC vs RSA vs ECDSA — Deep Dive

## Mục lục

- [Khi nào HS256 đủ, khi nào nó thành nợ kỹ thuật](#1-khi-nào-hs256-đủ-khi-nào-nó-thành-nợ-kỹ-thuật)
- [Hai thế giới: bí mật chung vs cặp khóa](#2-hai-thế-giới-bí-mật-chung-vs-cặp-khóa)
- [HMAC — một bí mật, cả hai đầu cùng giữ](#3-hmac--một-bí-mật-cả-hai-đầu-cùng-giữ)
- [RSA — mổ ruột bằng số nhỏ tính tay](#4-rsa--mổ-ruột-bằng-số-nhỏ-tính-tay)
- [ECDSA & EdDSA — đường cong elliptic, khóa nhỏ](#5-ecdsa--eddsa--đường-cong-elliptic-khóa-nhỏ)
- [Độ an toàn tương đương — vì sao 256-bit EC ≈ 3072-bit RSA](#6-độ-an-toàn-tương-đương--vì-sao-256-bit-ec--3072-bit-rsa)
- [Kích thước & hiệu năng — số thực tế (ops/sec, byte)](#7-kích-thước--hiệu-năng--số-thực-tế-opssec-byte)
- [Side-channel — cùng thuật toán, rò khóa theo cách khác nhau](#8-side-channel--cùng-thuật-toán-rò-khóa-theo-cách-khác-nhau)
- [Bảng so sánh tổng hợp](#9-bảng-so-sánh-tổng-hợp)
- [Cây quyết định — chọn thuật toán nào](#10-cây-quyết-định--chọn-thuật-toán-nào)
- [Code thực chiến — ký/verify "từ tay" với crypto thuần](#11-code-thực-chiến--kýverify-từ-tay-với-crypto-thuần)
- [Anti-patterns cần tránh](#12-anti-patterns-cần-tránh)
- [Tóm tắt — Cheat sheet](#13-tóm-tắt--cheat-sheet)

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

Doc này mổ xẻ ba họ thuật toán *tới tận số học bên trong* (kèm ví dụ tính tay) để bạn chọn đúng theo *kiến trúc*, không theo quán tính.

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
| Bài toán nền | hàm băm 1 chiều (PRF) | factoring (RSA) / ECDLP (EC) |
| Hợp với | một bên vừa ký vừa verify | nhiều bên verify, một bên ký |

Toàn bộ phần còn lại của doc là chi tiết bên trong mỗi họ — nhưng nếu chỉ nhớ một điều, hãy nhớ cái bảng này.

---

## 3. HMAC — một bí mật, cả hai đầu cùng giữ

`HS256` = HMAC dùng SHA-256. Cơ chế HMAC (cấu trúc ipad/opad, hai vòng hash) đã mổ xẻ chi tiết trong [Chữ ký số JWT — Deep Dive](/internals/signature-deep-dive/). Ở đây ta nhìn nó dưới góc **vì sao an toàn** và **vận hành & tin cậy**.

```diagram
tag = HMAC-SHA256(K, SigningInput)
    = SHA256( (K⊕opad) ‖ SHA256( (K⊕ipad) ‖ SigningInput ) )
```

### 3.1. Vì sao phải hai vòng băm — không phải SHA256(K ‖ data)

Cách ngây thơ "băm secret nối message" — `SHA256(K ‖ message)` — **vỡ** trước **length-extension attack**. SHA-256 thuộc họ Merkle–Damgård: trạng thái nội bộ sau khi băm xong chính là output. Biết `SHA256(K ‖ m)` và độ dài, kẻ tấn công **nối thêm** dữ liệu và tính được `SHA256(K ‖ m ‖ padding ‖ m')` mà *không cần biết K*.

```diagram
Naive:  H(K ‖ m)        →  attacker mở rộng được thành H(K ‖ m ‖ m')  → GIẢ tag
HMAC:   H((K⊕opad) ‖ H((K⊕ipad) ‖ m))
        ↑ vòng ngoài "đóng nắp" output vòng trong → length-extension vô hiệu
```

Vòng ngoài (với `K⊕opad`) khiến output vòng trong không còn là "trạng thái có thể nối tiếp" → length-extension bị chặn. Đó là toàn bộ lý do HMAC có **hai** vòng.

### 3.2. HMAC là một PRF — nền tảng của an toàn

Về mặt hình thức, HMAC được chứng minh là **PRF (pseudo-random function)**: với ai không biết `K`, output `HMAC(K, ·)` không phân biệt được với ngẫu nhiên. Hệ quả trực tiếp cho JWT:

```diagram
• Không biết K → không đoán được tag của một SigningInput mới
  (xác suất đoán đúng tag 256-bit ≈ 1/2²⁵⁶ — bất khả thi)
• Đổi 1 bit trong SigningInput → tag đổi ~50% số bit (avalanche)
• Không có "khóa công khai" để verifier dùng mà không ký được — vì chỉ có MỘT khóa
```

> [!NOTE]
> Sức mạnh HMAC đến từ **độ ngẫu nhiên của K**, không phải độ phức tạp thuật toán. HS256 với secret 6 ký tự kiểu mật khẩu → brute-force/dictionary ra trong vài giây bằng `hashcat`. HS256 với 32 byte từ CSPRNG → an toàn ngang 256-bit. Khác biệt nằm hoàn toàn ở entropy của K.

### 3.3. Ưu điểm

- **Nhanh nhất** trong cả ba họ — chỉ là hai vòng băm, không có số học modulo lớn. Cả ký lẫn verify đều ở mức micro-giây (xem §7).
- **Khóa gọn**: secret ngẫu nhiên ≥ 256 bit (32 byte) là đủ mạnh cho HS256.
- **Đơn giản**: không cần hạ tầng phân phối public key (JWKS), không quản lý cặp khóa, không lo nonce.

### 3.4. Nhược điểm — đều xoay quanh "bí mật chung"

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

## 4. RSA — mổ ruột bằng số nhỏ tính tay

`RS256` = RSASSA-PKCS1-v1_5 + SHA-256. `PS256` = RSASSA-PSS + SHA-256 (padding ngẫu nhiên, hiện đại hơn). Cả hai dùng chung cặp khóa RSA. Để *thấy* RSA hoạt động, ta dùng số nhỏ tính được bằng tay rồi suy ra trường hợp thật.

### 4.1. Sinh cặp khóa — từng bước với số nhỏ

```diagram
Bước 1  Chọn 2 số nguyên tố:        p = 61,  q = 53
Bước 2  Modulus:                     n = p·q = 3233
Bước 3  Hàm Euler:                   φ(n) = (p−1)(q−1) = 60·52 = 3120
Bước 4  Chọn số mũ công khai:        e = 17   (gcd(e, φ)=1; thật ra dùng 65537)
Bước 5  Số mũ riêng = nghịch đảo:    d = e⁻¹ mod φ = 17⁻¹ mod 3120 = 2753

   public key  = (n=3233, e=17)        ← phát công khai
   private key = (n=3233, d=2753)      ← giữ tuyệt mật (và p, q, φ cũng phải giữ kín)
```

Bước 5 dùng **thuật toán Euclid mở rộng** để tìm `d`. Trace thật:

```diagram
modinv(17, 3120):  tìm d sao cho 17·d ≡ 1 (mod 3120)
   Euclid mở rộng chạy gcd(3120, 17) = 1  → tồn tại nghịch đảo
   → d = 2753     (kiểm: 17·2753 = 46801 = 15·3120 + 1 ✓)
```

> [!NOTE]
> Trong thực tế `p, q` mỗi số ~1024 bit (cho RSA-2048), `e = 65537` (số `0x10001`, nhị phân `10000000000000001` — chỉ 2 bit '1' nên verify rất nhanh). `d` là số ~2048 bit. Toàn bộ an toàn dựa vào: **biết `n` công khai, KHÔNG tính lại được `p, q`** (bài toán factoring) → không tính được `φ` → không tính được `d`.

### 4.2. Ký bằng tay — chữ ký là phép lũy thừa modulo

Bỏ qua padding (sẽ nói ở §4.5), bản chất ký RSA là: **chữ ký = (đại diện message)^d mod n**. Lấy message rút gọn `m = 65`:

```diagram
Ký:     s = mᵈ mod n = 65²⁷⁵³ mod 3233 = 588      ← dùng d (riêng)
Verify: m' = sᵉ mod n = 588¹⁷ mod 3233 = 65       ← dùng e (công khai)
        m' == m (65) ? → ĐÚNG → chữ ký hợp lệ
```

Tính `65²⁷⁵³ mod 3233` không nhân 2753 lần — dùng **bình phương-và-nhân (square-and-multiply)**, đọc `d = 2753 = 101011000001₂` từ trái sang:

```diagram
 bit  giá trị  thao tác        r (lũy tích mod 3233)
 ───  ───────  ──────────────  ─────────────────────
  1     1      r=r²·65          65
  0     0      r=r²            992
  1     1      r=r²·65        2488
  0     0      r=r²           2182
  1     1      r=r²·65         601
  1     1      r=r²·65          19
  0     0      r=r²            361
  0     0      r=r²           1001
  0     0      r=r²           3004
  0     0      r=r²            713
  0     0      r=r²            788
  1     1      r=r²·65         588   ← chữ ký s = 588
```

Chỉ **12 bước** (= số bit của d) thay vì 2753 phép nhân. Với RSA-2048, `d` có ~2048 bit → ~2048 phép bình phương số 2048-bit — đây chính là lý do **ký RSA chậm**.

### 4.3. Vì sao kẻ tấn công không giả được

```diagram
Attacker có:  n=3233, e=17 (công khai), message muốn giả m*=66
Cần:          s* sao cho (s*)¹⁷ mod 3233 = 66
Muốn tính trực tiếp s* = 66^(1/17) mod n → cần d = 17⁻¹ mod φ
              → cần φ → cần p, q → cần PHÂN TÍCH n
n=3233 nhỏ nên phân tích dễ; nhưng n 2048-bit thì factoring là bất khả thi thực tế
```

Nếu attacker giữ nguyên `s=588` nhưng đổi message thành `m*=66`: verify tính `588¹⁷ mod 3233 = 65 ≠ 66` → **reject**. Không có đường tắt nào ngoài factoring.

### 4.4. Đặc tính bất đối xứng "lệch": verify rẻ, ký đắt

```diagram
Verify (dùng e=65537, chỉ 2 bit '1'):   sᵉ mod n   →  ~17 phép bình phương → NHANH
Ký     (dùng d ~2048-bit):              hashᵈ mod n →  ~2048 phép bình phương → CHẬM (10–30×)
```

```diagram
Hệ quả thực tế — và là điểm cộng của RSA:
   - Auth server KÝ (chậm) nhưng chỉ 1 lần / đăng nhập      → chấp nhận được
   - Resource server VERIFY (nhanh) làm MỖI request         → tối ưu đúng chiều
   (CRT — Chinese Remainder Theorem — giúp tăng tốc ký ~4× bằng cách tính mod p và mod q riêng)
```

### 4.5. Padding — phần "thật sự được ký" không phải hash trần

RSA trần (textbook) **không an toàn** (deterministic, malleable). Chuẩn quy định padding:

```diagram
RS256 = RSASSA-PKCS1-v1_5:
   EM = 0x00 ‖ 0x01 ‖ 0xFF…FF ‖ 0x00 ‖ DigestInfo(SHA256(SigningInput))
        └─ padding cố định ─┘        └─ OID thuật toán + hash ─┘
   → ký: s = EMᵈ mod n   |   verify: dựng lại EM kỳ vọng, so khớp từng byte

PS256 = RSASSA-PSS:
   thêm salt NGẪU NHIÊN + mask (MGF1) → mỗi lần ký ra chữ ký KHÁC nhau
   → có chứng minh an toàn chặt hơn; khuyến nghị cho hệ thống mới
```

> [!WARNING]
> Lỗ hổng Bleichenbacher (và biến thể) khai thác việc verifier **kiểm padding PKCS#1 lỏng lẻo** (không so khớp đầy đủ các byte `0x00 01 FF…`). Verifier RS256 phải dựng lại `EM` kỳ vọng và so **toàn bộ**, không "tìm hash ở đâu đó trong chuỗi". Đây là lý do nên dùng thư viện đã kiểm thử, không tự cài.

### 4.6. Giá phải trả: kích thước

- Khóa RSA-2048 → public key ~270 byte, private key ~1190 byte.
- **Chữ ký RSA luôn dài bằng modulus**: RSA-2048 → chữ ký 256 byte → sau base64url ~342 ký tự. Đây là phần làm token RS256 **phình to** so với ES256/EdDSA.

> [!NOTE]
> RS256 phổ biến nhất trong thực tế (OIDC, hầu hết identity provider) vì tương thích rộng. Nhưng nếu bắt đầu mới và stack hỗ trợ, `PS256` (RSA-PSS) được khuyến nghị hơn nhờ padding ngẫu nhiên — xem [Chữ ký số JWT — Deep Dive §7](/internals/signature-deep-dive/).

---

## 5. ECDSA & EdDSA — đường cong elliptic, khóa nhỏ

`ES256` = ECDSA trên đường cong P-256 + SHA-256. `EdDSA` = Ed25519 (đường cong Curve25519). Cả hai dựa trên bài toán **logarit rời rạc trên đường cong elliptic (ECDLP)**.

### 5.1. Đường cong & "phép cộng điểm" — số học mới

Một đường cong elliptic (dạng Weierstrass) là tập điểm `(x, y)` thỏa `y² = x³ + ax + b` trên một trường hữu hạn `𝔽_p`, cộng thêm "điểm vô cực" `O` làm phần tử trung hòa.

```diagram
PHÉP CỘNG ĐIỂM (chord-and-tangent) — định nghĩa hình học:
   P + Q:  kẻ đường thẳng qua P, Q → cắt đường cong tại điểm thứ 3 → lấy đối xứng qua trục x
   P + P (gấp đôi): dùng TIẾP TUYẾN tại P thay cho cát tuyến

   ┌───────────────── y² = x³ + ax + b ─────────────────┐
   │        •P                                          │
   │          \                                         │
   │           \____ • (giao điểm thứ 3)                │
   │      •Q         ┆                                  │
   │                 ┆ lấy đối xứng                     │
   │                 •  = P+Q                           │
   └────────────────────────────────────────────────────┘
```

Phép "nhân vô hướng" `d·G` = cộng `G` với chính nó `d` lần (dùng double-and-add, giống square-and-multiply ở RSA):

```diagram
private key:  d  (một số nguyên ngẫu nhiên ~256-bit)
public key:   Q = d·G   (G là "điểm sinh" công khai, cố định theo đường cong)

ECDLP:  biết Q và G, tìm d  →  KHÔNG có cách nào tốt hơn ~√n phép thử (Pollard rho)
        → với n ~2²⁵⁶, cần ~2¹²⁸ phép → bất khả thi
```

> [!IMPORTANT]
> Đây là chìa khóa của "khóa nhỏ mà mạnh": bài toán ECDLP **không có thuật toán dưới-mũ** (sub-exponential) như factoring của RSA. Thuật toán phá tốt nhất (Pollard rho) là **mũ đầy đủ** `O(√n)`, nên 256-bit EC đã mạnh ngang ~3072-bit RSA (xem §6).

### 5.2. Thuật toán ký ECDSA — và vai trò sống còn của `k`

```diagram
KÝ (message hash z = SHA256(SigningInput), rút gọn còn ≤ bit-length của n):
   1. chọn nonce k NGẪU NHIÊN, bí mật, DUY NHẤT mỗi lần ký
   2. R = k·G ;  r = R.x mod n          (nếu r=0 → chọn k khác)
   3. s = k⁻¹ · (z + r·d) mod n         (nếu s=0 → chọn k khác)
   → chữ ký = (r, s)

VERIFY (chỉ cần public key Q):
   1. w = s⁻¹ mod n
   2. u1 = z·w mod n ;  u2 = r·w mod n
   3. R' = u1·G + u2·Q ;  hợp lệ ⇔ R'.x mod n == r
```

JWS nối `(r, s)` thành `r ‖ s` **cố định độ dài** (ES256 = 32+32 = 64 byte) — **không** phải DER. Chi tiết và bẫy DER ở [Chữ ký số JWT — Deep Dive §6](/internals/signature-deep-dive/).

> [!WARNING]
> `s = k⁻¹(z + r·d)` chứa private key `d`. Nếu `k` **lặp lại** trên hai message khác nhau, hai phương trình hai ẩn cho phép giải ra `d` chỉ bằng đại số (vụ **Sony PS3 2010** dùng `k` cố định). Tệ hơn: chỉ cần `k` **hơi lệch** (vài bit đầu đoán được, RNG yếu) → tấn công lattice (HNP) khôi phục `d` sau vài trăm chữ ký. `k` là điểm chí mạng của ECDSA.

### 5.3. EdDSA — sửa đúng cái bẫy `k`

```diagram
EdDSA (Ed25519) khác ECDSA ở 3 điểm cốt lõi:
   1. nonce TẤT ĐỊNH:  k = H(prefix_bí_mật ‖ message)   → KHÔNG cần RNG khi ký
      → cùng (key, message) luôn ra cùng chữ ký; loại bỏ hoàn toàn rủi ro k
   2. đường cong twisted Edwards + công thức cộng ĐẦY ĐỦ (không có ca đặc biệt)
      → ít nhánh rẽ → kháng side-channel tốt hơn
   3. nhanh, đơn giản, ít chỗ cài sai
```

### 5.4. Ưu điểm tổng hợp

- Khóa & chữ ký **nhỏ** (private ~32B, public ~32–64B, chữ ký 64B) → token gọn, băng thông thấp.
- Ký **nhanh** hơn RSA nhiều; verify cũng nhanh.
- EdDSA: tất định, nhanh, kháng side-channel tốt — lựa chọn hiện đại nếu stack hỗ trợ.

---

## 6. Độ an toàn tương đương — vì sao 256-bit EC ≈ 3072-bit RSA

"Số bit" của RSA và EC **không** so sánh trực tiếp được, vì chúng dựa trên hai bài toán khác nhau với **thuật toán phá tốt nhất khác nhau**:

```diagram
RSA  ── phá bằng GNFS (General Number Field Sieve)
        → DƯỚI-mũ (sub-exponential): độ khó tăng chậm theo số bit
        → phải tăng modulus rất nhiều mới thêm chút an toàn

EC   ── phá bằng Pollard rho
        → MŨ đầy đủ: độ khó ≈ √n, tăng nhanh theo số bit
        → thêm vài chục bit khóa là an toàn nhân đôi
```

Bảng tương đương (theo NIST SP 800-57):

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
   → muốn lên 256-bit security: RSA cần 15360-bit (phình kinh khủng), EC chỉ 521-bit
```

> [!NOTE]
> Đây là lý do gốc khiến ES256/EdDSA "đáng giá": đạt độ an toàn cao với khóa và chữ ký nhỏ hơn nhiều → token nhẹ, ký nhanh. Cái giá là khả năng tương thích (một số hệ thống cũ chỉ hỗ trợ RS256). (Cả RSA lẫn ECC đều bị phá bởi máy tính lượng tử đủ lớn — Shor; đó là chuyện hậu-lượng-tử, ngoài phạm vi JWT hiện nay.)

---

## 7. Kích thước & hiệu năng — số thực tế (ops/sec, byte)

Con số dưới đây mang tính **bậc độ lớn** (tùy CPU/thư viện, đo trên một core thường), đủ để ra quyết định:

| Thuật toán | Chữ ký (raw) | Sau base64url | Ký (ops/sec) | Verify (ops/sec) |
|------------|--------------|----------------|--------------|-------------------|
| HS256 | 32 byte | ~43 ký tự | ~1.000.000+ | ~1.000.000+ |
| EdDSA (Ed25519) | 64 byte | ~86 ký tự | ~25.000–70.000 | ~15.000–25.000 |
| ES256 (P-256) | 64 byte | ~86 ký tự | ~10.000–30.000 | ~7.000–20.000 |
| RS256 (2048) | 256 byte | ~342 ký tự | ~1.000–4.000 (chậm) | ~25.000–60.000 (nhanh) |
| RS256 (4096) | 512 byte | ~683 ký tự | ~200–700 (rất chậm) | ~10.000–20.000 |

```diagram
Hai quan sát quan trọng:
   • RSA: KÝ chậm nhất, VERIFY thuộc nhóm nhanh nhất (vì e nhỏ) → lệch rõ rệt
   • EC/EdDSA: cân bằng cả hai chiều, không chiều nào "thảm họa"
   • HMAC: nhanh áp đảo cả hai chiều (nhưng không tách được vai trò khóa)
```

```diagram
Độ dài token (phần signature) ảnh hưởng:
   - Header HTTP (Authorization: Bearer ...) — giới hạn ~8KB ở nhiều proxy
   - Cookie (giới hạn ~4KB)
   - Băng thông MỖI request (token gửi kèm mọi lần gọi API)

   RS256-4096 (chữ ký 683 ký tự) + nhiều claim có thể chạm trần header
   → ưu tiên ES256/EdDSA khi cần gọn (chữ ký chỉ ~86 ký tự)
```

> [!IMPORTANT]
> Điểm hay bị quên khi benchmark: với bất đối xứng, **verify chạy nhiều hơn ký rất nhiều** (mỗi request đều verify, mỗi đăng nhập mới ký một lần). Nếu hệ thống của bạn verify hàng chục nghìn lần/giây, RSA verify nhanh là một lợi thế. Nhưng nếu ký nhiều (token ngắn hạn, refresh liên tục), ký RSA chậm thành nút cổ chai → EC/EdDSA thắng.

---

## 8. Side-channel — cùng thuật toán, rò khóa theo cách khác nhau

An toàn "trên giấy" khác với an toàn khi *cài đặt*. Mỗi họ có lớp rò rỉ riêng:

| Họ | Kênh rò rỉ | Cơ chế | Phòng thủ |
|----|------------|--------|-----------|
| HMAC | **Timing** khi so tag | So sánh chuỗi dừng sớm ở byte khác đầu tiên → đoán dần tag | So sánh **constant-time** (`crypto.timingSafeEqual`) |
| RSA | **Timing/cache** khi mũ-modulo bằng `d` | Thời gian phụ thuộc bit của `d` | **Blinding** (làm mù số mũ); thư viện chuẩn |
| ECDSA | **Nonce `k` lệch** | RNG yếu/biased → lattice (HNP) khôi phục `d` | RFC 6979 (k tất định) hoặc EdDSA |
| ECDSA/EdDSA | **Scalar mult** không hằng thời gian | Nhánh rẽ phụ thuộc bit của `d` | Cài đặt constant-time; đường cong "an toàn" |

```diagram
Bài học chung:
   "Thuật toán mạnh" KHÔNG đủ — cài đặt phải kín kênh phụ.
   → Đây là lý do KHÔNG tự viết primitive mật mã; dùng thư viện đã kiểm thử
     (OpenSSL, libsodium, jose) đã xử lý constant-time/blinding/nonce.
```

> [!WARNING]
> Side-channel quan trọng nhất *trong tầm kiểm soát của lập trình viên JWT* là **so sánh chữ ký/tag không constant-time** ở phía verifier tự viết. Luôn dùng so sánh hằng thời gian — chi tiết ở [Chữ ký số JWT — Deep Dive §8](/internals/signature-deep-dive/).

---

## 9. Bảng so sánh tổng hợp

| Tiêu chí | HMAC (HS*) | RSA (RS*/PS*) | ECDSA (ES*) | EdDSA |
|----------|-----------|---------------|-------------|-------|
| Loại | Đối xứng | Bất đối xứng | Bất đối xứng | Bất đối xứng |
| Bài toán nền | PRF / hàm băm | factoring | ECDLP | ECDLP |
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

## 10. Cây quyết định — chọn thuật toán nào

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

## 11. Code thực chiến — ký/verify "từ tay" với crypto thuần

Để thấy JWT không có gì ma thuật, đây là ký/verify **không dùng thư viện JWT**, chỉ `crypto` thuần.

### 11.1. HS256 từ `crypto.createHmac`

```javascript
import { createHmac, timingSafeEqual } from 'crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function signHS256(headerObj, payloadObj, secret) {
  const header  = b64url(JSON.stringify(headerObj));
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = `${header}.${payload}`;
  const sig = createHmac('sha256', secret).update(signingInput).digest('base64url');
  return `${signingInput}.${sig}`;
}

function verifyHS256(token, secret) {
  const [h, p, sig] = token.split('.');
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const got = Buffer.from(sig, 'base64url');
  // constant-time + so độ dài trước (timingSafeEqual ném lỗi nếu khác độ dài)
  return got.length === expected.length && timingSafeEqual(got, expected);
}
```

### 11.2. RS256 / ES256 từ `crypto.sign` / `crypto.verify`

```javascript
import { sign, verify, generateKeyPairSync } from 'crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

// Sinh cặp khóa (ES256 = EC P-256; đổi sang 'rsa' modulusLength:2048 cho RS256)
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function signES256(headerObj, payloadObj, priv) {
  const header  = b64url(JSON.stringify(headerObj));   // { alg:'ES256', typ:'JWT' }
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = Buffer.from(`${header}.${payload}`);
  // dsaEncoding:'ieee-p1363' → r‖s cố định 64B (KHÔNG phải DER) — đúng chuẩn JWS
  const sig = sign('sha256', signingInput, { key: priv, dsaEncoding: 'ieee-p1363' });
  return `${header}.${payload}.${b64url(sig)}`;
}

function verifyES256(token, pub) {
  const [h, p, s] = token.split('.');
  return verify(
    'sha256',
    Buffer.from(`${h}.${p}`),
    { key: pub, dsaEncoding: 'ieee-p1363' },
    Buffer.from(s, 'base64url'),
  );
}
```

> [!TIP]
> Với RS256 dùng `sign('sha256', data, privateKey)` (mặc định PKCS#1 v1.5). Với PS256 thêm `{ key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }`. Lưu ý `dsaEncoding: 'ieee-p1363'` cho ES* là bắt buộc để ra `r‖s` đúng chuẩn JWS — quên nó, Node mặc định ra DER và verifier JWT sẽ từ chối.

### 11.3. Sinh khóa cho từng họ (CLI)

```bash
# HMAC: chỉ cần secret ngẫu nhiên mạnh
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"

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

---

## 12. Anti-patterns cần tránh

| Anti-pattern | Hậu quả | Làm đúng |
|--------------|---------|----------|
| Dùng HS256 rồi copy secret ra N microservice | N nơi giả được token; lộ 1 = lộ hết | Chuyển sang RS256/ES256; chỉ auth server giữ private key |
| HS256 với secret là câu mật khẩu ngắn | Brute-force/dictionary ra secret (hashcat) | Secret ≥ 32 byte từ CSPRNG |
| Đưa HMAC secret cho bên thứ ba để họ verify | Trao luôn quyền giả token | Đưa public key (RS/ES), giữ private key |
| RSA-4096 cho mọi thứ "cho chắc" | Token phình, ký rất chậm (~200 ops/s) | RSA-2048/3072 đủ; cần gọn thì ES256/EdDSA |
| Tự cài k cho ECDSA / tái dùng / RNG yếu | Lộ private key (đại số/lattice) | Dùng thư viện chuẩn; ưu tiên EdDSA (k tất định) |
| ES* ký ra DER nhưng verifier chờ r‖s | Verify luôn fail | `dsaEncoding: 'ieee-p1363'` cho JWS |
| Verifier tự so chữ ký bằng `==` chuỗi | Timing attack (HMAC) | `timingSafeEqual` constant-time |
| Verify RS256 dò hash "ở đâu đó" trong EM | Bleichenbacher forgery | Dựng lại EM kỳ vọng, so toàn bộ byte |
| Verifier không ghim `algorithms` | alg confusion (RS→HS) | Luôn truyền allowlist alg |
| Coi chữ ký là "mã hóa" | Lộ dữ liệu nhạy cảm trong payload | Ký ≠ mã hóa; cần bí mật thì dùng JWE |

---

## 13. Tóm tắt — Cheat sheet

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
│  RUỘT:   RSA  = mᵈ mod n (ký) / sᵉ mod n (verify), e nhỏ→verify nhanh │
│          EC   = Q=d·G; ký dùng nonce k (k lặp = lộ d!)        │
│          HMAC = 2 vòng băm, chặn length-extension, là PRF     │
│                                                                │
│  Tương đương an toàn:  EC-256 ≈ RSA-3072 (128-bit)           │
│       (EC phá bằng Pollard rho — mũ; RSA bằng GNFS — dưới mũ) │
│  Kích thước chữ ký:    HS(32) < ES/EdDSA(64) ≪ RS(256+)      │
│  Hiệu năng: RSA ký chậm/verify nhanh; EC/EdDSA cân bằng.      │
│                                                                │
│  LUÔN: ghim algorithms=[...]; constant-time compare; ký ≠ mã hóa │
╰──────────────────────────────────────────────────────────────╯
```

**3 nguyên tắc xương sống:**

1. **Chọn theo mô hình tin cậy, không theo quán tính.** Một bên verify → HMAC; nhiều bên verify → bất đối xứng. Đây là quyết định kiến trúc, không phải "thuật toán nào mạnh hơn".
2. **Bất đối xứng để verifier không giả được token.** Public key phát đi thoải mái (qua JWKS); private key chỉ nằm ở nơi phát hành. An toàn RSA = factoring khó; an toàn EC = ECDLP khó.
3. **Cài đặt quan trọng ngang thuật toán.** `k` duy nhất cho ECDSA (hoặc dùng EdDSA), constant-time compare cho HMAC, blinding cho RSA — và luôn ghim `algorithms` ở verifier.

Đọc tiếp: [JWK & JWKS — Deep Dive](/cryptography/jwk-and-jwks/) (phát public key cho nhiều verifier) và [Key Rotation — Deep Dive](/cryptography/key-rotation/) (xoay khóa không downtime).
