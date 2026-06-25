# JWT Learn

Tài liệu học JSON Web Token tiếng Việt từ cơ bản đến chuyên sâu, xây dựng bằng Next.js 15 + Fumadocs và deploy lên Cloudflare Pages.

## Development

```bash
npm install
npm run dev
```

Mở http://localhost:3000.

## Build

```bash
npm run build
```

Static output nằm trong `dist/`.

## Deploy Cloudflare Pages

```bash
npm run deploy
```

Cloudflare Pages config:

- Build command: `npm run build`
- Output directory: `dist`
