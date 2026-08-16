# Link Security Checker

A beginner-friendly Node.js + Express project that checks URLs for common suspicious patterns.

## Features

- HTTPS check
- IP address detection
- URL length check
- `@` character detection
- Punycode detection
- Suspicious keyword detection
- Subdomain count check
- Non-standard port check
- Risk score from 0 to 100
- Low Risk / Suspicious / High Risk result

## Requirements

- Node.js 18+ recommended
- VS Code or another code editor
- Web browser

## Run the project

1. Open a terminal in this folder.
2. Install dependencies:

```bash
npm install
```

3. Start the server:

```bash
npm start
```

4. Open:

http://localhost:3000

For development, you can use:

```bash
npm run dev
```

## Important

This application is a heuristic checker. It does not prove that a URL is safe or malicious. For a more advanced version, add a reputable threat-intelligence API on the server side.

Never put an API key in `public/script.js`.
