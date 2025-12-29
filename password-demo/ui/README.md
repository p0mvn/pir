# HIBP Password Checker UI

A Next.js frontend for checking passwords against the Have I Been Pwned database.

## Features

- 🔒 **Client-side hashing** - Passwords are SHA-1 hashed locally before being sent
- ⚡ **Real-time checking** - Instant feedback on password breach status
- 🎨 **Modern UI** - Clean, responsive design with dark theme
- 📊 **Stats display** - Shows how many times a password appeared in breaches

## Getting Started

### Prerequisites

- Node.js 18+
- The HIBP server running (see `../server/README.md`)

### Installation

```bash
npm install
```

### Development

```bash
# Start the development server (runs on port 3001)
npm run dev
```

The app will be available at `http://localhost:3001`.

### Configuration

Set the API URL via environment variable:

```bash
NEXT_PUBLIC_API_URL=http://localhost:3000 npm run dev
```

### Production Build

```bash
npm run build
npm start
```

## Architecture

1. User enters a password
2. Password is hashed to SHA-1 in the browser using Web Crypto API
3. Only the hash is sent to the server
4. Server looks up hash in HIBP database
5. Result is displayed showing breach count

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:3000` | URL of the HIBP server |

## Attribution

Password data provided by [Have I Been Pwned](https://haveibeenpwned.com).


