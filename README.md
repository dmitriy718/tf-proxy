# TradeFlows Proxy

Cloudflare Worker proxy service for TradeFlows Pro platform.

## Purpose

This Cloudflare Worker acts as a secure proxy for API requests from the TradeFlows Pro application, handling:
- CORS headers
- API key management
- Request routing to external services (Polygon, Alpaca, etc.)
- Rate limiting and caching

## Tech Stack

- Cloudflare Workers
- TypeScript
- Wrangler CLI

## Development

```bash
# Install dependencies
npm install

# Run locally
npx wrangler dev

# Deploy to Cloudflare
npx wrangler deploy
```

## Environment Variables

Required secrets (set via `wrangler secret put`):
- `POLYGON_API_KEY` - Polygon.io API key
- `ALPACA_API_KEY` - Alpaca API key
- `ALPACA_SECRET_KEY` - Alpaca secret key

## Deployment

The proxy is deployed at: `https://tf-proxy.your-domain.workers.dev`

Configure the endpoint in TradeFlows Pro `.env`:
```
VITE_PROXY_URL=https://tf-proxy.your-domain.workers.dev
```

## Version History

- **Oct 22, 2024**: Clean repository structure
- **Sep 14, 2024**: Initial Cloudflare Worker setup

## License

Copyright © 2024 TradeFlows Professional. All rights reserved.
