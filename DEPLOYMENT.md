# TF-Proxy Deployment Guide

## Overview
This Cloudflare Workers proxy handles:
- API proxying for Polygon.io and Alpaca
- Stripe checkout session creation
- Stripe webhook handling for subscription management
- Firebase Firestore updates for user subscriptions

## Required Environment Variables

### Stripe Configuration
```bash
# Stripe API Keys (REPLACE WITH ACTUAL VALUES FROM STRIPE DASHBOARD)
STRIPE_SECRET_KEY=your_stripe_secret_key_here

# Stripe Webhook Secret (get from Stripe Dashboard -> Developers -> Webhooks)
# After creating webhook endpoint: https://tf-proxy.dmitriynyc718.workers.dev/api/stripe/webhook
STRIPE_WEBHOOK_SECRET=your_webhook_secret_here
```

### Firebase Configuration
To get Firebase service account credentials:
1. Go to Firebase Console: https://console.firebase.google.com/
2. Select your project: `tradeflows-pro`
3. Go to Project Settings (gear icon) -> Service Accounts
4. Click "Generate New Private Key"
5. Download the JSON file

From the downloaded JSON file, extract these values:
```bash
FIREBASE_PROJECT_ID=tradeflows-pro
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@tradeflows-pro.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nXXXX...\n-----END PRIVATE KEY-----\n"
```

**IMPORTANT**: The private key must include the `\n` characters. When adding to Cloudflare Workers secrets:
- Keep the quotes around the private key
- Preserve all newlines as `\n`

### API Keys (existing)
```bash
POLYGON_KEY=your_polygon_key
ALPACA_KEY=your_alpaca_key
ALPACA_SECRET=your_alpaca_secret
```

## Deployment Steps

### 1. Set Environment Variables in Cloudflare Workers

```bash
# Navigate to tf-proxy directory
cd C:\Users\dmitr\Projects\tf-proxy

# Set Stripe secrets
npx wrangler secret put STRIPE_SECRET_KEY
# Paste your actual Stripe secret key (starts with sk_live_)

npx wrangler secret put STRIPE_WEBHOOK_SECRET
# Paste the webhook secret from Stripe Dashboard

# Set Firebase secrets
npx wrangler secret put FIREBASE_PROJECT_ID
# Paste: tradeflows-pro

npx wrangler secret put FIREBASE_CLIENT_EMAIL
# Paste the client email from service account JSON

npx wrangler secret put FIREBASE_PRIVATE_KEY
# Paste the entire private key including -----BEGIN and -----END lines with \n characters
```

### 2. Deploy to Cloudflare Workers

```bash
npm run deploy
```

### 3. Configure Stripe Webhook

1. Go to Stripe Dashboard: https://dashboard.stripe.com/webhooks
2. Click "Add endpoint"
3. Set endpoint URL: `https://tf-proxy.dmitriynyc718.workers.dev/api/stripe/webhook`
4. Select events to listen to:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
5. Copy the webhook signing secret and add it to Cloudflare Workers (step 1 above)

## Testing

### Test Stripe Checkout
```bash
curl -X POST https://tf-proxy.dmitriynyc718.workers.dev/api/stripe/create-checkout \
  -H "Content-Type: application/json" \
  -d '{
    "priceId": "price_1SFpHtR3nVj6sOv4M3yKMR5z",
    "userEmail": "test@example.com",
    "userId": "test-user-id",
    "planName": "PREMIUM",
    "billingCycle": "monthly"
  }'
```

### Test Webhook (from Stripe CLI)
```bash
stripe listen --forward-to https://tf-proxy.dmitriynyc718.workers.dev/api/stripe/webhook
stripe trigger checkout.session.completed
```

## Monitoring

View logs:
```bash
npx wrangler tail
```

## Troubleshooting

### Issue: Webhook signature verification fails
- Ensure STRIPE_WEBHOOK_SECRET is correctly set
- Verify the webhook endpoint URL matches exactly
- Check webhook signing secret hasn't been regenerated

### Issue: Firebase update fails
- Verify Firebase service account credentials are correct
- Ensure private key includes all newlines as `\n`
- Check Firebase project ID matches
- Verify service account has Firestore write permissions

### Issue: User subscription not updating
- Check Cloudflare Workers logs: `npx wrangler tail`
- Verify userId is being passed correctly in checkout session metadata
- Ensure Firestore security rules allow service account writes

## Architecture Flow

1. **User clicks upgrade** → tradeflows-pro app
2. **App calls** → `/api/stripe/create-checkout` on tf-proxy
3. **tf-proxy creates** → Stripe checkout session
4. **User redirected to** → Stripe checkout page
5. **User completes payment** → Stripe processes
6. **Stripe sends webhook** → `/api/stripe/webhook` on tf-proxy
7. **tf-proxy updates** → Firebase Firestore user document
8. **User redirected back** → tradeflows-pro app with success
9. **App refreshes** → User data and sees premium features

## Security Notes

- All secrets stored in Cloudflare Workers encrypted secrets
- Webhook signature verification enabled
- CORS headers configured for app.tradeflows.net
- Firebase OAuth token generated on-the-fly for each request
- Rate limiting enabled via KV namespace
