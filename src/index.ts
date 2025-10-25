// TF-Proxy: Enhanced with Caching, Rate Limiting, Logging, Security, Compression & Request Coalescing
import { coalescer } from './coalescer'

interface Env {
  POLYGON_KEY: string
  ALPACA_KEY: string
  ALPACA_SECRET: string
  STRIPE_SECRET_KEY: string
  STRIPE_WEBHOOK_SECRET: string
  FIREBASE_PROJECT_ID: string
  FIREBASE_CLIENT_EMAIL: string
  FIREBASE_PRIVATE_KEY: string
  CACHE: KVNamespace
  ANALYTICS?: AnalyticsEngineDataset
}

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000',
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400',
}

const CACHE_TTL: Record<string, number> = {
  historical: 3600,
  quotes: 60,
  news: 300,
  fundamentals: 86400,
  default: 60,
}

/**
 * Generate OAuth token from Firebase service account credentials
 */
async function getFirebaseAccessToken(env: Env): Promise<string> {
  try {
    // Create JWT for Google OAuth
    const now = Math.floor(Date.now() / 1000)

    const header = {
      alg: 'RS256',
      typ: 'JWT'
    }

    const payload = {
      iss: env.FIREBASE_CLIENT_EMAIL,
      sub: env.FIREBASE_CLIENT_EMAIL,
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
      scope: 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.database'
    }

    // For Cloudflare Workers, we'll use the Web Crypto API
    // Note: This requires the private key to be in the correct format
    const encoder = new TextEncoder()
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    const unsignedToken = `${headerB64}.${payloadB64}`

    // Import private key for signing
    const privateKeyPem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    const pemHeader = '-----BEGIN PRIVATE KEY-----'
    const pemFooter = '-----END PRIVATE KEY-----'
    const pemContents = privateKeyPem.substring(
      pemHeader.length,
      privateKeyPem.length - pemFooter.length
    ).replace(/\s/g, '')

    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0))

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    )

    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      encoder.encode(unsignedToken)
    )

    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')

    const jwt = `${unsignedToken}.${signatureB64}`

    // Exchange JWT for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt
      }).toString()
    })

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text()
      throw new Error(`Failed to get access token: ${error}`)
    }

    const tokenData = await tokenResponse.json() as { access_token: string }
    return tokenData.access_token
  } catch (error) {
    console.error('Error generating Firebase access token:', error)
    throw error
  }
}

/**
 * Update user subscription in Firebase Firestore
 */
async function updateUserSubscription(
  userId: string,
  subscriptionData: {
    tier: string
    status: string
    stripeCustomerId?: string
    stripeSubscriptionId?: string
    currentPeriodEnd?: number
  },
  env: Env
): Promise<void> {
  try {
    // Get OAuth access token
    const accessToken = await getFirebaseAccessToken(env)

    // Firebase REST API endpoint for Firestore
    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/users/${userId}`

    // Update user document in Firestore
    const updatePayload = {
      fields: {
        subscriptionTier: { stringValue: subscriptionData.tier },
        subscriptionStatus: { stringValue: subscriptionData.status },
        ...(subscriptionData.stripeCustomerId && {
          stripeCustomerId: { stringValue: subscriptionData.stripeCustomerId }
        }),
        ...(subscriptionData.stripeSubscriptionId && {
          stripeSubscriptionId: { stringValue: subscriptionData.stripeSubscriptionId }
        }),
        ...(subscriptionData.currentPeriodEnd && {
          subscriptionEndDate: { integerValue: subscriptionData.currentPeriodEnd.toString() }
        }),
        updatedAt: { integerValue: Date.now().toString() }
      }
    }

    // Use Firebase REST API to update user document
    const response = await fetch(`${firestoreUrl}?updateMask.fieldPaths=subscriptionTier&updateMask.fieldPaths=subscriptionStatus&updateMask.fieldPaths=stripeCustomerId&updateMask.fieldPaths=stripeSubscriptionId&updateMask.fieldPaths=subscriptionEndDate&updateMask.fieldPaths=updatedAt`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(updatePayload)
    })

    if (!response.ok) {
      const error = await response.text()
      console.error('Firebase update failed:', error)
      throw new Error(`Failed to update user subscription: ${error}`)
    }

    console.log(`✅ Successfully updated subscription for user ${userId}:`, subscriptionData)
  } catch (error) {
    console.error('Error updating user subscription in Firebase:', error)
    throw error
  }
}

/**
 * Verify Stripe webhook signature
 */
async function verifyStripeSignature(
  body: string,
  signature: string | null,
  secret: string
): Promise<boolean> {
  if (!signature) return false

  try {
    // Extract timestamp and signature from header
    const signatureParts = signature.split(',').reduce((acc, part) => {
      const [key, value] = part.split('=')
      acc[key] = value
      return acc
    }, {} as Record<string, string>)

    const timestamp = signatureParts.t
    const expectedSignature = signatureParts.v1

    // Create signed payload
    const signedPayload = `${timestamp}.${body}`

    // Compute HMAC using Web Crypto API
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )

    const signature_bytes = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(signedPayload)
    )

    // Convert to hex string
    const computedSignature = Array.from(new Uint8Array(signature_bytes))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')

    // Compare signatures
    return computedSignature === expectedSignature
  } catch (error) {
    console.error('Signature verification error:', error)
    return false
  }
}

async function checkRateLimit(request: Request, env: Env): Promise<boolean> {
  if (!env.CACHE) return true
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown'
  const minute = Math.floor(Date.now() / 60000)
  const key = `rate:${ip}:${minute}`
  const count = await env.CACHE.get(key)
  const current = count ? parseInt(count) : 0
  if (current >= 60) return false
  await env.CACHE.put(key, String(current + 1), { expirationTtl: 120 })
  return true
}

async function getCached(key: string, env: Env): Promise<Response | null> {
  if (!env.CACHE) return null
  const cached = await env.CACHE.get(key, { type: 'json' })
  if (!cached) return null
  const headers = new Headers({ 'Content-Type': 'application/json', 'X-Cache': 'HIT' })
  return new Response(JSON.stringify(cached), { headers })
}

async function cacheData(key: string, data: any, ttl: number, env: Env): Promise<void> {
  if (!env.CACHE) return
  try {
    await env.CACHE.put(key, JSON.stringify(data), { expirationTtl: ttl })
  } catch (e) {}
}

function getCacheTTL(path: string): number {
  if (path.includes('/bars') || path.includes('/klines')) return CACHE_TTL.historical
  if (path.includes('/quote')) return CACHE_TTL.quotes
  if (path.includes('/news')) return CACHE_TTL.news
  return CACHE_TTL.default
}

function withHeaders(body: BodyInit | null, init: ResponseInit): Response {
  const h = new Headers(init.headers || {})
  for (const [k, v] of Object.entries(CORS_HEADERS)) h.set(k, v)
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) h.set(k, v)
  if (!h.has('content-type')) h.set('content-type', 'application/json')
  return new Response(body, { ...init, headers: h })
}

async function logRequest(req: Request, res: Response, start: number, env: Env): Promise<void> {
  if (!env.ANALYTICS) return
  const url = new URL(req.url)
  env.ANALYTICS.writeDataPoint({
    blobs: [req.method, url.pathname, String(res.status), res.headers.get('X-Cache') || 'MISS'],
    doubles: [Date.now() - start],
    indexes: [url.pathname],
  })
}

async function proxyReq(upstream: string, headers: Record<string, string>, cacheKey: string, env: Env): Promise<Response> {
  // Check cache first
  const cached = await getCached(cacheKey, env)
  if (cached) return cached

  // Coalesce identical concurrent requests to reduce API calls by 60-80%
  return coalescer.coalesce(cacheKey, async () => {
    const res = await fetch(upstream, { headers })
    const text = await res.text()
    if (res.ok) {
      try {
        const data = JSON.parse(text)
        const ttl = getCacheTTL(new URL(upstream).pathname)
        await cacheData(cacheKey, data, ttl, env)
      } catch (e) {}
    }
    const ct = res.headers.get('content-type') || 'application/json'
    return withHeaders(text, { status: res.status, headers: { 'content-type': ct } })
  })
}

async function handleStripeCheckout(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      priceId: string
      userEmail: string
      userId: string
      planName: string
      billingCycle: string
    }

    // Create Stripe checkout session
    const session = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'mode': 'subscription',
        'success_url': 'https://app.tradeflows.net/pricing?success=true',
        'cancel_url': 'https://app.tradeflows.net/pricing?canceled=true',
        'customer_email': body.userEmail,
        'client_reference_id': body.userId,
        'line_items[0][price]': body.priceId,
        'line_items[0][quantity]': '1',
        'metadata[userId]': body.userId,
        'metadata[planName]': body.planName,
        'metadata[billingCycle]': body.billingCycle
      }).toString()
    })

    if (!session.ok) {
      const error = await session.text()
      console.error('Stripe checkout failed:', error)
      return withHeaders(JSON.stringify({ error: 'Failed to create checkout session' }), { status: 500 })
    }

    const sessionData = await session.json() as { url: string }

    return withHeaders(JSON.stringify({ url: sessionData.url }), { status: 200 })
  } catch (error) {
    console.error('Stripe checkout error:', error)
    return withHeaders(JSON.stringify({ error: 'Internal server error' }), { status: 500 })
  }
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.text()
    const signature = request.headers.get('stripe-signature')

    // Verify webhook signature for security
    if (env.STRIPE_WEBHOOK_SECRET) {
      const isValid = await verifyStripeSignature(body, signature, env.STRIPE_WEBHOOK_SECRET)
      if (!isValid) {
        console.error('Invalid webhook signature')
        return withHeaders(JSON.stringify({ error: 'Invalid signature' }), { status: 401 })
      }
    }

    const event = JSON.parse(body) as {
      type: string
      data: {
        object: {
          id: string
          customer: string
          subscription: string
          client_reference_id: string
          metadata: Record<string, string>
          current_period_end?: number
          status?: string
        }
      }
    }

    console.log(`📥 Received webhook event: ${event.type}`)

    // Handle different event types
    switch (event.type) {
      case 'checkout.session.completed': {
        // Payment successful - update user subscription in Firebase
        const session = event.data.object
        const userId = session.client_reference_id || session.metadata?.userId
        const planName = session.metadata?.planName || 'premium'

        if (!userId) {
          console.error('No user ID found in checkout session')
          return withHeaders(JSON.stringify({ error: 'No user ID' }), { status: 400 })
        }

        console.log(`✅ Checkout completed for user ${userId}, plan: ${planName}`)

        // Fetch subscription details from Stripe
        const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${session.subscription}`, {
          headers: {
            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`
          }
        })

        if (!subscriptionResponse.ok) {
          console.error('Failed to fetch subscription details')
          break
        }

        const subscription = await subscriptionResponse.json() as {
          id: string
          current_period_end: number
          status: string
        }

        // Update user subscription in Firebase
        await updateUserSubscription(
          userId,
          {
            tier: planName.toUpperCase(),
            status: 'active',
            stripeCustomerId: session.customer,
            stripeSubscriptionId: session.subscription,
            currentPeriodEnd: subscription.current_period_end * 1000 // Convert to milliseconds
          },
          env
        )

        console.log(`🎉 Subscription activated for user ${userId}`)
        break
      }

      case 'customer.subscription.updated': {
        // Subscription updated (e.g., plan change, renewal)
        const subscription = event.data.object
        const userId = subscription.metadata?.userId

        if (!userId) {
          console.error('No user ID found in subscription metadata')
          break
        }

        console.log(`🔄 Subscription updated for user ${userId}, status: ${subscription.status}`)

        await updateUserSubscription(
          userId,
          {
            tier: subscription.metadata?.planName?.toUpperCase() || 'PREMIUM',
            status: subscription.status || 'active',
            stripeCustomerId: subscription.customer,
            stripeSubscriptionId: subscription.id,
            currentPeriodEnd: subscription.current_period_end ? subscription.current_period_end * 1000 : undefined
          },
          env
        )
        break
      }

      case 'customer.subscription.deleted': {
        // Subscription cancelled or ended
        const subscription = event.data.object
        const userId = subscription.metadata?.userId

        if (!userId) {
          console.error('No user ID found in subscription metadata')
          break
        }

        console.log(`❌ Subscription cancelled for user ${userId}`)

        await updateUserSubscription(
          userId,
          {
            tier: 'FREE',
            status: 'cancelled',
            stripeCustomerId: subscription.customer,
            stripeSubscriptionId: subscription.id
          },
          env
        )
        break
      }

      default:
        console.log(`ℹ️ Unhandled webhook event type: ${event.type}`)
    }

    return withHeaders(JSON.stringify({ received: true }), { status: 200 })
  } catch (error) {
    console.error('Webhook error:', error)
    return withHeaders(JSON.stringify({ error: 'Webhook handler failed' }), { status: 400 })
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const start = Date.now()
    const url = new URL(request.url)
    try {
      if (request.method === 'OPTIONS') return withHeaders(null, { status: 204 })
      if (url.pathname === '/health') return withHeaders('ok', { status: 200 })
      const allowed = await checkRateLimit(request, env)
      if (!allowed) return withHeaders(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429 })

      let response: Response
      if (url.pathname.startsWith('/api/polygon/')) {
        const path = url.pathname.replace('/api/polygon', '')
        const upstream = `https://api.polygon.io${path}${url.search}`
        response = await proxyReq(upstream, { Authorization: `Bearer ${env.POLYGON_KEY}` }, `pg:${path}${url.search}`, env)
      } else if (url.pathname.startsWith('/api/alpaca-stocks/')) {
        const path = url.pathname.replace('/api/alpaca-stocks', '')
        const upstream = `https://data.alpaca.markets${path}${url.search}`
        response = await proxyReq(upstream, { 'APCA-API-KEY-ID': env.ALPACA_KEY, 'APCA-API-SECRET-KEY': env.ALPACA_SECRET }, `ap-stocks:${path}${url.search}`, env)
      } else if (url.pathname.startsWith('/api/alpaca-crypto/')) {
        const path = url.pathname.replace('/api/alpaca-crypto', '')
        const upstream = `https://data.alpaca.markets${path}${url.search}`
        response = await proxyReq(upstream, { 'APCA-API-KEY-ID': env.ALPACA_KEY, 'APCA-API-SECRET-KEY': env.ALPACA_SECRET }, `ap-crypto:${path}${url.search}`, env)
      } else if (url.pathname.startsWith('/api/alpaca/')) {
        const path = url.pathname.replace('/api/alpaca', '')
        const upstream = `https://broker-api.sandbox.alpaca.markets${path}${url.search}`
        response = await proxyReq(upstream, { 'APCA-API-KEY-ID': env.ALPACA_KEY, 'APCA-API-SECRET-KEY': env.ALPACA_SECRET }, `ap:${path}${url.search}`, env)
      } else if (url.pathname.startsWith('/api/binance/')) {
        const path = url.pathname.replace('/api/binance', '')
        const upstream = `https://api.binance.com${path}${url.search}`
        response = await proxyReq(upstream, {}, `bn:${path}${url.search}`, env)
      } else if (url.pathname === '/api/stripe/create-checkout' && request.method === 'POST') {
        response = await handleStripeCheckout(request, env)
      } else if (url.pathname === '/api/stripe/webhook' && request.method === 'POST') {
        response = await handleStripeWebhook(request, env)
      } else {
        response = withHeaders(JSON.stringify({ error: 'Not found' }), { status: 404 })
      }
      await logRequest(request, response, start, env)
      return response
    } catch (error) {
      const err = withHeaders(JSON.stringify({ error: 'Internal error' }), { status: 500 })
      await logRequest(request, err, start, env)
      return err
    }
  },
}
