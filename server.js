'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const Stripe = require('stripe');
const { google } = require('googleapis');
const fs = require('node:fs');

const required = ['FIREBASE_SERVICE_ACCOUNT_PATH', 'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_PLAY_PACKAGE_NAME'];
for (const key of required) {
  if (!process.env[key]) console.warn(`[config] ${key} não está configurada; rotas dependentes não funcionarão.`);
}

if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH && fs.existsSync(process.env.FIREBASE_SERVICE_ACCOUNT_PATH)) {
  const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
} else {
  // Em ambientes Google Cloud, ADC pode inicializar o Admin SDK sem arquivo local.
  admin.initializeApp({ credential: admin.credential.applicationDefault() });
}
const db = admin.firestore();
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const app = express();
const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, callback) {
  if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error('Origem não permitida por CORS'));
} }));

// Stripe requires the untouched raw request body to verify webhook signatures.
app.post('/v1/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe webhook não configurado');
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return res.status(400).send(`Webhook inválido: ${err.message}`); }

  try {
    if (['checkout.session.completed', 'checkout.session.async_payment_succeeded'].includes(event.type)) {
      const session = event.data.object;
      // One-time credit purchases are fulfilled only from a verified Stripe webhook.
      if (session.metadata?.kind === 'credit_pack' && session.payment_status === 'paid') {
        const uid = session.client_reference_id || session.metadata?.firebaseUid;
        const credits = Number(session.metadata?.credits || 0);
        if (!uid || !Number.isSafeInteger(credits) || credits <= 0) throw new Error('Pacote de créditos inválido no webhook.');
        const eventRef = db.collection('hypeProcessedPayments').doc(event.id);
        await db.runTransaction(async tx => {
          const processed = await tx.get(eventRef);
          if (processed.exists) return; // idempotência contra reentrega do webhook
          const walletRef = db.collection('hypeWallets').doc(uid);
          const wallet = await tx.get(walletRef);
          const before = Number(wallet.exists ? wallet.data().balance || 0 : 0);
          tx.set(walletRef, { balance: before + credits, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
          tx.create(db.collection('hypeCreditLedger').doc(), {
            uid, delta: credits, balanceAfter: before + credits, type: 'purchase', provider: 'stripe',
            providerEventId: event.id, checkoutSessionId: session.id, createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
          tx.create(eventRef, { type: 'credit_pack', uid, credits, processedAt: admin.firestore.FieldValue.serverTimestamp() });
        });
      } else {
        const uid = session.client_reference_id || session.metadata?.firebaseUid;
        if (uid && session.subscription) {
          const subscription = await stripe.subscriptions.retrieve(session.subscription);
          await saveStripeEntitlement(uid, subscription);
        }
      }
    } else if (['customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted'].includes(event.type)) {
      const subscription = event.data.object;
      const uid = subscription.metadata?.firebaseUid;
      if (uid) await saveStripeEntitlement(uid, subscription);
    }
    return res.json({ received: true });
  } catch (err) {
    console.error('[stripe webhook]', err);
    return res.status(500).send('Falha ao processar webhook');
  }
});

app.use(express.json({ limit: '64kb' }));
app.get('/health', (_req, res) => res.json({ ok: true, service: 'hype-subscriptions' }));

async function requireUser(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Autenticação HYPE obrigatória.' });
  try {
    req.hypeUser = await admin.auth().verifyIdToken(match[1]);
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Sessão inválida ou expirada. Entre novamente.' });
  }
}

function subscriptionIsActive(state, expiryTime) {
  const expiry = expiryTime ? Date.parse(expiryTime) : 0;
  const stateAllows = ['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD', 'SUBSCRIPTION_STATE_CANCELED'].includes(state);
  return stateAllows && Number.isFinite(expiry) && expiry > Date.now();
}

app.get('/v1/subscriptions/me', requireUser, async (req, res) => {
  try {
    const snap = await db.collection('hypeSubscriptions').doc(req.hypeUser.uid).get();
    const data = snap.exists ? snap.data() : {};
    const active = Boolean(data.active && data.expiryTime && Date.parse(data.expiryTime) > Date.now());
    return res.json({ active, provider: data.provider || null, status: data.status || 'none', expiryTime: data.expiryTime || null, plan: data.plan || null });
  } catch (err) {
    console.error('[subscription me]', err);
    return res.status(500).json({ error: 'Não foi possível consultar a assinatura.' });
  }
});

app.post('/v1/subscriptions/google/verify', requireUser, async (req, res) => {
  const { purchaseToken, productId, packageName } = req.body || {};
  if (!purchaseToken || productId !== (process.env.GOOGLE_PLAY_PRODUCT_ID || 'hype_premium')) {
    return res.status(400).json({ active: false, error: 'Token ou produto inválido.' });
  }
  if (packageName !== process.env.GOOGLE_PLAY_PACKAGE_NAME) {
    return res.status(400).json({ active: false, error: 'Pacote Android não corresponde.' });
  }
  try {
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
      scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    });
    const publisher = google.androidpublisher({ version: 'v3', auth });
    const result = await publisher.purchases.subscriptionsv2.get({ packageName, token: purchaseToken });
    const subscription = result.data;
    const lineItem = (subscription.lineItems || []).find(item => item.productId === productId);
    const expiryTime = lineItem?.expiryTime || null;
    const state = subscription.subscriptionState || 'SUBSCRIPTION_STATE_UNSPECIFIED';
    const active = subscriptionIsActive(state, expiryTime);

    // Do not grant Premium unless Google confirms the subscription is active.
    const entitlement = {
      active,
      provider: 'google_play',
      status: state,
      expiryTime,
      productId,
      plan: lineItem?.offerDetails?.basePlanId || null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      userId: req.hypeUser.uid,
      // Store a hash/reference, never expose the raw token in client responses.
      purchaseTokenHash: require('node:crypto').createHash('sha256').update(purchaseToken).digest('hex'),
    };
    await db.collection('hypeSubscriptions').doc(req.hypeUser.uid).set(entitlement, { merge: true });

    // Acknowledge an initial purchase only after Google confirms it. This endpoint is
    // idempotent; acknowledgement errors are logged for operational follow-up.
    if (active && subscription.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
      try {
        await publisher.purchases.subscriptions.acknowledge({ packageName, subscriptionId: productId, token: purchaseToken, requestBody: {} });
      } catch (ackErr) { console.error('[google acknowledge]', ackErr.message); }
    }
    return res.json({ active, provider: 'google_play', status: state, expiryTime, plan: entitlement.plan });
  } catch (err) {
    console.error('[google verify]', err);
    return res.status(502).json({ active: false, error: 'Não foi possível verificar a compra com o Google Play.' });
  }
});

app.post('/v1/subscriptions/stripe/portal', requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe não configurado.' });
  try {
    const snap = await db.collection('hypeSubscriptions').doc(req.hypeUser.uid).get();
    const customer = snap.exists ? snap.data()?.stripeCustomerId : null;
    if (!customer) return res.status(404).json({ error: 'Nenhuma assinatura do site encontrada para esta conta.' });
    const session = await stripe.billingPortal.sessions.create({
      customer,
      return_url: process.env.CHECKOUT_SUCCESS_URL,
    });
    return res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe portal]', err);
    return res.status(500).json({ error: 'Não foi possível abrir o gerenciamento da assinatura.' });
  }
});

app.post('/v1/subscriptions/stripe/checkout', requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe não configurado.' });
  const plan = req.body?.plan;
  const price = plan === 'monthly' ? process.env.STRIPE_PRICE_MONTHLY : plan === 'annual' ? process.env.STRIPE_PRICE_ANNUAL : null;
  if (!price) return res.status(400).json({ error: 'Plano Stripe inválido ou ainda não configurado.' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price, quantity: 1 }],
      client_reference_id: req.hypeUser.uid,
      metadata: { firebaseUid: req.hypeUser.uid, plan },
      subscription_data: { metadata: { firebaseUid: req.hypeUser.uid, plan } },
      success_url: process.env.CHECKOUT_SUCCESS_URL,
      cancel_url: process.env.CHECKOUT_CANCEL_URL,
      allow_promotion_codes: true,
    });
    return res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe checkout]', err);
    return res.status(500).json({ error: 'Não foi possível abrir o checkout.' });
  }
});

async function saveStripeEntitlement(uid, subscription) {
  const expirySeconds = subscription.current_period_end || 0;
  const expiryTime = expirySeconds ? new Date(expirySeconds * 1000).toISOString() : null;
  const active = ['active', 'trialing'].includes(subscription.status) && expiryTime && Date.parse(expiryTime) > Date.now();
  await db.collection('hypeSubscriptions').doc(uid).set({
    active: Boolean(active), provider: 'stripe', status: subscription.status,
    expiryTime, plan: subscription.metadata?.plan || null,
    stripeCustomerId: subscription.customer || null,
    stripeSubscriptionId: subscription.id,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(), userId: uid,
  }, { merge: true });
}



// Commercial licensing / reseller system. Roles are stored server-side in hypeRoles/{uid}.
// Never accept a role, wallet balance, expiry date, or credit amount as authoritative from the client.
function requireRole(roles) {
  return async (req, res, next) => {
    try {
      const snap = await db.collection('hypeRoles').doc(req.hypeUser.uid).get();
      const role = snap.exists ? snap.data().role : null;
      const status = snap.exists ? (snap.data().status || 'active') : null;
      if (status !== 'active' || !roles.includes(role)) return res.status(403).json({ error: 'Permissão insuficiente.' });
      req.hypeRole = { role, data: snap.data() };
      return next();
    } catch (err) {
      console.error('[role check]', err);
      return res.status(500).json({ error: 'Não foi possível validar permissões.' });
    }
  };
}
const requireOwner = (req, res, next) => requireRole(['owner'])(req, res, next);
const requireOwnerOrReseller = (req, res, next) => requireRole(['owner', 'reseller'])(req, res, next);
const ALLOWED_LICENSE_DAYS = new Set([7, 30, 90, 365]);
function creditCostFor(days) {
  try {
    const costs = JSON.parse(process.env.LICENSE_CREDIT_COSTS_JSON || '{}');
    const n = Number(costs[String(days)]);
    return Number.isSafeInteger(n) && n > 0 ? n : null;
  } catch (_) { return null; }
}

app.get('/v1/admin/me', requireUser, requireOwnerOrReseller, async (req, res) => {
  const uid = req.hypeUser.uid;
  const walletSnap = await db.collection('hypeWallets').doc(uid).get();
  const wallet = walletSnap.exists ? Number(walletSnap.data().balance || 0) : 0;
  return res.json({ uid, email: req.hypeUser.email || null, role: req.hypeRole.role, credits: wallet, creditCostsConfigured: Boolean(process.env.LICENSE_CREDIT_COSTS_JSON) });
});

app.get('/v1/admin/overview', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    const uid = req.hypeUser.uid;
    const isOwner = req.hypeRole.role === 'owner';
    const walletSnap = await db.collection('hypeWallets').doc(uid).get();
    let licensesQuery = db.collection('hypeLicenses').orderBy('createdAt', 'desc').limit(50);
    if (!isOwner) licensesQuery = db.collection('hypeLicenses').where('createdBy', '==', uid).orderBy('createdAt', 'desc').limit(50);
    const [licensesSnap, rolesSnap] = await Promise.all([
      licensesQuery.get(),
      isOwner ? db.collection('hypeRoles').where('role', '==', 'reseller').limit(200).get() : Promise.resolve(null),
    ]);
    return res.json({ role: req.hypeRole.role, credits: Number(walletSnap.exists ? walletSnap.data().balance || 0 : 0),
      licenses: licensesSnap.docs.map(d => ({ id: d.id, ...d.data(), createdAt: d.data().createdAt?.toDate?.().toISOString() || null, expiresAt: d.data().expiresAt?.toDate?.().toISOString() || null })),
      resellers: rolesSnap ? rolesSnap.docs.map(d => ({ uid: d.id, ...d.data() })) : [] });
  } catch (err) {
    console.error('[admin overview]', err);
    return res.status(500).json({ error: 'Falha ao carregar painel.' });
  }
});

app.post('/v1/admin/resellers', requireUser, requireOwner, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail válido de uma conta HYPE já cadastrada.' });
  try {
    const target = await admin.auth().getUserByEmail(email);
    const ref = db.collection('hypeRoles').doc(target.uid);
    const existing = await ref.get();
    if (existing.exists && existing.data().role === 'owner') return res.status(409).json({ error: 'A conta proprietária não pode ser revendedora.' });
    await ref.set({ role: 'reseller', status: 'active', email, createdBy: req.hypeUser.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.json({ ok: true, uid: target.uid, email, role: 'reseller' });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Crie primeiro a conta HYPE desse usuário.' });
    console.error('[create reseller]', err);
    return res.status(500).json({ error: 'Não foi possível criar revendedor.' });
  }
});

app.post('/v1/admin/resellers/:uid/status', requireUser, requireOwner, async (req, res) => {
  const status = req.body?.status;
  if (!['active', 'suspended'].includes(status)) return res.status(400).json({ error: 'Status inválido.' });
  const ref = db.collection('hypeRoles').doc(req.params.uid);
  const snap = await ref.get();
  if (!snap.exists || snap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor não encontrado.' });
  await ref.set({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp(), updatedBy: req.hypeUser.uid }, { merge: true });
  return res.json({ ok: true, uid: req.params.uid, status });
});

app.post('/v1/admin/credits/adjust', requireUser, requireOwner, async (req, res) => {
  const targetUid = String(req.body?.uid || '').trim();
  const delta = Number(req.body?.delta);
  const reason = String(req.body?.reason || '').trim().slice(0, 200);
  if (!targetUid || !Number.isSafeInteger(delta) || delta === 0 || Math.abs(delta) > 100000 || !reason) return res.status(400).json({ error: 'Informe UID, ajuste inteiro não zero e motivo.' });
  try {
    const roleSnap = await db.collection('hypeRoles').doc(targetUid).get();
    if (!roleSnap.exists || roleSnap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor não encontrado.' });
    const walletRef = db.collection('hypeWallets').doc(targetUid);
    let balanceAfter = 0;
    await db.runTransaction(async tx => {
      const walletSnap = await tx.get(walletRef);
      const before = Number(walletSnap.exists ? walletSnap.data().balance || 0 : 0);
      balanceAfter = before + delta;
      if (balanceAfter < 0) throw new Error('SALDO_NEGATIVO');
      tx.set(walletRef, { balance: balanceAfter, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      tx.create(db.collection('hypeCreditLedger').doc(), { uid: targetUid, delta, balanceAfter, type: 'admin_adjustment', reason, actorUid: req.hypeUser.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });
    });
    return res.json({ ok: true, uid: targetUid, delta, balance: balanceAfter });
  } catch (err) {
    if (err.message === 'SALDO_NEGATIVO') return res.status(409).json({ error: 'O ajuste deixaria o saldo negativo.' });
    console.error('[credit adjustment]', err);
    return res.status(500).json({ error: 'Falha ao ajustar créditos.' });
  }
});

app.post('/v1/admin/licenses/grant', requireUser, requireOwnerOrReseller, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const days = Number(req.body?.days);
  const note = String(req.body?.note || '').trim().slice(0, 200);
  if (!email || !ALLOWED_LICENSE_DAYS.has(days)) return res.status(400).json({ error: 'Informe e-mail da conta HYPE e duração 7, 30, 90 ou 365 dias.' });
  const isOwner = req.hypeRole.role === 'owner';
  const cost = isOwner ? 0 : creditCostFor(days);
  if (!isOwner && cost === null) return res.status(503).json({ error: 'O proprietário ainda não configurou LICENSE_CREDIT_COSTS_JSON no servidor.' });
  try {
    const target = await admin.auth().getUserByEmail(email);
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(now.toMillis() + days * 86400000);
    const licenseRef = db.collection('hypeLicenses').doc();
    const entitlementRef = db.collection('hypeSubscriptions').doc(target.uid);
    const walletRef = db.collection('hypeWallets').doc(req.hypeUser.uid);
    await db.runTransaction(async tx => {
      let balanceAfter = null;
      if (!isOwner) {
        const walletSnap = await tx.get(walletRef);
        const before = Number(walletSnap.exists ? walletSnap.data().balance || 0 : 0);
        if (before < cost) throw new Error('CREDITOS_INSUFICIENTES');
        balanceAfter = before - cost;
        tx.set(walletRef, { balance: balanceAfter, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        tx.create(db.collection('hypeCreditLedger').doc(), { uid: req.hypeUser.uid, delta: -cost, balanceAfter, type: 'license_sale', targetUid: target.uid, licenseId: licenseRef.id, createdAt: admin.firestore.FieldValue.serverTimestamp() });
      }
      tx.set(licenseRef, { targetUid: target.uid, targetEmail: email, days, creditCost: cost, status: 'active', createdBy: req.hypeUser.uid, createdByRole: req.hypeRole.role, note, createdAt: now, expiresAt, source: isOwner ? 'owner_grant' : 'reseller_credit' });
      tx.set(entitlementRef, { active: true, provider: 'license', status: 'active', plan: `license_${days}d`, expiryTime: expiresAt.toDate().toISOString(), userId: target.uid, licenseId: licenseRef.id, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    });
    return res.json({ ok: true, licenseId: licenseRef.id, targetUid: target.uid, email, days, expiresAt: expiresAt.toDate().toISOString(), creditCost: cost });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'A pessoa precisa criar uma conta HYPE antes de receber acesso.' });
    if (err.message === 'CREDITOS_INSUFICIENTES') return res.status(409).json({ error: 'Saldo de créditos insuficiente.' });
    console.error('[grant license]', err);
    return res.status(500).json({ error: 'Não foi possível conceder a licença.' });
  }
});

// Teste HYPE de 30 minutos: uma concessao por conta Firebase.

// HYPE: solicitacao de teste pelo cliente, sem liberacao automatica.
app.post('/v1/trials/request', requireUser, async (req, res) => {
  const uid = req.hypeUser.uid;
  const email = String(req.hypeUser.email || '').trim().toLowerCase();
  const requestRef = db.collection('hypeTrialRequests').doc(uid);
  const trialRef = db.collection('hypeTrials').doc(uid);
  const subscriptionRef = db.collection('hypeSubscriptions').doc(uid);

  try {
    const result = await db.runTransaction(async tx => {
      const requestSnap = await tx.get(requestRef);
      const trialSnap = await tx.get(trialRef);
      const subscriptionSnap = await tx.get(subscriptionRef);

      if (trialSnap.exists) return { status: 'trial_used' };

      const subscription = subscriptionSnap.exists ? subscriptionSnap.data() : {};
      const expiry = subscription.expiryTime ? Date.parse(subscription.expiryTime) : 0;

      if (subscription.active && Number.isFinite(expiry) && expiry > Date.now()) {
        return { status: 'already_active' };
      }

      if (requestSnap.exists && requestSnap.data().status === 'pending') {
        return { status: 'pending', createdAt: requestSnap.data().createdAt || null };
      }

      tx.set(requestRef, {
        uid,
        email,
        status: 'pending',
        requestedAt: admin.firestore.FieldValue.serverTimestamp(),
        reviewedAt: null,
        reviewedBy: null
      });

      return { status: 'pending' };
    });

    if (result.status === 'trial_used') {
      return res.status(409).json({ error: 'Esta conta ja utilizou o teste gratuito.', status: result.status });
    }
    if (result.status === 'already_active') {
      return res.status(409).json({ error: 'Esta conta ja possui acesso ativo.', status: result.status });
    }

    return res.status(200).json({
      status: result.status,
      message: 'Solicitacao registrada. Aguarde a avaliacao de um vendedor.'
    });
  } catch (err) {
    console.error('[trial request]', err);
    return res.status(500).json({ error: 'Nao foi possivel registrar a solicitacao.' });
  }
});

// O cliente consulta somente a propria solicitacao.
app.get('/v1/trials/request/me', requireUser, async (req, res) => {
  try {
    const snap = await db.collection('hypeTrialRequests').doc(req.hypeUser.uid).get();
    if (!snap.exists) return res.json({ status: 'none' });

    const data = snap.data();
    return res.json({
      status: data.status || 'pending',
      requestedAt: data.requestedAt?.toDate?.().toISOString() || null,
      reviewedAt: data.reviewedAt?.toDate?.().toISOString() || null
    });
  } catch (err) {
    console.error('[trial request status]', err);
    return res.status(500).json({ error: 'Nao foi possivel consultar a solicitacao.' });
  }
});

// Somente proprietarios e revendedores podem consultar pedidos.
app.get('/v1/admin/trial-requests', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    const snap = await db.collection('hypeTrialRequests')
      .where('status', '==', 'pending')
      .limit(100)
      .get();

    return res.json({
      requests: snap.docs.map(doc => {
        const data = doc.data();
        return {
          uid: doc.id,
          email: data.email || null,
          status: data.status,
          requestedAt: data.requestedAt?.toDate?.().toISOString() || null
        };
      })
    });
  } catch (err) {
    console.error('[admin trial requests]', err);
    return res.status(500).json({ error: 'Nao foi possivel listar as solicitacoes.' });
  }
});

// Decisao administrativa: approve ou reject.
app.post('/v1/admin/trial-requests/:uid/decision', requireUser, requireOwnerOrReseller, async (req, res) => {
  const targetUid = String(req.params.uid || '').trim();
  const action = String(req.body?.action || '').trim().toLowerCase();

  if (!targetUid || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'Informe um UID valido e a decisao approve ou reject.' });
  }

  const requestRef = db.collection('hypeTrialRequests').doc(targetUid);
  const trialRef = db.collection('hypeTrials').doc(targetUid);
  const subscriptionRef = db.collection('hypeSubscriptions').doc(targetUid);

  try {
    const result = await db.runTransaction(async tx => {
      const requestSnap = await tx.get(requestRef);
      const trialSnap = await tx.get(trialRef);
      const subscriptionSnap = await tx.get(subscriptionRef);

      if (!requestSnap.exists) return { status: 'not_found' };
      if (requestSnap.data().status !== 'pending') return { status: 'not_pending' };

      const reviewedAt = admin.firestore.FieldValue.serverTimestamp();

      if (action === 'reject') {
        tx.set(requestRef, {
          status: 'rejected',
          reviewedBy: req.hypeUser.uid,
          reviewedAt
        }, { merge: true });

        return { status: 'rejected' };
      }

      if (trialSnap.exists) return { status: 'trial_used' };

      const current = subscriptionSnap.exists ? subscriptionSnap.data() : {};
      const currentExpiry = current.expiryTime ? Date.parse(current.expiryTime) : 0;

      if (current.active && Number.isFinite(currentExpiry) && currentExpiry > Date.now()) {
        return { status: 'already_active' };
      }

      const nowMs = Date.now();
      const expiresAt = admin.firestore.Timestamp.fromMillis(nowMs + 30 * 60 * 1000);

      tx.create(trialRef, {
        uid: targetUid,
        email: requestSnap.data().email || null,
        issuedBy: req.hypeUser.uid,
        issuedByRole: req.hypeRole.role,
        createdAt: admin.firestore.Timestamp.fromMillis(nowMs),
        expiresAt
      });

      tx.set(subscriptionRef, {
        active: true,
        provider: 'trial',
        status: 'active',
        plan: 'trial_30m',
        expiryTime: expiresAt.toDate().toISOString(),
        userId: targetUid,
        trialId: targetUid,
        updatedAt: reviewedAt
      }, { merge: true });

      tx.set(requestRef, {
        status: 'approved',
        reviewedBy: req.hypeUser.uid,
        reviewedAt
      }, { merge: true });

      return { status: 'approved', expiryTime: expiresAt.toDate().toISOString() };
    });

    if (result.status === 'not_found') {
      return res.status(404).json({ error: 'Solicitacao nao encontrada.' });
    }
    if (result.status === 'not_pending') {
      return res.status(409).json({ error: 'Esta solicitacao ja foi analisada.' });
    }
    if (result.status === 'trial_used') {
      return res.status(409).json({ error: 'Esta conta ja utilizou o teste gratuito.' });
    }
    if (result.status === 'already_active') {
      return res.status(409).json({ error: 'Esta conta ja possui acesso ativo.' });
    }

    return res.json(result);
  } catch (err) {
    console.error('[trial decision]', err);
    return res.status(500).json({ error: 'Nao foi possivel processar a decisao.' });
  }
});
app.post('/v1/admin/trials/grant', requireUser, requireOwnerOrReseller, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const note = String(req.body?.note || '').trim().slice(0, 200);

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Informe o e-mail da conta HYPE.' });
  }

  try {
    const target = await admin.auth().getUserByEmail(email);
    const nowMs = Date.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(nowMs + 30 * 60 * 1000);
    const trialRef = db.collection('hypeTrials').doc(target.uid);
    const subscriptionRef = db.collection('hypeSubscriptions').doc(target.uid);

    const result = await db.runTransaction(async tx => {
      const trialSnap = await tx.get(trialRef);
      const subscriptionSnap = await tx.get(subscriptionRef);

      if (trialSnap.exists) return { status: 'trial_used' };

      const current = subscriptionSnap.exists ? subscriptionSnap.data() : {};
      const currentExpiry = current.expiryTime ? Date.parse(current.expiryTime) : 0;

      if (current.active && Number.isFinite(currentExpiry) && currentExpiry > nowMs) {
        return { status: 'already_active' };
      }

      tx.create(trialRef, {
        uid: target.uid,
        email: target.email || email,
        issuedBy: req.hypeUser.uid,
        issuedByRole: req.hypeRole.role,
        note,
        createdAt: admin.firestore.Timestamp.fromMillis(nowMs),
        expiresAt
      });

      tx.set(subscriptionRef, {
        active: true,
        provider: 'trial',
        status: 'active',
        plan: 'trial_30m',
        expiryTime: expiresAt.toDate().toISOString(),
        userId: target.uid,
        trialId: target.uid,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return {
        status: 'granted',
        expiryTime: expiresAt.toDate().toISOString()
      };
    });

    if (result.status === 'trial_used') {
      return res.status(409).json({
        error: 'Esta conta ja utilizou o teste gratuito.'
      });
    }

    if (result.status === 'already_active') {
      return res.status(409).json({
        error: 'Esta conta ja possui um acesso ativo.'
      });
    }

    return res.status(201).json({
      ok: true,
      message: 'Teste de 30 minutos concedido.',
      email: target.email || email,
      expiryTime: result.expiryTime
    });
  } catch (err) {
    if (err.code === 'auth/user-not-found') {
      return res.status(404).json({
        error: 'Conta HYPE nao encontrada. O usuario precisa se cadastrar primeiro.'
      });
    }

    console.error('[trial grant]', err);
    return res.status(500).json({
      error: 'Nao foi possivel conceder o teste.'
    });
  }
});
app.post('/v1/credits/checkout', requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Checkout de créditos não configurado.' });
  const pack = String(req.body?.pack || '');
  const packs = { '100': { credits: 100, price: process.env.STRIPE_CREDIT_PACK_100 }, '500': { credits: 500, price: process.env.STRIPE_CREDIT_PACK_500 }, '1000': { credits: 1000, price: process.env.STRIPE_CREDIT_PACK_1000 } };
  const selected = packs[pack];
  if (!selected || !selected.price) return res.status(400).json({ error: 'Pacote inexistente ou ainda não configurado.' });
  try {
    const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: selected.price, quantity: 1 }], client_reference_id: req.hypeUser.uid,
      metadata: { kind: 'credit_pack', firebaseUid: req.hypeUser.uid, credits: String(selected.credits), pack },
      success_url: process.env.CHECKOUT_SUCCESS_URL, cancel_url: process.env.CHECKOUT_CANCEL_URL, payment_method_types: ['card', 'pix'] });
    return res.json({ url: session.url });
  } catch (err) {
    console.error('[credit checkout]', err);
    return res.status(500).json({ error: 'Não foi possível iniciar a compra de créditos.' });
  }
});

app.get('/v1/admin/ledger', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    let q = db.collection('hypeCreditLedger').orderBy('createdAt', 'desc').limit(100);
    if (req.hypeRole.role !== 'owner') q = q.where('uid', '==', req.hypeUser.uid).orderBy('createdAt', 'desc').limit(100);
    const snap = await q.get();
    return res.json({ entries: snap.docs.map(d => ({ id: d.id, ...d.data(), createdAt: d.data().createdAt?.toDate?.().toISOString() || null })) });
  } catch (err) {
    console.error('[ledger]', err);
    return res.status(500).json({ error: 'Não foi possível consultar o extrato.' });
  }
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => console.log(`HYPE subscription backend listening on :${port}`));
