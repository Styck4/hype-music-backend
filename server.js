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
  if (!process.env[key]) console.warn(`[config] ${key} nÃ£o estÃ¡ configurada; rotas dependentes nÃ£o funcionarÃ£o.`);
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
  return callback(new Error('Origem nÃ£o permitida por CORS'));
} }));

// Stripe requires the untouched raw request body to verify webhook signatures.
app.post('/v1/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe webhook nÃ£o configurado');
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return res.status(400).send(`Webhook invÃ¡lido: ${err.message}`); }

  try {
    if (['checkout.session.completed', 'checkout.session.async_payment_succeeded'].includes(event.type)) {
      const session = event.data.object;
      // One-time credit purchases are fulfilled only from a verified Stripe webhook.
      if (session.metadata?.kind === 'credit_pack' && session.payment_status === 'paid') {
        const uid = session.client_reference_id || session.metadata?.firebaseUid;
        const credits = Number(session.metadata?.credits || 0);
        const declaredTotal = Number(session.metadata?.totalCents || 0);
        if (!uid || ![100, 500, 1000].includes(credits) ||
            session.currency !== 'brl' || Number(session.amount_total) !== declaredTotal ||
            !Number.isSafeInteger(declaredTotal) || declaredTotal < 100) {
          throw new Error('Pacote de créditos inválido no webhook.');
        }
        // Checkout Session is the idempotency key across all success event types.
        const eventRef = db.collection('hypeProcessedPayments').doc(session.id);
        await db.runTransaction(async tx => {
          const processed = await tx.get(eventRef);
          if (processed.exists) return; // idempotÃªncia contra reentrega do webhook
          const walletRef = db.collection('hypeWallets').doc(uid);
          const wallet = await tx.get(walletRef);
          const before = Number(wallet.exists ? wallet.data().balance || 0 : 0);
          tx.set(walletRef, { balance: before + credits, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
          tx.create(db.collection('hypeCreditLedger').doc(), {
            uid, delta: credits, balanceAfter: before + credits, type: 'purchase', provider: 'stripe',
            providerEventId: event.id, checkoutSessionId: session.id, createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
          tx.create(eventRef, { type: 'credit_pack', uid, credits, stripeEventId: event.id,
            checkoutSessionId: session.id, processedAt: admin.firestore.FieldValue.serverTimestamp() });
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
  if (!match) return res.status(401).json({ error: 'AutenticaÃ§Ã£o HYPE obrigatÃ³ria.' });
  try {
    req.hypeUser = await admin.auth().verifyIdToken(match[1]);
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'SessÃ£o invÃ¡lida ou expirada. Entre novamente.' });
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
    return res.status(500).json({ error: 'NÃ£o foi possÃ­vel consultar a assinatura.' });
  }
});

app.post('/v1/subscriptions/google/verify', requireUser, async (req, res) => {
  const { purchaseToken, productId, packageName } = req.body || {};
  if (!purchaseToken || productId !== (process.env.GOOGLE_PLAY_PRODUCT_ID || 'hype_premium')) {
    return res.status(400).json({ active: false, error: 'Token ou produto invÃ¡lido.' });
  }
  if (packageName !== process.env.GOOGLE_PLAY_PACKAGE_NAME) {
    return res.status(400).json({ active: false, error: 'Pacote Android nÃ£o corresponde.' });
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
    return res.status(502).json({ active: false, error: 'NÃ£o foi possÃ­vel verificar a compra com o Google Play.' });
  }
});

app.post('/v1/subscriptions/stripe/portal', requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe nÃ£o configurado.' });
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
    return res.status(500).json({ error: 'NÃ£o foi possÃ­vel abrir o gerenciamento da assinatura.' });
  }
});

app.post('/v1/subscriptions/stripe/checkout', requireUser, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe nÃ£o configurado.' });
  const plan = req.body?.plan;
  const price = plan === 'monthly' ? process.env.STRIPE_PRICE_MONTHLY : plan === 'annual' ? process.env.STRIPE_PRICE_ANNUAL : null;
  if (!price) return res.status(400).json({ error: 'Plano Stripe invÃ¡lido ou ainda nÃ£o configurado.' });
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
    return res.status(500).json({ error: 'NÃ£o foi possÃ­vel abrir o checkout.' });
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
      if (status !== 'active' || !roles.includes(role)) return res.status(403).json({ error: 'PermissÃ£o insuficiente.' });
      req.hypeRole = { role, data: snap.data() };
      return next();
    } catch (err) {
      console.error('[role check]', err);
      return res.status(500).json({ error: 'NÃ£o foi possÃ­vel validar permissÃµes.' });
    }
  };
}
const requireOwner = (req, res, next) => requireRole(['owner'])(req, res, next);
const requireOwnerOrReseller = (req, res, next) => requireRole(['owner', 'reseller'])(req, res, next);

// === HYPE MUSIC: customer management and owner-controlled commercial settings ===
const customerRef = uid => db.collection('hypeClients').doc(uid);
async function assertCanManageClient(req, uid) {
  if (req.hypeRole.role === 'owner') return true;
  const snap = await customerRef(uid).get();
  if (snap.exists && snap.data().resellerUid === req.hypeUser.uid && snap.data().deleted !== true) return true;
  // Backward compatibility: customers previously licensed by this reseller.
  const legacy = await db.collection('hypeLicenses')
    .where('targetUid', '==', uid).limit(50).get();
  return legacy.docs.some(doc => doc.data().createdBy === req.hypeUser.uid);
}

function validEmail(value) {
  return typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

async function issueLicenseForUser({ target, actor, actorRole, days, note }) {
  if (!ALLOWED_LICENSE_DAYS.has(days)) throw new Error('DURACAO_INVALIDA');
  const isOwner = actorRole === 'owner';
  const cost = isOwner ? 0 : await creditCostFor(days);
  if (!isOwner && cost === null) throw new Error('CUSTO_NAO_CONFIGURADO');
  const now = admin.firestore.Timestamp.now();
  const licenseRef = db.collection('hypeLicenses').doc();
  const entitlementRef = db.collection('hypeSubscriptions').doc(target.uid);
  const walletRef = db.collection('hypeWallets').doc(actor);
  let expiresAt;
  await db.runTransaction(async tx => {
    const entitlementSnap = await tx.get(entitlementRef);
    const walletSnap = isOwner ? null : await tx.get(walletRef);
    const current = entitlementSnap.exists ? entitlementSnap.data() : {};
    const parsed = current.expiryTime ? Date.parse(current.expiryTime) : 0;
    const base = Number.isFinite(parsed) && parsed > now.toMillis() ? parsed : now.toMillis();
    expiresAt = admin.firestore.Timestamp.fromMillis(base + days * 86400000);
    let balanceAfter = null;
    if (!isOwner) {
      const before = Number(walletSnap.exists ? walletSnap.data().balance || 0 : 0);
      if (before < cost) throw new Error('CREDITOS_INSUFICIENTES');
      balanceAfter = before - cost;
      tx.set(walletRef, { balance: balanceAfter, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      tx.create(db.collection('hypeCreditLedger').doc(), {
        uid: actor, delta: -cost, balanceAfter, type: 'license_sale',
        targetUid: target.uid, licenseId: licenseRef.id,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    tx.set(licenseRef, {
      targetUid: target.uid, targetEmail: target.email, days, creditCost: cost,
      status: 'active', createdBy: actor, createdByRole: actorRole, note: note || '',
      createdAt: now, expiresAt, source: isOwner ? 'owner_grant' : 'reseller_credit'
    });
    tx.set(entitlementRef, {
      active: true, provider: 'license', status: 'active', plan: `license_${days}d`,
      expiryTime: expiresAt.toDate().toISOString(), userId: target.uid,
      licenseId: licenseRef.id, updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    tx.set(customerRef(target.uid), {
      uid: target.uid, email: target.email || null,
      ...(isOwner ? {} : { resellerUid: actor }),
      createdBy: isOwner ? 'owner' : actor,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deleted: false, status: 'active'
    }, { merge: true });
  });
  return { licenseId: licenseRef.id, targetUid: target.uid, email: target.email, days,
    expiresAt: expiresAt.toDate().toISOString(), creditCost: cost };
}

// Create a Firebase Auth account and issue the selected license in one guided workflow.
// The returned password-setup link must be delivered privately to the customer by the operator.
app.post('/v1/admin/clients', requireUser, requireOwnerOrReseller, async (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 100);
  const email = String(req.body?.email || '').trim().toLowerCase();
  const days = Number(req.body?.days);
  const note = String(req.body?.note || '').trim().slice(0, 200);
  if (!name || !validEmail(email) || !ALLOWED_LICENSE_DAYS.has(days)) {
    return res.status(400).json({ error: 'Informe nome, e-mail válido e duração de 30, 90 ou 120 dias.' });
  }
  let createdUser = null;
  try {
    createdUser = await admin.auth().createUser({ email, displayName: name, emailVerified: false, disabled: false });
    const actionCodeSettings = process.env.FIREBASE_PASSWORD_SETUP_URL
      ? { url: process.env.FIREBASE_PASSWORD_SETUP_URL, handleCodeInApp: false }
      : undefined;
    const passwordSetupLink = await admin.auth().generatePasswordResetLink(email, actionCodeSettings);
    const result = await issueLicenseForUser({
      target: { uid: createdUser.uid, email: createdUser.email },
      actor: req.hypeUser.uid, actorRole: req.hypeRole.role, days, note
    });
    await customerRef(createdUser.uid).set({
      uid: createdUser.uid, name, email, resellerUid: req.hypeRole.role === 'reseller' ? req.hypeUser.uid : null,
      createdBy: req.hypeUser.uid, status: 'active', deleted: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return res.status(201).json({ ok: true, ...result, name, passwordSetupLink,
      message: 'Conta criada e licença emitida. Envie o link de definição de senha ao cliente por canal privado.' });
  } catch (err) {
    if (createdUser?.uid) {
      // If issuance failed, disable the orphaned account; never silently leave an unlicensed login.
      try { await admin.auth().deleteUser(createdUser.uid); } catch (_) {}
      try { await customerRef(createdUser.uid).delete(); } catch (_) {}
    }
    if (err.code === 'auth/email-already-exists') return res.status(409).json({ error: 'Este e-mail já possui uma conta HYPE. Use a opção de vincular cliente existente.' });
    if (err.message === 'CREDITOS_INSUFICIENTES') return res.status(409).json({ error: 'Saldo de créditos insuficiente.' });
    if (err.message === 'DURACAO_INVALIDA') return res.status(400).json({ error: 'Duração inválida.' });
    console.error('[create client]', err);
    return res.status(500).json({ error: 'Não foi possível criar o cliente e emitir a licença.' });
  }
});

// Attach an already registered account to the current reseller/owner and issue a license.
app.post('/v1/admin/clients/link', requireUser, requireOwnerOrReseller, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const days = Number(req.body?.days);
  const note = String(req.body?.note || '').trim().slice(0, 200);
  if (!validEmail(email) || !ALLOWED_LICENSE_DAYS.has(days)) return res.status(400).json({ error: 'Informe e-mail válido e duração permitida.' });
  try {
    const target = await admin.auth().getUserByEmail(email);
    const existing = await customerRef(target.uid).get();
    if (req.hypeRole.role === 'reseller' && existing.exists && existing.data().resellerUid && existing.data().resellerUid !== req.hypeUser.uid) {
      return res.status(403).json({ error: 'Este cliente pertence a outro revendedor.' });
    }
    const result = await issueLicenseForUser({ target, actor: req.hypeUser.uid, actorRole: req.hypeRole.role, days, note });
    await customerRef(target.uid).set({
      uid: target.uid, email, resellerUid: req.hypeRole.role === 'reseller' ? req.hypeUser.uid : (existing.data()?.resellerUid || null),
      createdBy: existing.data()?.createdBy || req.hypeUser.uid, status: 'active', deleted: false,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return res.json({ ok: true, ...result });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Conta HYPE não encontrada.' });
    if (err.message === 'CREDITOS_INSUFICIENTES') return res.status(409).json({ error: 'Saldo de créditos insuficiente.' });
    console.error('[link client]', err);
    return res.status(500).json({ error: 'Não foi possível vincular o cliente.' });
  }
});

app.get('/v1/admin/clients', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    const isOwner = req.hypeRole.role === 'owner';
    const snap = await (isOwner
      ? db.collection('hypeClients').limit(1000).get()
      : db.collection('hypeClients').where('resellerUid', '==', req.hypeUser.uid).limit(1000).get());
    const visibleDocs = snap.docs.filter(doc => doc.data().deleted !== true);
    const clients = await Promise.all(visibleDocs.map(async doc => {
      const c = doc.data();
      const ent = await db.collection('hypeSubscriptions').doc(doc.id).get();
      const e = ent.exists ? ent.data() : {};
      return { uid: doc.id, name: c.name || '', email: c.email || '', status: c.status || 'active',
        expiryTime: e.expiryTime || null, active: Boolean(e.active && e.expiryTime && Date.parse(e.expiryTime) > Date.now()),
        resellerUid: c.resellerUid || null };
    }));
    return res.json({ clients });
  } catch (err) {
    console.error('[clients list]', err);
    return res.status(500).json({ error: 'Não foi possível listar clientes.' });
  }
});

app.patch('/v1/admin/clients/:uid', requireUser, requireOwnerOrReseller, async (req, res) => {
  const uid = String(req.params.uid || '');
  try {
    if (!(await assertCanManageClient(req, uid))) return res.status(403).json({ error: 'Você não pode alterar este cliente.' });
    const snap = await admin.auth().getUser(uid);
    const patch = {};
    if (req.body?.name !== undefined) patch.displayName = String(req.body.name).trim().slice(0, 100);
    if (req.body?.email !== undefined) {
      const email = String(req.body.email).trim().toLowerCase();
      if (!validEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });
      patch.email = email;
      patch.emailVerified = false;
    }
    if (Object.keys(patch).length) await admin.auth().updateUser(uid, patch);
    const updated = await admin.auth().getUser(uid);
    await customerRef(uid).set({ name: updated.displayName || '', email: updated.email || '',
      updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.json({ ok: true, uid, name: updated.displayName || '', email: updated.email || '' });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Cliente não encontrado.' });
    console.error('[client update]', err);
    return res.status(500).json({ error: 'Não foi possível atualizar o cliente.' });
  }
});

app.post('/v1/admin/clients/:uid/status', requireUser, requireOwnerOrReseller, async (req, res) => {
  const uid = String(req.params.uid || '');
  const status = String(req.body?.status || '');
  if (!['active', 'suspended'].includes(status)) return res.status(400).json({ error: 'Status inválido.' });
  try {
    if (!(await assertCanManageClient(req, uid))) return res.status(403).json({ error: 'Você não pode alterar este cliente.' });
    await admin.auth().updateUser(uid, { disabled: status === 'suspended' });
    if (status === 'suspended') await admin.auth().revokeRefreshTokens(uid);
    await customerRef(uid).set({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    const entitlementRef = db.collection('hypeSubscriptions').doc(uid);
    const entitlementSnap = await entitlementRef.get();
    if (status === 'suspended') {
      await entitlementRef.set({ active: false, status: 'suspended', updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    } else if (entitlementSnap.exists) {
      const entitlement = entitlementSnap.data();
      const stillValid = entitlement.expiryTime && Date.parse(entitlement.expiryTime) > Date.now();
      await entitlementRef.set({ active: Boolean(stillValid), status: stillValid ? 'active' : 'expired',
        updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    }
    return res.json({ ok: true, uid, status });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Cliente não encontrado.' });
    console.error('[client status]', err);
    return res.status(500).json({ error: 'Não foi possível alterar o status.' });
  }
});

app.delete('/v1/admin/clients/:uid', requireUser, requireOwnerOrReseller, async (req, res) => {
  const uid = String(req.params.uid || '');
  try {
    if (!(await assertCanManageClient(req, uid))) return res.status(403).json({ error: 'Você não pode excluir este cliente.' });
    await admin.auth().updateUser(uid, { disabled: true });
    await admin.auth().revokeRefreshTokens(uid);
    await customerRef(uid).set({ status: 'deleted', deleted: true, deletedAt: admin.firestore.FieldValue.serverTimestamp(), deletedBy: req.hypeUser.uid }, { merge: true });
    await db.collection('hypeSubscriptions').doc(uid).set({ active: false, status: 'deleted', updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await db.collection('hypeLicenses').where('targetUid', '==', uid).get().then(s => Promise.all(s.docs.map(d => d.ref.set({ status: 'revoked', revokedAt: admin.firestore.FieldValue.serverTimestamp(), revokedBy: req.hypeUser.uid }, { merge: true }))));
    return res.json({ ok: true, uid, status: 'deleted', message: 'Cliente desativado. O histórico financeiro foi preservado.' });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Cliente não encontrado.' });
    console.error('[client delete]', err);
    return res.status(500).json({ error: 'Não foi possível excluir o cliente.' });
  }
});

// Owner-controlled price book. Prices are in BRL cents; never accepted from the browser during checkout.
const DEFAULT_CREDIT_PACK_PRICES = { "100": 35000, "500": 150000, "1000": 300000 };
app.get('/v1/admin/pricing', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    const snap = await db.collection('hypeSettings').doc('commercial').get();
    const settings = snap.exists ? snap.data() : {};
    return res.json({ packs: settings.packPrices || DEFAULT_CREDIT_PACK_PRICES,
      licenseCosts: settings.licenseCosts || JSON.parse(process.env.LICENSE_CREDIT_COSTS_JSON || '{"30":1,"90":3,"120":4}'),
      canEdit: req.hypeRole.role === 'owner' });
  } catch (err) {
    console.error('[pricing get]', err);
    return res.status(500).json({ error: 'Não foi possível consultar preços.' });
  }
});
app.put('/v1/admin/pricing', requireUser, requireOwner, async (req, res) => {
  const packs = req.body?.packs || {};
  const normalized = {};
  for (const count of ['100', '500', '1000']) {
    const value = Number(packs[count]);
    if (!Number.isSafeInteger(value) || value < 100 || value > 100000000) {
      return res.status(400).json({ error: `Preço inválido para pacote ${count}. Informe centavos de BRL.` });
    }
    normalized[count] = value;
  }
  const rawCosts = req.body?.licenseCosts || {};
  const licenseCosts = {};
  for (const days of ['30', '90', '120']) {
    const cost = Number(rawCosts[days]);
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > 100000) {
      return res.status(400).json({ error: `Custo inválido para licença de ${days} dias.` });
    }
    licenseCosts[days] = cost;
  }
  await db.collection('hypeSettings').doc('commercial').set({
    packPrices: normalized, licenseCosts,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(), updatedBy: req.hypeUser.uid
  }, { merge: true });
  return res.json({ ok: true, packs: normalized, licenseCosts });
});

// Create reseller accounts directly from the owner panel; send password setup link manually.
app.post('/v1/admin/resellers/create', requireUser, requireOwner, async (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 100);
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!name || !validEmail(email)) return res.status(400).json({ error: 'Informe nome e e-mail válido.' });
  let created = null;
  try {
    created = await admin.auth().createUser({ email, displayName: name, emailVerified: false, disabled: false });
    await db.collection('hypeRoles').doc(created.uid).set({
      role: 'reseller', status: 'active', email, name,
      createdBy: req.hypeUser.uid, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection('hypeWallets').doc(created.uid).set({ balance: 0, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    const passwordSetupLink = await admin.auth().generatePasswordResetLink(email,
      process.env.FIREBASE_PASSWORD_SETUP_URL ? { url: process.env.FIREBASE_PASSWORD_SETUP_URL, handleCodeInApp: false } : undefined);
    return res.status(201).json({ ok: true, uid: created.uid, email, name, passwordSetupLink });
  } catch (err) {
    if (created?.uid) {
      try { await admin.auth().deleteUser(created.uid); } catch (_) {}
      try { await db.collection('hypeRoles').doc(created.uid).delete(); } catch (_) {}
      try { await db.collection('hypeWallets').doc(created.uid).delete(); } catch (_) {}
    }
    if (err.code === 'auth/email-already-exists') return res.status(409).json({ error: 'Este e-mail já possui uma conta HYPE.' });
    console.error('[create reseller account]', err);
    return res.status(500).json({ error: 'Não foi possível criar o revendedor.' });
  }
});

const ALLOWED_LICENSE_DAYS = new Set([30, 90, 120]);
async function creditCostFor(days) {
  try {
    const snap = await db.collection('hypeSettings').doc('commercial').get();
    const configured = snap.exists && snap.data().licenseCosts
      ? snap.data().licenseCosts
      : JSON.parse(process.env.LICENSE_CREDIT_COSTS_JSON || '{"30":1,"90":3,"120":4}');
    const n = Number(configured[String(days)]);
    return Number.isSafeInteger(n) && n > 0 && n <= 100000 ? n : null;
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
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail vÃ¡lido de uma conta HYPE jÃ¡ cadastrada.' });
  try {
    const target = await admin.auth().getUserByEmail(email);
    const ref = db.collection('hypeRoles').doc(target.uid);
    const existing = await ref.get();
    if (existing.exists && existing.data().role === 'owner') return res.status(409).json({ error: 'A conta proprietÃ¡ria nÃ£o pode ser revendedora.' });
    await ref.set({ role: 'reseller', status: 'active', email, createdBy: req.hypeUser.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.json({ ok: true, uid: target.uid, email, role: 'reseller' });
  } catch (err) {
    if (err.code === 'auth/user-not-found') return res.status(404).json({ error: 'Crie primeiro a conta HYPE desse usuÃ¡rio.' });
    console.error('[create reseller]', err);
    return res.status(500).json({ error: 'NÃ£o foi possÃ­vel criar revendedor.' });
  }
});

app.post('/v1/admin/resellers/:uid/status', requireUser, requireOwner, async (req, res) => {
  const status = req.body?.status;
  if (!['active', 'suspended'].includes(status)) return res.status(400).json({ error: 'Status invÃ¡lido.' });
  const ref = db.collection('hypeRoles').doc(req.params.uid);
  const snap = await ref.get();
  if (!snap.exists || snap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor nÃ£o encontrado.' });
  await ref.set({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp(), updatedBy: req.hypeUser.uid }, { merge: true });
  return res.json({ ok: true, uid: req.params.uid, status });
});


app.patch('/v1/admin/resellers/:uid', requireUser, requireOwner, async (req, res) => {
  const uid = String(req.params.uid || '');
  const patch = {};
  if (req.body?.name !== undefined) patch.displayName = String(req.body.name).trim().slice(0, 100);
  if (req.body?.email !== undefined) {
    const email = String(req.body.email).trim().toLowerCase();
    if (!validEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });
    patch.email = email; patch.emailVerified = false;
  }
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nenhuma alteração informada.' });
  try {
    const roleRef = db.collection('hypeRoles').doc(uid);
    const roleSnap = await roleRef.get();
    if (!roleSnap.exists || roleSnap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor não encontrado.' });
    const updated = await admin.auth().updateUser(uid, patch);
    await roleRef.set({ name: updated.displayName || '', email: updated.email || '',
      updatedAt: admin.firestore.FieldValue.serverTimestamp(), updatedBy: req.hypeUser.uid }, { merge: true });
    return res.json({ ok: true, uid, name: updated.displayName || '', email: updated.email || '' });
  } catch (err) {
    console.error('[reseller update]', err);
    return res.status(500).json({ error: 'Não foi possível atualizar o revendedor.' });
  }
});

app.delete('/v1/admin/resellers/:uid', requireUser, requireOwner, async (req, res) => {
  const uid = String(req.params.uid || '');
  try {
    const roleRef = db.collection('hypeRoles').doc(uid);
    const roleSnap = await roleRef.get();
    if (!roleSnap.exists || roleSnap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor não encontrado.' });
    await admin.auth().updateUser(uid, { disabled: true });
    await admin.auth().revokeRefreshTokens(uid);
    await roleRef.set({ status: 'suspended', deleted: true, deletedAt: admin.firestore.FieldValue.serverTimestamp(),
      deletedBy: req.hypeUser.uid }, { merge: true });
    return res.json({ ok: true, uid, status: 'suspended', message: 'Revendedor desativado. Carteira, clientes e histórico foram preservados.' });
  } catch (err) {
    console.error('[reseller delete]', err);
    return res.status(500).json({ error: 'Não foi possível desativar o revendedor.' });
  }
});

app.post('/v1/admin/credits/adjust', requireUser, requireOwner, async (req, res) => {
  const targetUid = String(req.body?.uid || '').trim();
  const delta = Number(req.body?.delta);
  const reason = String(req.body?.reason || '').trim().slice(0, 200);
  if (!targetUid || !Number.isSafeInteger(delta) || delta === 0 || Math.abs(delta) > 100000 || !reason) return res.status(400).json({ error: 'Informe UID, ajuste inteiro nÃ£o zero e motivo.' });
  try {
    const roleSnap = await db.collection('hypeRoles').doc(targetUid).get();
    if (!roleSnap.exists || roleSnap.data().role !== 'reseller') return res.status(404).json({ error: 'Revendedor nÃ£o encontrado.' });
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
    return res.status(500).json({ error: 'Falha ao ajustar crÃ©ditos.' });
  }
});

app.post('/v1/admin/licenses/grant', requireUser, requireOwnerOrReseller, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const days = Number(req.body?.days);
  const note = String(req.body?.note || '').trim().slice(0, 200);

  if (!email || !ALLOWED_LICENSE_DAYS.has(days)) {
    return res.status(400).json({
      error: 'Informe e-mail e duração de 30, 90 ou 120 dias.'
    });
  }

  const isOwner = req.hypeRole.role === 'owner';
  const cost = isOwner ? 0 : await creditCostFor(days);

  if (!isOwner && cost === null) {
    return res.status(503).json({
      error: 'LICENSE_CREDIT_COSTS_JSON não configurado corretamente.'
    });
  }

  try {
    const target = await admin.auth().getUserByEmail(email);
    if (!isOwner && !(await assertCanManageClient(req, target.uid))) {
      return res.status(403).json({ error: 'Este cliente não está vinculado à sua carteira de clientes. Cadastre ou vincule o cliente primeiro.' });
    }
    const now = admin.firestore.Timestamp.now();

    const licenseRef = db.collection('hypeLicenses').doc();
    const entitlementRef = db.collection('hypeSubscriptions').doc(target.uid);
    const walletRef = db.collection('hypeWallets').doc(req.hypeUser.uid);

    let expiresAt = null;

    await db.runTransaction(async tx => {
      // Todas as leituras acontecem antes das escritas.
      const entitlementSnap = await tx.get(entitlementRef);

      let walletSnap = null;

      if (!isOwner) {
        walletSnap = await tx.get(walletRef);
      }

      // Preserva o vencimento futuro do cliente.
      const entitlement = entitlementSnap.exists
        ? entitlementSnap.data()
        : {};

      const rawExpiry = entitlement.expiryTime;

      let currentExpiry = 0;

      if (rawExpiry && typeof rawExpiry.toDate === 'function') {
        currentExpiry = rawExpiry.toDate().getTime();
      } else if (rawExpiry) {
        currentExpiry = Date.parse(rawExpiry);
      }

      const baseTime = Number.isFinite(currentExpiry) &&
        currentExpiry > now.toMillis()
          ? currentExpiry
          : now.toMillis();

      expiresAt = admin.firestore.Timestamp.fromMillis(
        baseTime + days * 86400000
      );

      let balanceAfter = null;

      if (!isOwner) {
        const before = Number(
          walletSnap.exists ? walletSnap.data().balance || 0 : 0
        );

        if (before < cost) {
          throw new Error('CREDITOS_INSUFICIENTES');
        }

        balanceAfter = before - cost;

        tx.set(walletRef, {
          balance: balanceAfter,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        tx.create(db.collection('hypeCreditLedger').doc(), {
          uid: req.hypeUser.uid,
          delta: -cost,
          balanceAfter,
          type: 'license_sale',
          targetUid: target.uid,
          licenseId: licenseRef.id,
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }

      tx.set(licenseRef, {
        targetUid: target.uid,
        targetEmail: email,
        days,
        creditCost: cost,
        status: 'active',
        createdBy: req.hypeUser.uid,
        createdByRole: req.hypeRole.role,
        note,
        createdAt: now,
        expiresAt,
        source: isOwner ? 'owner_grant' : 'reseller_credit'
      });

      tx.set(entitlementRef, {
        active: true,
        provider: 'license',
        status: 'active',
        plan: `license_${days}d`,
        expiryTime: expiresAt.toDate().toISOString(),
        userId: target.uid,
        licenseId: licenseRef.id,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    });

    return res.json({
      ok: true,
      licenseId: licenseRef.id,
      targetUid: target.uid,
      email,
      days,
      expiresAt: expiresAt.toDate().toISOString(),
      creditCost: cost
    });

  } catch (err) {
    if (err.code === 'auth/user-not-found') {
      return res.status(404).json({
        error: 'A pessoa precisa criar uma conta HYPE antes de receber acesso.'
      });
    }

    if (err.message === 'CREDITOS_INSUFICIENTES') {
      return res.status(409).json({
        error: 'Saldo de créditos insuficiente.'
      });
    }

    console.error('[grant license]', err);

    return res.status(500).json({
      error: 'Não foi possível conceder a licença.'
    });
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
    let query = db.collection('hypeTrialRequests').where('status', '==', 'pending');
    const snap = await query.limit(200).get();
    const visibleDocs = req.hypeRole.role === 'owner' ? snap.docs : await Promise.all(
      snap.docs.map(async doc => ({ doc, client: await customerRef(doc.id).get() }))
    ).then(rows => rows.filter(x => x.client.exists && x.client.data().resellerUid === req.hypeUser.uid).map(x => x.doc));

    return res.json({
      requests: visibleDocs.map(doc => {
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

  if (req.hypeRole.role === 'reseller' && !(await assertCanManageClient(req, targetUid))) {
    return res.status(403).json({ error: 'Esta solicitação não pertence à sua carteira.' });
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
    if (req.hypeRole.role === 'reseller' && !(await assertCanManageClient(req, target.uid))) {
      return res.status(403).json({ error: 'Este cliente não pertence à sua carteira.' });
    }
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
app.post('/v1/credits/checkout', requireUser, requireOwnerOrReseller, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: 'Checkout de creditos nao configurado.' });
  }

  const credits = Number(req.body?.credits ?? req.body?.quantity ?? req.body?.pack);
  if (![100, 500, 1000].includes(credits)) {
    return res.status(400).json({ error: 'Escolha um pacote de 100, 500 ou 1.000 créditos.' });
  }

  const priceSnap = await db.collection('hypeSettings').doc('commercial').get();
  const packPrices = priceSnap.exists && priceSnap.data().packPrices
    ? priceSnap.data().packPrices : DEFAULT_CREDIT_PACK_PRICES;
  const totalCents = Number(packPrices[String(credits)]);
  if (!Number.isSafeInteger(totalCents) || totalCents < 100) {
    return res.status(503).json({ error: 'Preço deste pacote não está configurado pelo proprietário.' });
  }
  const unitPriceCents = Math.round(totalCents / credits);

  if (!process.env.CHECKOUT_SUCCESS_URL || !process.env.CHECKOUT_CANCEL_URL) {
    return res.status(503).json({
      error: 'URLs de retorno do checkout nao configuradas.'
    });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'brl',
          product_data: {
            name: `HYPE MUSIC - ${credits} creditos`,
            description: `Compra de ${credits} creditos HYPE MUSIC`
          },
          unit_amount: totalCents
        },
        quantity: 1
      }],
      client_reference_id: req.hypeUser.uid,
      metadata: {
        kind: 'credit_pack',
        firebaseUid: req.hypeUser.uid,
        credits: String(credits),
        unitPriceCents: String(unitPriceCents),
        totalCents: String(totalCents)
      },
      success_url: process.env.CHECKOUT_SUCCESS_URL,
      cancel_url: process.env.CHECKOUT_CANCEL_URL,
      payment_method_types: ['card', 'pix']
    });

    return res.json({
      url: session.url,
      credits,
      unitPriceCents,
      totalCents,
      currency: 'brl'
    });
  } catch (err) {
    console.error('[credit checkout]', err);
    return res.status(500).json({
      error: 'Nao foi possivel iniciar a compra de creditos.'
    });
  }
});
app.get('/v1/admin/ledger', requireUser, requireOwnerOrReseller, async (req, res) => {
  try {
    let q = db.collection('hypeCreditLedger');
    if (req.hypeRole.role !== 'owner') {
      q = q.where('uid', '==', req.hypeUser.uid);
    }
    q = q.orderBy('createdAt', 'desc').limit(100);
    const snap = await q.get();
    return res.json({ entries: snap.docs.map(d => ({ id: d.id, ...d.data(), createdAt: d.data().createdAt?.toDate?.().toISOString() || null })) });
  } catch (err) {
    console.error('[ledger]', err);
    return res.status(500).json({ error: 'NÃ£o foi possÃ­vel consultar o extrato.' });
  }
});

const port = Number(process.env.PORT || 8787);
app.listen(port, () => console.log(`HYPE subscription backend listening on :${port}`));




