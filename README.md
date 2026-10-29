# HYPE MUSIC subscription backend

Node.js/Express backend shared by the Android app and subscription site. It uses Firebase Authentication ID tokens for identity, Firestore as the entitlement store, Google Play Developer API for purchase verification, and Stripe Checkout + Customer Portal for website subscriptions.

See `../HYPE_SUBSCRIPTIONS_SETUP.md` before deploying. Configure `.env` from `.env.example`; never commit secrets. HTTPS is required in production.
