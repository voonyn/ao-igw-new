# 11 — QR Login backend

**What to build:** The three endpoints that turn a scan into a sign-in.

**Start** opens a Login Session naming nobody, mints a nonce, asks the Scan
Verifier for a transaction, and hands the browser the verifier's code object
unchanged. Re-encoding it would silently drop any field the verifier adds,
including the fallback link.

**The callback** is where the Scan Verifier pushes its result. It sits behind its
own credential and outside the tenant lookup, because a push carries no Tenant
until the QR Login Transaction is found. It records the result on the transaction
and never touches the Login Session: the browser is polling with that session's
token, and recording a factor rotates the token, so a callback that recorded the
factor would invalidate the token before the browser learned it had succeeded.

**The poll** is the only party holding a valid session token, so it does the
binding and records the factor.

The session domain gains the two operations this needs — open a Login Session that
names nobody, and complete one by binding a Subject and recording a named factor.
Neither knows anything about the Scan Verifier, so a later factor reuses them.

**Blocked by:** 09.

**Status:** done

- [x] Start returns the verifier's code object byte for byte.
- [x] No verifier-side identifier that must stay server-side reaches the browser.
- [x] The push callback is refused without the correct credential.
- [x] The callback finds its transaction by the verifier's own identifier, with no Tenant given.
- [x] A nonce that does not match fails the transaction.
- [x] The poll answers only pending, authenticated, or expired.
- [x] An expired transaction, a consumed one, and an unknown one all answer expired.
- [x] A presented name resolving to no person fails the transaction, and no person is created.
- [x] A transaction is claimed once, and replaying the same push changes nothing.
- [x] The transaction expires on a short timer sized above the verifier's own window.
- [x] A successful poll returns a rotated session token, and the previous token stops working.
- [x] The recorded factor appears wherever the sign-in records its factors.
- [x] With the integration off, none of the three endpoints exist.
- [x] The nonce plaintext is stored nowhere and reaches no log line.
