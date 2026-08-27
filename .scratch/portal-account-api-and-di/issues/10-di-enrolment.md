# 10 — Digital Identity enrolment

**What to build:** A person the tenant provisions is registered with the Scan
Verifier, so a later scan resolves to a real account. Both administrative writes
enrol: creating a person, and inviting one. Both produce a person with a username,
and the Scan Verifier keys on the username.

The call runs after the local write commits and outside its transaction. The Scan
Verifier is a third party with no compensating delete on this side, so letting its
outage roll back a committed person would trade a missing mirror for a lost person.
The call is synchronous and bounded by the configured timeout: a background call
would be in-process state, and any Instance of this deployment must serve any
request.

A success stores the verifier's identifier for that person. A failure leaves it
empty and logs a warning naming the person. The empty value is how an operator
finds who is not mirrored, and how a retry knows whom to skip.

The console shows the enrolment state on the person detail, read-only, and the
field is absent when the integration is off.

**Blocked by:** 09.

**Status:** done

- [x] Creating a person enrols them with the Scan Verifier.
- [x] Inviting a person enrols them too.
- [x] A person with no username is skipped, and the skip is logged.
- [x] A failed enrolment leaves the person created and answers the console normally.
- [x] A failed enrolment logs a warning naming the person and leaves the stored identifier empty.
- [x] The administrative write waits no longer than the configured timeout.
- [x] The console shows whether a person is enrolled, and the field cannot be edited.
- [x] With the integration off, no enrolment is attempted and the console field is absent.
- [x] Service tests prove the local write succeeds when the Scan Verifier fails.
