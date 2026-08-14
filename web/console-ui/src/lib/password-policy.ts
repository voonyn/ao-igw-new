// Client-side mirror of the gateway's password policy check
// (internal/core/password/pwpolicy.go), driven by the *resolved* policy the API
// returns from GET /settings/auth rather than by constants — a hardcoded minimum
// drifts from the tenant's real policy the first time an operator changes it.
//
// This is an affordance, not a gate: the server re-validates every password. The
// form's job is to stop the operator wasting a round trip and to say which rule
// they broke. The HIBP breach check (pwCheckBreach) is server-only and fails
// open there, so it is stated as a rule but not enforced here.

import type { AuthPolicy } from "./console-api";

/** bcrypt's input limit — the server rejects anything longer. */
const MAX_BYTES = 72;

const CLASS_TESTS = [/\p{Ll}/u, /\p{Lu}/u, /\p{Nd}/u] as const;

function classCount(pw: string): number {
  let n = CLASS_TESTS.filter((re) => re.test(pw)).length;
  // Symbol = anything that isn't lower, upper, or digit (matches the Go side's
  // fall-through: unicode.IsLower/IsUpper/IsDigit else "symbol").
  if (/[^\p{Ll}\p{Lu}\p{Nd}]/u.test(pw)) n++;
  return n;
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** The active policy's requirements, in the order the server checks them. */
export function policyRules(p: AuthPolicy | null): string[] {
  if (!p) return [];
  const rules: string[] = [];
  if (p.pwMinLength > 0) rules.push(`At least ${p.pwMinLength} characters`);
  if (p.pwMinClasses > 1) rules.push(`At least ${p.pwMinClasses} of: lowercase, uppercase, digit, symbol`);
  if (p.pwDenyList.length > 0) rules.push(`Not one of ${p.pwDenyList.length} disallowed password(s)`);
  if (p.pwCheckBreach) rules.push("Checked against known breached passwords (server-side)");
  rules.push(`At most ${MAX_BYTES} bytes`);
  return rules;
}

/** The first rule `pw` breaks, or null when it satisfies the policy. */
export function passwordViolation(pw: string, p: AuthPolicy | null): string | null {
  if (!pw) return "Enter a password.";
  if (byteLength(pw) > MAX_BYTES) return `Too long — the maximum is ${MAX_BYTES} bytes.`;
  // No policy yet (still loading, or the read was refused): fall back to the one
  // rule that always holds rather than blocking the operator on a read they may
  // not be allowed to make. The server still enforces the rest.
  if (!p) return null;
  if (p.pwMinLength > 0 && [...pw].length < p.pwMinLength) return `Too short — the policy requires ${p.pwMinLength} characters.`;
  if (p.pwMinClasses > 1 && classCount(pw) < p.pwMinClasses)
    return `Not complex enough — the policy requires ${p.pwMinClasses} of lowercase, uppercase, digit, symbol.`;
  // Exact match after trim + lowercase, exactly as the server compares.
  const needle = pw.toLowerCase();
  if (p.pwDenyList.some((d) => d.trim().toLowerCase() === needle)) return "That password is on the tenant's deny-list.";
  return null;
}
