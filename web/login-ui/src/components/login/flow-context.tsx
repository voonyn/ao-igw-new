"use client"

import * as React from "react"
import { useRouter } from "next/navigation"

export type Direction = "forward" | "back"

type LoginFlowValue = {
  email: string
  setEmail: (email: string) => void
  /** The goidc AuthnSession id carried from the entry `?authRequest=` query. */
  authRequest: string
  setAuthRequest: (id: string) => void
  /** A server-validated post-login return URL carried from the entry
   *  `?redirect_uri=` query; used by /success when there is no OIDC request. */
  redirectUri: string
  setRedirectUri: (uri: string) => void
  /** The pending steps the gateway named at /password: `otp` for the challenge,
   *  `otp_enroll` for forced setup, or empty when the sign-in owes nothing. These
   *  are steps the person still owes, never factors they already proved. The
   *  gateway names at most one, and /success re-reads it to route back. */
  methods: string[]
  setMethods: (methods: string[]) => void
  direction: Direction
  /** Set the slide direction, then route to `href`. */
  navigate: (href: string, direction: Direction) => void
  /** False during SSR / first paint, true once running on the client. */
  hydrated: boolean
}

const LoginFlowContext = React.createContext<LoginFlowValue | null>(null)

/* ------------------------------------------------------------------ *
 * Email is persisted in sessionStorage so a refresh / deep-link keeps
 * the in-progress flow. We expose it through an external store and read
 * it with useSyncExternalStore — that restores it without a setState
 * in an effect and stays consistent across SSR hydration.
 * ------------------------------------------------------------------ */
const EMAIL_KEY = "ao.login.email"
const AUTHREQ_KEY = "ao.login.authRequest"
const REDIRECT_KEY = "ao.login.redirectUri"
const METHODS_KEY = "ao.login.methods"

// A small sessionStorage-backed external store, used for both the in-progress
// email and the carried authRequest so a refresh / client navigation across
// steps keeps them (read with useSyncExternalStore, no setState-in-effect).
function makeStore(key: string) {
  const listeners = new Set<() => void>()
  const read = () => {
    try {
      return window.sessionStorage.getItem(key) ?? ""
    } catch {
      return ""
    }
  }
  const write = (value: string) => {
    try {
      window.sessionStorage.setItem(key, value)
    } catch {
      // sessionStorage unavailable — flow still works within a single render tree
    }
    listeners.forEach((listener) => listener())
  }
  const subscribe = (listener: () => void) => {
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }
  return { read, write, subscribe }
}

const emailStore = makeStore(EMAIL_KEY)
const authRequestStore = makeStore(AUTHREQ_KEY)
const redirectUriStore = makeStore(REDIRECT_KEY)
const methodsStore = makeStore(METHODS_KEY)

const noopSubscribe = () => () => {}

export function LoginFlowProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [direction, setDirection] = React.useState<Direction>("forward")

  const email = React.useSyncExternalStore(emailStore.subscribe, emailStore.read, () => "")
  const authRequest = React.useSyncExternalStore(authRequestStore.subscribe, authRequestStore.read, () => "")
  const redirectUri = React.useSyncExternalStore(redirectUriStore.subscribe, redirectUriStore.read, () => "")
  const methodsRaw = React.useSyncExternalStore(methodsStore.subscribe, methodsStore.read, () => "")
  const methods = React.useMemo(() => (methodsRaw ? methodsRaw.split(",") : []), [methodsRaw])
  const hydrated = React.useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false
  )

  const setEmail = React.useCallback((value: string) => emailStore.write(value), [])
  const setAuthRequest = React.useCallback((value: string) => authRequestStore.write(value), [])
  const setRedirectUri = React.useCallback((value: string) => redirectUriStore.write(value), [])
  const setMethods = React.useCallback((value: string[]) => methodsStore.write(value.join(",")), [])

  const navigate = React.useCallback(
    (href: string, dir: Direction) => {
      setDirection(dir)
      router.push(href)
    },
    [router]
  )

  const value = React.useMemo<LoginFlowValue>(
    () => ({ email, setEmail, authRequest, setAuthRequest, redirectUri, setRedirectUri, methods, setMethods, direction, navigate, hydrated }),
    [email, setEmail, authRequest, setAuthRequest, redirectUri, setRedirectUri, methods, setMethods, direction, navigate, hydrated]
  )

  return (
    <LoginFlowContext.Provider value={value}>
      {children}
    </LoginFlowContext.Provider>
  )
}

export function useLoginFlow() {
  const ctx = React.useContext(LoginFlowContext)
  if (!ctx) {
    throw new Error("useLoginFlow must be used within a LoginFlowProvider")
  }
  return ctx
}

/**
 * Guards a later step: if the flow hasn't captured an email yet (direct
 * navigation / refresh with no stored state), bounce back to the start.
 * Returns the current email so callers can render once it's available.
 */
export function useRequireEmail() {
  const { email, hydrated } = useLoginFlow()
  const router = useRouter()
  React.useEffect(() => {
    if (hydrated && !email) router.replace("/identifier")
  }, [hydrated, email, router])
  return email
}
