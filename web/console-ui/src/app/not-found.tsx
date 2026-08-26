import Link from "next/link";

// Root not-found. Reached by an unknown path and by any detail route calling
// `notFound()` for an id that doesn't exist or that the caller can't read — the
// admin API answers 404 for both, and the console says the same thing.

export default function NotFound() {
  return (
    <div
      style={{
        minHeight: "100dvh",
        display: "grid",
        placeItems: "center",
        padding: "2rem",
        textAlign: "center",
        fontFamily: "var(--font-inter, system-ui), sans-serif",
      }}
    >
      <div style={{ maxWidth: 420 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: "0 0 8px" }}>Not found</h1>
        <p style={{ fontSize: 14, color: "var(--muted, #6b7280)", lineHeight: 1.6, margin: "0 0 20px" }}>
          That record doesn&apos;t exist, or it sits outside the access your roles grant. If you expected to see it, ask
          a tenant manager to check your membership.
        </p>
        <Link className="btn primary" href="/overview">
          Back to the console
        </Link>
      </div>
    </div>
  );
}
