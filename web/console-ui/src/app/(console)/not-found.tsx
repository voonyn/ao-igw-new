import Link from "next/link";

// Console-scoped not-found: a detail route calling `notFound()` for an id that
// doesn't exist — or that the caller can't read, which the admin API answers as
// 404 either way — lands here, inside the shell, rather than on the bare root
// page. Same sentence as `app/not-found.tsx`; only the chrome differs.

export default function ConsoleNotFound() {
  return (
    <div className="fade-in">
      <div className="page-head">
        <div>
          <h1>Not found</h1>
          <div className="sub">
            That record doesn&apos;t exist, or it sits outside the access your roles grant. If you expected to see it,
            ask a tenant manager to check your membership.
          </div>
        </div>
      </div>
      <div className="card view-notice" role="status">
        <div style={{ minWidth: 0, flex: 1 }}>
          <b>Nothing to show for this address.</b>
          <p>The id in the URL didn&apos;t resolve to a record you can read.</p>
        </div>
        <Link className="btn ghost sm" href="/overview">
          Back to overview
        </Link>
      </div>
    </div>
  );
}
