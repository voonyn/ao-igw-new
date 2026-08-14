// Shown while a console segment is still resolving. A skeleton, not an empty
// table — "loading" and "nothing here" must not look the same.

export default function ConsoleLoading() {
  return (
    <div className="fade-in" aria-busy="true" aria-label="Loading">
      <div className="page-head">
        <div style={{ width: "100%" }}>
          <div className="skel" style={{ width: 220, height: 26 }} />
          <div className="skel" style={{ width: 420, maxWidth: "80%", height: 14, marginTop: 10 }} />
        </div>
      </div>
      <div className="card" style={{ padding: 18 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} style={{ display: "flex", gap: 14, alignItems: "center", padding: "10px 0" }}>
            <div className="skel" style={{ width: 28, height: 28, borderRadius: "50%" }} />
            <div className="skel" style={{ flex: 1, height: 13 }} />
            <div className="skel" style={{ width: 90, height: 13 }} />
          </div>
        ))}
      </div>
    </div>
  );
}
