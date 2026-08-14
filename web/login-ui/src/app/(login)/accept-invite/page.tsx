import { AcceptInviteClient } from "./accept-invite-client"

// Server component: reads the invite token from the query (the link the
// invitation email carries) and hands it to the client form. The token is
// single-use and validated by the gateway on submit; it is never persisted here.
export default async function AcceptInvitePage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>
}) {
  const { token } = await searchParams
  return <AcceptInviteClient token={token ?? ""} />
}
