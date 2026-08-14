import { VerifyEmailClient } from "./verify-email-client"

// Server component: reads the verification token from the query and hands it to
// the client, which confirms it against the gateway on load.
export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>
}) {
  const { token } = await searchParams
  return <VerifyEmailClient token={token ?? ""} />
}
