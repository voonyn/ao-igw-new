import { ResetClient } from "./reset-client"

// Server component: reads the reset token from the query and hands it to the
// client form. The token is single-use and validated by the gateway on submit;
// it is never persisted here.
export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>
}) {
  const { token } = await searchParams
  return <ResetClient token={token ?? ""} />
}
