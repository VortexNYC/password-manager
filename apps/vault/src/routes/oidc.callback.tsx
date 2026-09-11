import { createFileRoute, redirect } from "@tanstack/react-router"
import { finishLogin } from "../auth"

export const Route = createFileRoute("/oidc/callback")({
  loader: async () => {
    await finishLogin(window.location.href)
    throw redirect({ to: "/items" })
  },
  component: Callback,
  errorComponent: ({ error }) => (
    <main className="p-6">
      <p className="text-sm">Sign-in failed.</p>
      <p className="text-muted-foreground mt-1 text-xs">
        {error instanceof Error ? error.message : "error"}
      </p>
    </main>
  ),
})

function Callback() {
  return <p className="p-6 text-sm">Signing in…</p>
}
