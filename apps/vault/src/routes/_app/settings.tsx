import { createFileRoute } from "@tanstack/react-router"
import { Button, OperationalHeader } from "@vortexnyc/ui"

export const Route = createFileRoute("/_app/settings")({
  component: Settings,
})

function Settings() {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader
        title="Settings"
        subtitle="Identity is Ory Elements. This app does not restyle those screens."
      />
      <div className="flex flex-col gap-3 px-4 py-4">
        <p className="text-sm">
          Password, TOTP, WebAuthn, and lookup codes live at login.veil.nyc.
        </p>
        <Button asChild size="sm" variant="outline">
          <a href="https://login.veil.nyc/settings">Open identity settings</a>
        </Button>
      </div>
    </div>
  )
}
