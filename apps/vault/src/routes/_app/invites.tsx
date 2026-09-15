import { createFileRoute } from "@tanstack/react-router"
import { OperationalHeader } from "@vortexnyc/ui"

export const Route = createFileRoute("/_app/invites")({
  component: Invites,
})

function Invites() {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader
        title="Invites"
        subtitle="Kratos recovery. The code never enters this browser."
      />
      <div className="flex flex-col gap-2 px-4 py-4 text-sm">
        <p>
          Invite is <code>password-manager human invite EMAIL --code-file</code>. The
          recovery code writes to a mode-600 file. Courier mails the link from
          noreply@veil.nyc.
        </p>
        <p className="text-muted-foreground text-xs">
          Origin does not return a recovery code over HTTP. Putting it in this SPA
          would be a Reveal. Email is the channel.
        </p>
      </div>
    </div>
  )
}
