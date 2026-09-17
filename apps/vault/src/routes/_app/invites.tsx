import { Text } from "@cloudflare/kumo/components/text";
import { createFileRoute } from "@tanstack/react-router";
import { PageChrome } from "../../page-chrome";

export const Route = createFileRoute("/_app/invites")({
  component: Invites,
});

function Invites() {
  return (
    <PageChrome title="Invites" subtitle="Kratos recovery. The code never enters this browser.">
      <div className="flex flex-col gap-2">
        <Text as="p">
          Invite is <code>veil human invite EMAIL --code-file</code>. The recovery code
          writes to a mode-600 file. Courier mails the link from noreply@veil.nyc.
        </Text>
        <Text as="p" variant="secondary" size="sm">
          Origin does not return a recovery code over HTTP. Putting it in this SPA would be a
          Reveal. Email is the channel.
        </Text>
      </div>
    </PageChrome>
  );
}
