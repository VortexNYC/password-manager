import { Text } from "@cloudflare/kumo/components/text";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { finishLogin } from "../auth";

export const Route = createFileRoute("/oidc/callback")({
  loader: async () => {
    await finishLogin(window.location.href);
    throw redirect({ to: "/items" });
  },
  component: Callback,
  errorComponent: ({ error }) => (
    <main className="p-6">
      <Text as="p">Sign-in failed.</Text>
      <Text as="p" variant="secondary" size="xs">
        {error instanceof Error ? error.message : "error"}
      </Text>
    </main>
  ),
});

function Callback() {
  return (
    <main className="p-6">
      <Text as="p">Signing in…</Text>
    </main>
  );
}
