import { createFileRoute } from "@tanstack/react-router"
import { Recovery } from "@ory/elements-react/theme"
import { frontend, oryConfig } from "../ory"
import { flowSearch, loadOrCreateFlow } from "../flow"

export const Route = createFileRoute("/recovery")({
  validateSearch: flowSearch,
  loaderDeps: ({ search }) => ({ flow: search.flow }),
  loader: ({ deps }) =>
    loadOrCreateFlow("/recovery", deps.flow, () => frontend.createBrowserRecoveryFlow(), (id) =>
      frontend.getRecoveryFlow({ id }),
    ),
  component: () => <Recovery flow={Route.useLoaderData()} config={oryConfig} />,
})
