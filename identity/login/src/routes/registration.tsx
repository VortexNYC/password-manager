import { createFileRoute } from "@tanstack/react-router"
import { Registration } from "@ory/elements-react/theme"
import { frontend, oryConfig } from "../ory"
import { flowSearch, loadOrCreateFlow } from "../flow"

export const Route = createFileRoute("/registration")({
  validateSearch: flowSearch,
  loaderDeps: ({ search }) => ({ flow: search.flow }),
  loader: ({ deps }) =>
    loadOrCreateFlow(
      "/registration",
      deps.flow,
      () => frontend.createBrowserRegistrationFlow(),
      (id) => frontend.getRegistrationFlow({ id }),
    ),
  component: () => <Registration flow={Route.useLoaderData()} config={oryConfig} />,
})
