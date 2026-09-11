import { createFileRoute } from "@tanstack/react-router"
import { Verification } from "@ory/elements-react/theme"
import { frontend, oryConfig } from "../ory"
import { flowSearch, loadOrCreateFlow } from "../flow"

export const Route = createFileRoute("/verification")({
  validateSearch: flowSearch,
  loaderDeps: ({ search }) => ({ flow: search.flow }),
  loader: ({ deps }) =>
    loadOrCreateFlow(
      "/verification",
      deps.flow,
      () => frontend.createBrowserVerificationFlow(),
      (id) => frontend.getVerificationFlow({ id }),
    ),
  component: () => <Verification flow={Route.useLoaderData()} config={oryConfig} />,
})
