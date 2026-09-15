import { createFileRoute } from "@tanstack/react-router"
import { Login } from "@ory/elements-react/theme"
import { frontend, oryConfig } from "../ory"
import { loadOrCreateFlow, loginSearch } from "../flow"

export const Route = createFileRoute("/login")({
  validateSearch: loginSearch,
  loaderDeps: ({ search }) => ({
    flow: search.flow,
    return_to: search.return_to,
    login_challenge: search.login_challenge,
  }),
  loader: ({ deps }) =>
    loadOrCreateFlow(
      "/login",
      deps.flow,
      () => {
        const req: { returnTo?: string; loginChallenge?: string } = {}
        if (deps.return_to) {
          req.returnTo = deps.return_to
        }
        if (deps.login_challenge) {
          req.loginChallenge = deps.login_challenge
        }
        return frontend.createBrowserLoginFlow(req)
      },
      (id) => frontend.getLoginFlow({ id }),
    ),
  component: () => <Login flow={Route.useLoaderData()} config={oryConfig} />,
})
