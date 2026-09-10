import { createFileRoute, Link } from "@tanstack/react-router"

export const Route = createFileRoute("/error")({
  validateSearch: (search: Record<string, unknown>): { id?: string } => ({
    id: typeof search.id === "string" ? search.id : undefined,
  }),
  component: ErrorPage,
})

function ErrorPage() {
  const { id } = Route.useSearch()
  return (
    <main>
      <p>Something went wrong.</p>
      {id ? <p>{id}</p> : null}
      <p>
        <Link to="/login">Log in</Link>
      </p>
    </main>
  )
}
