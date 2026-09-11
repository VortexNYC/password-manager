import { redirect } from "@tanstack/react-router"

export function flowSearch(search: Record<string, unknown>): { flow?: string } {
  return { flow: typeof search.flow === "string" ? search.flow : undefined }
}

export function loginSearch(search: Record<string, unknown>): {
  flow?: string
  return_to?: string
  login_challenge?: string
} {
  const out: { flow?: string; return_to?: string; login_challenge?: string } = flowSearch(search)
  if (typeof search.return_to === "string") {
    out.return_to = search.return_to
  }
  if (typeof search.login_challenge === "string") {
    out.login_challenge = search.login_challenge
  }
  return out
}

export async function loadOrCreateFlow<T extends { id: string }>(
  path: string,
  flowId: string | undefined,
  create: () => Promise<T>,
  get: (id: string) => Promise<T>,
): Promise<T> {
  if (!flowId) {
    const created = await create()
    throw redirect({ to: path, search: { flow: created.id } })
  }
  return get(flowId)
}
