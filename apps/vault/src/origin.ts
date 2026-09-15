import {
  createAgent,
  createClient,
  createGrant,
  createItem,
  listAgents,
  listEvents,
  listGrants,
  listItems,
} from "@vortex-api/pwm-sdk"
import { originAPI, token } from "./auth"

function client() {
  const t = token()
  if (!t) {
    throw new Error("signed out")
  }
  return createClient({
    baseUrl: originAPI,
    auth: () => t,
  })
}

export function items() {
  return listItems({ client: client() })
}

export function addItem(body: {
  name: string
  uri?: string
  secret?: string
  login?: string
  kind?: "api_key" | "card" | "identity"
  card?: {
    number?: string
    exp_month?: string
    exp_year?: string
    cvv?: string
    holder?: string
  }
  identity?: {
    given_name?: string
    family_name?: string
    address?: string
    city?: string
    region?: string
    postal?: string
    country?: string
    phone?: string
    email?: string
  }
}) {
  return createItem({ client: client(), body })
}

export function importItems(file: File) {
  const t = token()
  if (!t) {
    throw new Error("signed out")
  }
  const q = encodeURIComponent(file.name)
  return fetch(`${originAPI}/v1/import?filename=${q}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${t}`,
      "Content-Type": "application/octet-stream",
    },
    body: file,
  })
}

export function grants() {
  return listGrants({ client: client() })
}

export function addGrant(body: {
  item: string
  level: "level1" | "level2"
  agent?: string
  human?: string
}) {
  return createGrant({ client: client(), body })
}

export function agents() {
  return listAgents({ client: client() })
}

export function addAgent(name: string) {
  return createAgent({ client: client(), body: { name } })
}

export function events() {
  return listEvents({ client: client() })
}
