import { createFileRoute, Outlet, useNavigate, useRouterState } from "@tanstack/react-router"
import {
  OperationalHeader,
  OperationalShell,
  OperationalSidebar,
  OperationalSidebarItem,
  OperationalSidebarSection,
} from "@vortexnyc/ui"
import { beginLogin, signedIn, signOut, token, amrOf } from "../auth"

export const Route = createFileRoute("/_app")({
  beforeLoad: async () => {
    if (signedIn()) {
      return
    }
    window.location.assign(await beginLogin())
  },
  component: Shell,
})

const nav = [
  { to: "/items", label: "Items" },
  { to: "/grants", label: "Grants" },
  { to: "/agents", label: "Agents" },
  { to: "/invites", label: "Invites" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" },
] as const

function Shell() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const navigate = useNavigate()
  const raw = token()
  const aal2 = raw ? amrOf(raw).includes("totp") : false
  return (
    <OperationalShell
      sidebar={
        <OperationalSidebar
          brand={<span>Veil</span>}
          footer={
            <OperationalSidebarItem
              type="button"
              onClick={() => {
                signOut()
                window.location.assign("/")
              }}
            >
              Sign out
            </OperationalSidebarItem>
          }
        >
          <OperationalSidebarSection>
            {nav.map((item) => (
              <OperationalSidebarItem
                key={item.to}
                type="button"
                active={pathname === item.to}
                onClick={() => {
                  void navigate({ to: item.to })
                }}
              >
                {item.label}
              </OperationalSidebarItem>
            ))}
          </OperationalSidebarSection>
        </OperationalSidebar>
      }
      header={
        <OperationalHeader
          title="Vault"
          subtitle={aal2 ? "password + TOTP" : "session"}
        />
      }
    >
      <Outlet />
    </OperationalShell>
  )
}
