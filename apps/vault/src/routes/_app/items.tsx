import { createFileRoute } from "@tanstack/react-router"
import { useEffect, useRef, useState } from "react"
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Input,
  Label,
  OperationalEmptyState,
  OperationalHeader,
  OperationalRow,
  OperationalTableFrame,
} from "@vortexnyc/ui"
import { addItem, importItems, items } from "../../origin"
import type { Item } from "@vortex-api/pwm-sdk"

export const Route = createFileRoute("/_app/items")({
  component: Items,
})

type Kind = "api_key" | "card" | "identity"

function Items() {
  const [rows, setRows] = useState<Item[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<Kind>("api_key")
  const fileRef = useRef<HTMLInputElement>(null)

  async function reload() {
    const res = await items()
    if (res.error || !res.data) {
      setError("list failed")
      setRows([])
      return
    }
    setError(null)
    setRows(res.data.items)
  }

  useEffect(() => {
    void reload()
  }, [])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader
        title="Items"
        subtitle="Secrets go in. They do not come back out. Fill is the read path."
        actions={
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".csv,.1pux,text/csv,application/zip"
              className="sr-only"
              onChange={(e) => {
                const file = e.currentTarget.files?.[0]
                e.currentTarget.value = ""
                if (!file) {
                  return
                }
                void importItems(file).then(async (res) => {
                  if (!res.ok) {
                    setError("import failed")
                    return
                  }
                  setError(null)
                  await reload()
                })
              }}
            />
            <Button
              size="sm"
              variant="outline"
              type="button"
              onClick={() => fileRef.current?.click()}
            >
              Import
            </Button>
            <Dialog
              open={open}
              onOpenChange={(next) => {
                setOpen(next)
                if (!next) {
                  setKind("api_key")
                }
              }}
            >
              <DialogTrigger asChild>
                <Button size="sm">Add</Button>
              </DialogTrigger>
              <DialogContent>
                <form
                  className="flex flex-col gap-3"
                  onSubmit={(e) => {
                    e.preventDefault()
                    const fd = new FormData(e.currentTarget)
                    const name = String(fd.get("name") ?? "")
                    const body =
                      kind === "card"
                        ? {
                            name,
                            kind,
                            card: {
                              number: String(fd.get("number") ?? "") || undefined,
                              exp_month: String(fd.get("exp_month") ?? "") || undefined,
                              exp_year: String(fd.get("exp_year") ?? "") || undefined,
                              cvv: String(fd.get("cvv") ?? "") || undefined,
                              holder: String(fd.get("holder") ?? "") || undefined,
                            },
                          }
                        : kind === "identity"
                          ? {
                              name,
                              kind,
                              identity: {
                                given_name: String(fd.get("given_name") ?? "") || undefined,
                                family_name: String(fd.get("family_name") ?? "") || undefined,
                                address: String(fd.get("address") ?? "") || undefined,
                                city: String(fd.get("city") ?? "") || undefined,
                                region: String(fd.get("region") ?? "") || undefined,
                                postal: String(fd.get("postal") ?? "") || undefined,
                                country: String(fd.get("country") ?? "") || undefined,
                                phone: String(fd.get("phone") ?? "") || undefined,
                                email: String(fd.get("email") ?? "") || undefined,
                              },
                            }
                          : {
                              name,
                              kind,
                              uri: String(fd.get("uri") ?? "") || undefined,
                              login: String(fd.get("login") ?? "") || undefined,
                              secret: String(fd.get("secret") ?? "") || undefined,
                            }
                    void addItem(body).then((res) => {
                      if (res.error) {
                        setError("create failed")
                        return
                      }
                      setOpen(false)
                      setKind("api_key")
                      void reload()
                    })
                  }}
                >
                  <DialogHeader>
                    <DialogTitle>Add item</DialogTitle>
                    <DialogDescription>
                      The secret is sent once. This page will never show it.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="flex flex-col gap-1">
                    <Label htmlFor="kind">Kind</Label>
                    <select
                      id="kind"
                      className="border-input bg-background h-9 rounded-md border px-3 text-sm"
                      value={kind}
                      onChange={(e) => setKind(e.currentTarget.value as Kind)}
                    >
                      <option value="api_key">Password / API key</option>
                      <option value="card">Card</option>
                      <option value="identity">Identity</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-1">
                    <Label htmlFor="name">Name</Label>
                    <Input id="name" name="name" required autoComplete="off" />
                  </div>
                  {kind === "api_key" ? (
                    <>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="uri">URI</Label>
                        <Input id="uri" name="uri" placeholder="https://api.example.com" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="login">Fill username</Label>
                        <Input id="login" name="login" autoComplete="username" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="secret">Secret</Label>
                        <Input id="secret" name="secret" type="password" autoComplete="new-password" />
                      </div>
                    </>
                  ) : null}
                  {kind === "card" ? (
                    <>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="number">Number</Label>
                        <Input id="number" name="number" autoComplete="cc-number" required />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="exp_month">Month</Label>
                        <Input id="exp_month" name="exp_month" autoComplete="cc-exp-month" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="exp_year">Year</Label>
                        <Input id="exp_year" name="exp_year" autoComplete="cc-exp-year" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="cvv">CVV</Label>
                        <Input id="cvv" name="cvv" autoComplete="cc-csc" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="holder">Name on card</Label>
                        <Input id="holder" name="holder" autoComplete="cc-name" />
                      </div>
                    </>
                  ) : null}
                  {kind === "identity" ? (
                    <>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="given_name">Given name</Label>
                        <Input id="given_name" name="given_name" autoComplete="given-name" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="family_name">Family name</Label>
                        <Input id="family_name" name="family_name" autoComplete="family-name" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="address">Street</Label>
                        <Input id="address" name="address" autoComplete="address-line1" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="city">City</Label>
                        <Input id="city" name="city" autoComplete="address-level2" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="region">Region</Label>
                        <Input id="region" name="region" autoComplete="address-level1" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="postal">Postal</Label>
                        <Input id="postal" name="postal" autoComplete="postal-code" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="country">Country</Label>
                        <Input id="country" name="country" autoComplete="country-name" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="phone">Phone</Label>
                        <Input id="phone" name="phone" autoComplete="tel" />
                      </div>
                      <div className="flex flex-col gap-1">
                        <Label htmlFor="email">Email</Label>
                        <Input id="email" name="email" autoComplete="email" />
                      </div>
                    </>
                  ) : null}
                  <DialogFooter>
                    <Button type="submit" size="sm">
                      Save
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        }
      />
      {error ? <p className="text-destructive px-4 py-2 text-xs">{error}</p> : null}
      <OperationalTableFrame>
        {rows === null ? (
          <p className="text-muted-foreground px-4 py-3 text-sm">Loading…</p>
        ) : rows.length === 0 ? (
          <OperationalEmptyState
            title="No items"
            description="Add a password, card, or identity. Import a 1Password export. Chrome fill reads it; this page does not."
          />
        ) : (
          rows.map((item) => (
            <OperationalRow
              key={item.id}
              title={item.name}
              subtitle={(item.uris ?? []).join(" · ") || item.kind}
              trailing={
                <span className="text-muted-foreground text-xs">
                  {item.has_totp ? "TOTP" : item.kind}
                </span>
              }
            />
          ))
        )}
      </OperationalTableFrame>
    </div>
  )
}
