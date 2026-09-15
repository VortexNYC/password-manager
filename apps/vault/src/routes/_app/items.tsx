import { createFileRoute } from "@tanstack/react-router"
import { useEffect, useState } from "react"
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
import { addItem, items } from "../../origin"
import type { Item } from "@vortex-api/pwm-sdk"

export const Route = createFileRoute("/_app/items")({
  component: Items,
})

function Items() {
  const [rows, setRows] = useState<Item[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

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
          <Dialog open={open} onOpenChange={setOpen}>
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
                  const uri = String(fd.get("uri") ?? "")
                  const login = String(fd.get("login") ?? "")
                  const secret = String(fd.get("secret") ?? "")
                  void addItem({
                    name,
                    uri: uri || undefined,
                    login: login || undefined,
                    secret: secret || undefined,
                  }).then((res) => {
                    if (res.error) {
                      setError("create failed")
                      return
                    }
                    setOpen(false)
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
                  <Label htmlFor="name">Name</Label>
                  <Input id="name" name="name" required autoComplete="off" />
                </div>
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
                <DialogFooter>
                  <Button type="submit" size="sm">
                    Save
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        }
      />
      {error ? <p className="text-destructive px-4 py-2 text-xs">{error}</p> : null}
      <OperationalTableFrame>
        {rows === null ? (
          <p className="text-muted-foreground px-4 py-3 text-sm">Loading…</p>
        ) : rows.length === 0 ? (
          <OperationalEmptyState
            title="No items"
            description="Add an API key or password. Chrome fill reads it; this page does not."
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
