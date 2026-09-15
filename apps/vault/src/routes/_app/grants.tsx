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
import { addGrant, grants } from "../../origin"
import type { Grant } from "@vortex-api/pwm-sdk"

export const Route = createFileRoute("/_app/grants")({
  component: Grants,
})

function Grants() {
  const [rows, setRows] = useState<Grant[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  async function reload() {
    const res = await grants()
    if (res.error || !res.data) {
      setError("list failed")
      setRows([])
      return
    }
    setError(null)
    setRows(res.data.grants)
  }

  useEffect(() => {
    void reload()
  }, [])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader
        title="Grants"
        subtitle="Same grant object. Agent or Kratos human id. Not a family vault."
        actions={
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button size="sm">Grant</Button>
            </DialogTrigger>
            <DialogContent>
              <form
                className="flex flex-col gap-3"
                onSubmit={(e) => {
                  e.preventDefault()
                  const fd = new FormData(e.currentTarget)
                  const item = String(fd.get("item") ?? "")
                  const agent = String(fd.get("agent") ?? "")
                  const human = String(fd.get("human") ?? "")
                  const level = String(fd.get("level") ?? "level2")
                  void addGrant({
                    item,
                    level: level === "level1" ? "level1" : "level2",
                    agent: agent || undefined,
                    human: human || undefined,
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
                  <DialogTitle>Grant Use</DialogTitle>
                  <DialogDescription>XOR agent name or human identity id.</DialogDescription>
                </DialogHeader>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="item">Item</Label>
                  <Input id="item" name="item" required />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="agent">Agent</Label>
                  <Input id="agent" name="agent" />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="human">Human id</Label>
                  <Input id="human" name="human" />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="level">Level</Label>
                  <Input id="level" name="level" defaultValue="level2" />
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
          <OperationalEmptyState title="No grants" description="Grant an agent or a human Use on an item." />
        ) : (
          rows.map((g) => (
            <OperationalRow
              key={g.id}
              title={g.item_id}
              subtitle={`${g.agent_id} · ${g.level}`}
            />
          ))
        )}
      </OperationalTableFrame>
    </div>
  )
}
