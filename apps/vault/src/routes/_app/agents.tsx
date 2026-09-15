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
import { addAgent, agents } from "../../origin"
import type { Agent } from "@vortex-api/pwm-sdk"

export const Route = createFileRoute("/_app/agents")({
  component: Agents,
})

function Agents() {
  const [rows, setRows] = useState<Agent[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  async function reload() {
    const res = await agents()
    if (res.error || !res.data) {
      setError("list failed")
      setRows([])
      return
    }
    setError(null)
    setRows(res.data.agents)
  }

  useEffect(() => {
    void reload()
  }, [])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader
        title="Agents"
        subtitle="Principals. Hydra client secrets stay --secret-file, never here."
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
                  void addAgent(name).then((res) => {
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
                  <DialogTitle>Add agent</DialogTitle>
                  <DialogDescription>Lowercase name. Not a token.</DialogDescription>
                </DialogHeader>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="name">Name</Label>
                  <Input id="name" name="name" required />
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
          <OperationalEmptyState title="No agents" description="Register a principal, then grant items." />
        ) : (
          rows.map((a) => (
            <OperationalRow key={a.id} title={a.id} subtitle={a.kind} />
          ))
        )}
      </OperationalTableFrame>
    </div>
  )
}
