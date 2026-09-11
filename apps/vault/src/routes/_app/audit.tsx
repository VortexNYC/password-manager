import { createFileRoute } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import {
  OperationalEmptyState,
  OperationalHeader,
  OperationalRow,
  OperationalTableFrame,
} from "@vortexnyc/ui"
import { events } from "../../origin"
import type { AuditEvent } from "@vortex-api/pwm-sdk"

export const Route = createFileRoute("/_app/audit")({
  component: Audit,
})

function Audit() {
  const [rows, setRows] = useState<AuditEvent[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void events().then((res) => {
      if (res.error || !res.data) {
        setError("list failed")
        setRows([])
        return
      }
      setRows([...res.data.events].reverse())
    })
  }, [])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <OperationalHeader title="Audit" subtitle="Decisions. Never secrets." />
      {error ? <p className="text-destructive px-4 py-2 text-xs">{error}</p> : null}
      <OperationalTableFrame>
        {rows === null ? (
          <p className="text-muted-foreground px-4 py-3 text-sm">Loading…</p>
        ) : rows.length === 0 ? (
          <OperationalEmptyState title="No events" />
        ) : (
          rows.map((e, i) => (
            <OperationalRow
              key={`${e.time}-${e.item_id}-${i}`}
              title={`${e.decision} ${e.action}`}
              subtitle={`${e.item_id} · ${e.agent_id} · ${e.time}`}
            />
          ))
        )}
      </OperationalTableFrame>
    </div>
  )
}
