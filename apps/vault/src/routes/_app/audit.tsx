import { Empty } from "@cloudflare/kumo/components/empty";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { Table } from "@cloudflare/kumo/components/table";
import { Text } from "@cloudflare/kumo/components/text";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageChrome } from "../../page-chrome";
import { events } from "../../origin";
import type { AuditEvent } from "@vortex-api/veil";

export const Route = createFileRoute("/_app/audit")({
  component: Audit,
});

function Audit() {
  const [rows, setRows] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void events().then((res) => {
      if (res.error || !res.data) {
        setError("list failed");
        setRows([]);
        return;
      }
      setRows([...res.data.events].reverse());
    });
  }, []);

  return (
    <PageChrome title="Audit" subtitle="Decisions. Never secrets.">
      {error ? (
        <Text as="p" variant="error">
          {error}
        </Text>
      ) : null}
      <LayerCard>
        <LayerCard.Primary>
          {rows === null ? (
            <Text variant="secondary">Loading…</Text>
          ) : rows.length === 0 ? (
            <Empty title="No events" />
          ) : (
            <Table>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Decision</Table.Head>
                  <Table.Head>Item</Table.Head>
                  <Table.Head>Agent</Table.Head>
                  <Table.Head>Time</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {rows.map((e, i) => (
                  <Table.Row key={`${e.time}-${e.item_id}-${i}`}>
                    <Table.Cell>
                      {e.decision} {e.action}
                    </Table.Cell>
                    <Table.Cell>{e.item_id}</Table.Cell>
                    <Table.Cell>{e.agent_id}</Table.Cell>
                    <Table.Cell>
                      <Text as="span" variant="mono-secondary">
                        {e.time}
                      </Text>
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          )}
        </LayerCard.Primary>
      </LayerCard>
    </PageChrome>
  );
}
