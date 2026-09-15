import { Button } from "@cloudflare/kumo/components/button";
import { Dialog } from "@cloudflare/kumo/components/dialog";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { Label } from "@cloudflare/kumo/components/label";
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { Table } from "@cloudflare/kumo/components/table";
import { Text } from "@cloudflare/kumo/components/text";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageChrome } from "../../page-chrome";
import { addAgent, agents } from "../../origin";
import type { Agent } from "@vortex-api/pwm-sdk";

export const Route = createFileRoute("/_app/agents")({
  component: Agents,
});

function Agents() {
  const [rows, setRows] = useState<Agent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function reload() {
    const res = await agents();
    if (res.error || !res.data) {
      setError("list failed");
      setRows([]);
      return;
    }
    setError(null);
    setRows(res.data.agents);
  }

  useEffect(() => {
    void reload();
  }, []);

  return (
    <PageChrome
      title="Agents"
      subtitle="Principals. Hydra client secrets stay --secret-file, never here."
      actions={
        <>
          <Button type="button" variant="primary" onClick={() => setOpen(true)}>
            Add
          </Button>
          <Dialog.Root open={open} onOpenChange={setOpen}>
            <Dialog size="sm" className="p-6">
              <form
                className="flex flex-col gap-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  const fd = new FormData(e.currentTarget);
                  const name = String(fd.get("name") ?? "");
                  void addAgent(name).then((res) => {
                    if (res.error) {
                      setError("create failed");
                      return;
                    }
                    setOpen(false);
                    void reload();
                  });
                }}
              >
                <Dialog.Title>Add agent</Dialog.Title>
                <Dialog.Description>Lowercase name. Not a token.</Dialog.Description>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="name">Name</Label>
                  <Input id="name" name="name" required />
                </div>
                <div className="flex justify-end">
                  <Button type="submit" variant="primary">
                    Save
                  </Button>
                </div>
              </form>
            </Dialog>
          </Dialog.Root>
        </>
      }
    >
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
            <Empty title="No agents" description="Register a principal, then grant items." />
          ) : (
            <Table>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>Kind</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {rows.map((a) => (
                  <Table.Row key={a.id}>
                    <Table.Cell>{a.id}</Table.Cell>
                    <Table.Cell>{a.kind}</Table.Cell>
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
