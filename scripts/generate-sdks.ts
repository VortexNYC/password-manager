#!/usr/bin/env -S pnpm exec tsx
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const openApiPath = resolve(repoRoot, "docs/openapi/password-manager.openapi.json");
const embedPath = resolve(repoRoot, "internal/publicapi/spec.json");
const typeScriptOutput = resolve(repoRoot, "sdks/typescript");
const pythonOutput = resolve(repoRoot, "sdks/python");
const goOutput = resolve(repoRoot, "sdks/go");
const tempRoot = resolve(repoRoot, ".tmp/sdk-generate");
const GO_MODULE_PATH = "github.com/vortexnyc/pwm-go";

const MIT = `MIT License

Copyright (c) 2026 Vortex NYC, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

function listFiles(path: string): readonly string[] {
  if (!existsSync(path)) {
    return [];
  }
  return readdirSync(path).flatMap((entry) => {
    const childPath = resolve(path, entry);
    if (statSync(childPath).isDirectory()) {
      return listFiles(childPath);
    }
    return [childPath];
  });
}

function specVersion(): string {
  const parsed: unknown = JSON.parse(readFileSync(openApiPath, "utf8"));
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("info" in parsed) ||
    typeof parsed.info !== "object" ||
    parsed.info === null ||
    !("version" in parsed.info) ||
    typeof parsed.info.version !== "string"
  ) {
    throw new Error("OpenAPI spec must define info.version");
  }
  return parsed.info.version;
}

function run(name: string, args: string[]): void {
  console.log(`\n${name}`);
  console.log(args.join(" "));
  const result = spawnSync(args[0], args.slice(1), {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${name} failed`);
  }
}

function javaOk(): boolean {
  return spawnSync("java", ["-version"], { stdio: "ignore" }).status === 0;
}

function dockerOk(): boolean {
  return spawnSync("docker", ["info"], { stdio: "ignore" }).status === 0;
}

function generatorArgs(kind: "python" | "go", input: string, output: string, version: string): string[] {
  const extra =
    kind === "python"
      ? [
          "--additional-properties",
          `packageName=vortex_pwm,projectName=vortex-pwm-sdk,packageVersion=${version},generateSourceCodeOnly=true,hideGenerationTimestamp=true`,
        ]
      : [
          "--git-user-id",
          "vortexnyc",
          "--git-repo-id",
          "pwm-go",
          "--additional-properties",
          `packageName=vortexpwm,packageVersion=${version},hideGenerationTimestamp=true,structPrefix=true,withGoMod=true`,
        ];
  return [
    "generate",
    "-i",
    input,
    "-g",
    kind,
    "-o",
    output,
    ...extra,
    "--global-property",
    "apiTests=false,modelTests=false",
  ];
}

function generateLang(kind: "python" | "go", version: string): void {
  const temp = resolve(tempRoot, kind);
  mkdirSync(temp, { recursive: true });
  if (javaOk()) {
    run(`Generate ${kind} SDK with OpenAPI Generator`, [
      "pnpm",
      "exec",
      "openapi-generator-cli",
      ...generatorArgs(kind, openApiPath, temp, version),
    ]);
  } else if (dockerOk()) {
    const uid = String(process.getuid?.() ?? 0);
    const gid = String(process.getgid?.() ?? 0);
    run(`Generate ${kind} SDK with OpenAPI Generator (docker)`, [
      "docker",
      "run",
      "--rm",
      "--user",
      `${uid}:${gid}`,
      "-v",
      `${repoRoot}:/local`,
      "openapitools/openapi-generator-cli:v7.23.0",
      ...generatorArgs(
        kind,
        "/local/docs/openapi/password-manager.openapi.json",
        `/local/.tmp/sdk-generate/${kind}`,
        version
      ),
    ]);
  } else {
    throw new Error(`generate ${kind} SDK: need java or docker. This is not optional.`);
  }
  rmSync(kind === "python" ? pythonOutput : goOutput, { force: true, recursive: true });
  mkdirSync(dirname(kind === "python" ? pythonOutput : goOutput), { recursive: true });
  cpSync(temp, kind === "python" ? pythonOutput : goOutput, { recursive: true });
}

function pruneGeneratedSdkOutputs(): void {
  const noise = [
    resolve(pythonOutput, ".openapi-generator"),
    resolve(pythonOutput, ".openapi-generator-ignore"),
    resolve(pythonOutput, "vortex_pwm", "docs"),
    resolve(pythonOutput, "vortex_pwm", "test"),
    resolve(pythonOutput, "vortex_pwm_README.md"),
    resolve(goOutput, ".openapi-generator"),
    resolve(goOutput, ".openapi-generator-ignore"),
    resolve(goOutput, ".gitignore"),
    resolve(goOutput, ".travis.yml"),
    resolve(goOutput, "docs"),
    resolve(goOutput, "git_push.sh"),
  ];
  for (const path of noise) {
    rmSync(path, { force: true, recursive: true });
  }
}

function rewriteGeneratedTypescriptWithoutEslintDisable(): void {
  for (const path of listFiles(typeScriptOutput)) {
    if (!path.endsWith(".ts")) {
      continue;
    }
    const content = readFileSync(path, "utf8");
    const next = content
      .replace(/^[ \t]*\/\/ eslint-disable-next-line.*\n/gm, "")
      .replace(/^[ \t]*\/\* eslint-disable.*\*\/\n/gm, "")
      .replace("export interface ClientMeta {}", "export type ClientMeta = Record<never, never>;");
    if (next !== content) {
      writeFileSync(path, next);
    }
  }
}

function appendTypeScriptRootExports(): void {
  const indexPath = resolve(typeScriptOutput, "index.ts");
  const content = readFileSync(indexPath, "utf8");
  const extra = "export { createClient } from './client';\nexport type { Config } from './client';\n";
  if (content.includes("export { createClient } from './client';")) {
    return;
  }
  writeFileSync(indexPath, `${content.replace(/\n+$/u, "")}\n${extra}`);
}

function writePackageMetadata(version: string): void {
  writeFileSync(resolve(typeScriptOutput, "LICENSE"), MIT);
  writeFileSync(
    resolve(typeScriptOutput, "package.json"),
    `${JSON.stringify(
      {
        name: "@vortex-api/pwm-sdk",
        version,
        description: "Generated TypeScript SDK for Vortex Password Manager. Use injects. Never GetSecret.",
        license: "MIT",
        type: "module",
        sideEffects: false,
        main: "./index.ts",
        types: "./index.ts",
        repository: {
          type: "git",
          url: "git+https://github.com/VortexNYC/password-manager.git",
          directory: "sdks/typescript",
        },
      },
      null,
      2
    )}\n`
  );
  writeFileSync(
    resolve(typeScriptOutput, "README.md"),
    `# Vortex Password Manager TypeScript SDK

Generated from \`docs/openapi/password-manager.openapi.json\`. Do not handwrite clients.

\`\`\`ts
import { createClient, listItems, useItem } from "@vortex-api/pwm-sdk";

const client = createClient({
  baseUrl: "https://pwm.vortex.nyc",
  headers: { Authorization: \`Bearer \${process.env.PWM_OIDC_TOKEN}\` },
});

const { data } = await listItems({ client });
await useItem({
  client,
  body: { item: "stripe", url: "https://api.stripe.com/v1/customers", method: "POST" },
});
\`\`\`

The vault secret is never in the response.
`
  );

  writeFileSync(resolve(pythonOutput, "LICENSE"), MIT);
  writeFileSync(
    resolve(pythonOutput, "pyproject.toml"),
    `[project]
name = "vortex-pwm-sdk"
version = "${version}"
description = "Generated Python SDK for Vortex Password Manager. Use injects. Never GetSecret."
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.9"
dependencies = [
  "urllib3 >= 2.1.0, < 3.0.0",
  "python-dateutil >= 2.8.2",
  "pydantic >= 2",
  "typing-extensions >= 4.7.1",
]

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["vortex_pwm*"]
`
  );
  writeFileSync(
    resolve(pythonOutput, "README.md"),
    `# vortex-pwm-sdk

Generated from \`docs/openapi/password-manager.openapi.json\`. Do not handwrite clients.

\`\`\`bash
pip install vortex-pwm-sdk
\`\`\`

\`\`\`py
import os
import vortex_pwm

configuration = vortex_pwm.Configuration(host="https://pwm.vortex.nyc")
configuration.access_token = os.environ["PWM_OIDC_TOKEN"]
client = vortex_pwm.ApiClient(configuration)
api = vortex_pwm.AgentApi(client)
items = api.list_items()
api.use_item(vortex_pwm.UseRequest(item="stripe", url="https://api.stripe.com/v1/customers"))
\`\`\`

The vault secret is never in the response.
`
  );

  writeFileSync(resolve(goOutput, "LICENSE"), MIT);
  writeFileSync(
    resolve(goOutput, "README.md"),
    `# Vortex Password Manager Go SDK

Generated from \`docs/openapi/password-manager.openapi.json\`. Do not handwrite clients.

The public module is \`${GO_MODULE_PATH}\`.

\`\`\`bash
go get ${GO_MODULE_PATH}
\`\`\`

\`\`\`go
package main

import (
	"context"
	"os"

	vortexpwm "${GO_MODULE_PATH}"
)

func main() {
	cfg := vortexpwm.NewConfiguration()
	cfg.Host = "pwm.vortex.nyc"
	cfg.Scheme = "https"
	cfg.AddDefaultHeader("Authorization", "Bearer "+os.Getenv("PWM_OIDC_TOKEN"))
	client := vortexpwm.NewAPIClient(cfg)
	_, _, _ = client.AgentAPI.ListItems(context.Background()).Execute()
}
\`\`\`

The vault secret is never in the response.
`
  );
}

function assertNoGetSecret(): void {
  const symbol = /\b(GetSecret|getSecret|get_secret)\s*\(/;
  for (const root of [typeScriptOutput, pythonOutput, goOutput]) {
    for (const path of listFiles(root)) {
      if (!/\.(go|py|ts)$/.test(path)) {
        continue;
      }
      if (symbol.test(readFileSync(path, "utf8"))) {
        throw new Error(`${relative(repoRoot, path)} grew GetSecret`);
      }
    }
  }
}

rmSync(tempRoot, { force: true, recursive: true });
mkdirSync(tempRoot, { recursive: true });
mkdirSync(dirname(embedPath), { recursive: true });
cpSync(openApiPath, embedPath);

const version = specVersion();
const tsTemp = resolve(tempRoot, "typescript");

run("Generate TypeScript SDK with Hey API", [
  "pnpm",
  "exec",
  "openapi-ts",
  "--input",
  openApiPath,
  "--output",
  tsTemp,
  "--client",
  "@hey-api/client-fetch",
  "--plugins",
  "@hey-api/sdk",
]);

rmSync(typeScriptOutput, { force: true, recursive: true });
mkdirSync(typeScriptOutput, { recursive: true });
cpSync(tsTemp, typeScriptOutput, { recursive: true });

generateLang("python", version);
generateLang("go", version);
pruneGeneratedSdkOutputs();
rewriteGeneratedTypescriptWithoutEslintDisable();
appendTypeScriptRootExports();
writePackageMetadata(version);
assertNoGetSecret();

run("Format generated SDK outputs", [
  "pnpm",
  "exec",
  "vp",
  "fmt",
  "--no-error-on-unmatched-pattern",
  typeScriptOutput,
  pythonOutput,
  goOutput,
]);

rmSync(tempRoot, { force: true, recursive: true });
console.log("sdk:generate ok");
