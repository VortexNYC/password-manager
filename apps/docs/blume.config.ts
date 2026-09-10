import { defineConfig } from "blume";

export default defineConfig({
  title: "Vortex Password Manager",
  description:
    "Agent credential broker. Use injects. The model never holds the secret.",
  logo: {
    image: {
      light: "/logo-light.svg",
      dark: "/logo-dark.svg",
      alt: "Vortex",
    },
    text: "PWM",
    href: "/",
  },
  github: {
    owner: "VortexNYC",
    repo: "password-manager",
    branch: "main",
    dir: "apps/docs",
  },
  content: { root: "content/docs" },
  navigation: {
    tabs: [
      { label: "Docs", path: "/" },
      { label: "API", path: "/reference" },
    ],
  },
  openapi: {
    enabled: true,
    route: "/reference",
    spec: "../../docs/openapi/password-manager.openapi.json",
    codeSamples: ["curl", "js", "python"],
  },
  theme: {
    accent: "oklch(0.1448 0 0)",
    background: {
      light: "oklch(0.947 0.0074 80.72)",
      dark: "oklch(0 0 0)",
    },
    radius: "md",
    mode: "system",
    fonts: {
      display: {
        name: "Hedvig Letters Serif",
        fallback: "serif",
        variants: [{ src: "./fonts/hedvig-letters-serif.woff2", weight: 400 }],
      },
      body: {
        name: "Hedvig Letters Sans",
        fallback: "sans",
        variants: [{ src: "./fonts/hedvig-letters-sans.woff2", weight: 400 }],
      },
      mono: "ibm-plex-mono",
    },
  },
  lastModified: true,
  export: true,
  ai: {
    llmsTxt: true,
    ask: { enabled: false },
    mcp: {
      enabled: true,
      route: "/mcp",
      name: "Vortex Password Manager Docs",
      instructions:
        "Documentation for Vortex Password Manager, the agent credential broker. OpenAPI is the contract. listItems and useItem never return vault secrets. MCP tools list_items and fetch are the same operations.",
    },
  },
  seo: {
    og: { enabled: true },
    sitemap: true,
    robots: true,
    structuredData: true,
  },
  deployment: {
    output: "server",
    adapter: "cloudflare",
    site: "https://vortex.nyc",
    base: "/pwm/docs",
  },
});
