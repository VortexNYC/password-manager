import {
  defineRailway,
  image,
  postgres,
  preserve,
  project,
  service,
  volume,
} from "railway/iac";

// Hydra preDeploy is SQL migrate (no volume). pwm must not preDeploy:
// Railway pre-deploy does not mount volumes.
// pwm start is exec form (Dockerfile/distroless, no shell). Binary binds $PORT.
export default defineRailway(() => {
  const db = postgres("Postgres");

  const hydra = service("hydra", {
    source: image("oryd/hydra:v26.2.0"),
    preDeploy: "hydra migrate sql -e --yes",
    start: "hydra serve all --sqa-opt-out",
    domains: ["id.veil.nyc"],
    env: {
      DSN: db.env.DATABASE_URL,
      PORT: "4444",
      SECRETS_SYSTEM: preserve(),
      HYDRA_SYSTEM_SECRET: preserve(),
      OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT: preserve(),
      OIDC_SUBJECT_IDENTIFIERS_SUPPORTED_TYPES: "public",
      SERVE_PUBLIC_HOST: "0.0.0.0",
      SERVE_PUBLIC_PORT: "4444",
      SERVE_ADMIN_HOST: "0.0.0.0",
      SERVE_ADMIN_PORT: "4445",
      SERVE_COOKIES_SAME_SITE_MODE: "Lax",
      URLS_SELF_ISSUER: "https://id.veil.nyc",
      URLS_LOGIN: preserve(),
      URLS_CONSENT: preserve(),
      URLS_LOGOUT: preserve(),
    },
  });

  const pwm = service("pwm", {
    start: "/password-manager mcp",
    domains: ["veil.nyc"],
    env: {
      PORT: "4461",
      PWM_HOME: "/data",
      PWM_HYDRA_ISSUER: "https://id.veil.nyc",
      PWM_HYDRA_ADMIN: preserve(),
      PWM_MCP_URL: "https://veil.nyc/mcp",
    },
    volumeMounts: {
      "/data": volume("pwm-volume"),
    },
  });

  return project("password-manager", {
    resources: [db, hydra, pwm],
  });
});
