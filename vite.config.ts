import { defineConfig } from "vite-plus";

export default defineConfig({
  run: {
    cache: true,
  },
  fmt: {
    ignorePatterns: [
      "**/*.gen.*",
      "sdks/python/**",
      "sdks/go/**",
      "apps/docs/.blume/**",
      "apps/docs/.astro/**",
      "apps/docs/dist/**",
    ],
  },
  lint: {
    ignorePatterns: [
      "**/*.gen.*",
      "sdks/python/**",
      "sdks/go/**",
      "apps/docs/.blume/**",
      "apps/docs/.astro/**",
      "apps/docs/dist/**",
    ],
  },
});
