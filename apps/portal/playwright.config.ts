import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  forbidOnly: true,
  testDir: "./tests",
  timeout: 120_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: {
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure"
  },
  projects: [
    {
      name: "chromium-desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 900 }
      }
    }
  ]
});
