import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { thirdPartyNotices } from "./scripts/third-party-notices.mjs";

export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss(), thirdPartyNotices()],
  build: {
    rolldownOptions: {
      output: {
        postBanner: "/* Dependency notices: ../licenses/THIRD-PARTY-NOTICES.txt */"
      }
    }
  }
});
