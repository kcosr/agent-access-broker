import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router/dom";
import { applyStoredTheme } from "./workbench";
// The app stylesheet declares the cascade-layer order; the kit lands in `wb`.
import "./styles.css";
import "./workbench/styles/index.css";
import { THEME_KEY } from "./app/theme";
import { createPortalRouter } from "./app/router";

applyStoredTheme(THEME_KEY);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, refetchOnWindowFocus: false, staleTime: 30_000 }
  }
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={createPortalRouter()} />
    </QueryClientProvider>
  </StrictMode>
);
