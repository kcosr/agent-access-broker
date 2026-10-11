// Root route: portal-wide providers around the routed page.
import { Link, Outlet } from "react-router";
import { LinkProvider, ToastProvider, type LinkProps } from "../workbench";
import { ResourceTypesProvider } from "../lib/resource-types";
import { useResourceTypesQuery } from "../data/queries";
import { ModalHost } from "./modal-host";
import { ModalProvider } from "./modal";
import { PaletteProvider } from "./palette";
import { SessionProvider } from "./session";

function RouterLink({ href, ...rest }: LinkProps) {
  return <Link to={href} {...rest} />;
}

function ResourceTypes({ children }: { children: React.ReactNode }) {
  return <ResourceTypesProvider value={useResourceTypesQuery()}>{children}</ResourceTypesProvider>;
}

export function RootLayout() {
  return (
    <LinkProvider component={RouterLink}>
      <ToastProvider>
        <ModalProvider>
          <SessionProvider>
            <ResourceTypes>
              <PaletteProvider>
                <Outlet />
                <ModalHost />
              </PaletteProvider>
            </ResourceTypes>
          </SessionProvider>
        </ModalProvider>
      </ToastProvider>
    </LinkProvider>
  );
}
