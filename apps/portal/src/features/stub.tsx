// Placeholder page used while a feature is being built.
import { EmptyState, List, Main } from "../workbench";
import { PortalPage } from "../app/top-bar";

export function StubPage({ title }: { title: string }) {
  return (
    <PortalPage>
      <Main label={title}>
        <List>
          <EmptyState icon="layers" title={title}>
            This page is being rebuilt.
          </EmptyState>
        </List>
      </Main>
    </PortalPage>
  );
}
