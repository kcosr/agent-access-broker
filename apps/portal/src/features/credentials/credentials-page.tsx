// My access › Credentials.
import { List, Main } from "../../workbench";
import { PortalPage } from "../../app/top-bar";
import { useSelfSubject } from "../../app/active-route";
import { CredentialDrawer, CredentialRows, CredentialToolbar, useCredentialList } from "./credential-list";

export function CredentialsPage() {
  const model = useCredentialList(useSelfSubject());
  return (
    <PortalPage drawer={model.open ? <CredentialDrawer model={model} /> : null}>
      <Main label="Credentials" toolbar={<CredentialToolbar model={model} />} refetching={model.data.query.isFetching && !model.data.loading}>
        <List full>
          <CredentialRows model={model} />
        </List>
      </Main>
    </PortalPage>
  );
}
