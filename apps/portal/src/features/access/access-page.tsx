// My access › Access: what your agent tokens can reach, by service.
import { useMemo } from "react";
import { Banner, Button, List, Main } from "../../workbench";
import { credentialStatus } from "../../lib/helpers";
import { PortalPage } from "../../app/top-bar";
import { useSelfSubject } from "../../app/active-route";
import { ROUTE } from "../../app/paths";
import { AccessDrawer, AccessRows, AccessSidebar, AccessToolbar, useAccessList } from "./access-list";

export function AccessPage() {
  const model = useAccessList(useSelfSubject());
  const attention = useMemo(
    () => model.data.credentials.filter((credential) => ["Not verified", "Verification failed"].includes(credentialStatus(credential))).length,
    [model.data.credentials]
  );
  return (
    <PortalPage sidebar={<AccessSidebar model={model} />} drawer={model.open ? <AccessDrawer model={model} /> : null}>
      <Main
        label="Access"
        toolbar={<AccessToolbar model={model} />}
        header={
          attention > 0 ? (
            <div className="pt-header-banners">
            <Banner
              tone="warning"
              slim
              actions={
                <Button size="sm" href={ROUTE.credentials}>
                  Open credentials
                </Button>
              }
            >
              {attention === 1 ? "1 credential is" : `${attention} credentials are`} not verified. Actions that use them may fail until they are.
            </Banner>
            </div>
          ) : null
        }
        refetching={(model.options.query.isFetching || model.data.query.isFetching) && !model.options.loading}
      >
        <List full>
          <AccessRows model={model} />
        </List>
      </Main>
    </PortalPage>
  );
}
