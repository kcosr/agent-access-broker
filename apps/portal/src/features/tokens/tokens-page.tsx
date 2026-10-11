// My access › Tokens.
import { Main } from "../../workbench";
import { PortalPage } from "../../app/top-bar";
import { useSelfSubject } from "../../app/active-route";
import { TokenDrawer, TokenListBody, TokenToolbar, useTokenList } from "./token-list";

export function TokensPage() {
  const model = useTokenList(useSelfSubject());
  return (
    <PortalPage drawer={model.open ? <TokenDrawer model={model} /> : null}>
      <Main label="Tokens" toolbar={<TokenToolbar model={model} />} refetching={model.data.query.isFetching && !model.data.loading}>
        <TokenListBody model={model} />
      </Main>
    </PortalPage>
  );
}
