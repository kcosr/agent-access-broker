import { canWriteAdmin } from "../../lib/capabilities";
import { AdminIconButton, AdminForm, AdminButton } from "../../components/admin-access";
// A managed user's identity token (workspace access). Revealed values stay in
// this mounted section, never in the shared query cache; only metadata is cached.
import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { brokerApi } from "../../api";
import type { IdentityTokenMetadata } from "../../types";
import { errorMessage } from "../../lib/helpers";
import { portalQueryKeys, viewerKey } from "../../lib/portal-queries";
import { Badge, ErrorState, Input, SettingsRow, SettingsSection, SkeletonBlock, Time, useToast } from "../../workbench";
import { FormError } from "../../components/form";
import { useModal } from "../../app/modal";
import { useSession } from "../../app/session";
import { useIdentityToken } from "../../data/queries";

type Change = "generate" | "remove" | "set";

export function IdentityTokenSection({ principalId }: { principalId: string }) {
  const { session, attempt } = useSession();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { confirm } = useModal();
  const query = useIdentityToken(principalId);
  const { data: metadata, isPending } = query;
  const [revealed, setRevealed] = useState<string>();
  const [replacement, setReplacement] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  async function reveal(copy: boolean) {
    setPending(copy ? "copy" : "reveal");
    setError(null);
    try {
      const result = await attempt((current) => brokerApi.adminRevealIdentityToken(current, principalId));
      if (!mounted.current) return;
      if (copy) {
        await navigator.clipboard.writeText(result.token);
        toast("Identity token copied");
      } else {
        setRevealed(result.token);
      }
    } catch (failure) {
      if (mounted.current) setError(copy ? "Could not copy the identity token. Reveal it to copy manually." : errorMessage(failure));
    } finally {
      if (mounted.current) setPending(null);
    }
  }

  async function change(action: Change) {
    setRevealed(undefined);
    const result = await attempt((current) =>
      action === "set" ? brokerApi.adminSetIdentityToken(current, principalId, replacement) : brokerApi.adminIdentityTokenAction(current, principalId, action)
    );
    queryClient.setQueryData<IdentityTokenMetadata>(portalQueryKeys.identityToken(viewerKey(session), principalId), result);
    if (mounted.current) setReplacement("");
    toast("Identity token updated", { tone: "success" });
  }

  const confirmChange = (action: "generate" | "remove" | "set") =>
    confirm({
      title: action === "remove" ? "Remove identity token?" : action === "generate" ? "Generate a new identity token?" : "Save this identity token?",
      body:
        action === "remove"
          ? "Fingerprint access stops until an administrator sets a token again. The token’s Enabled and Read-only settings, username bindings, the shared identity pause, and issued Broker tokens remain unchanged."
          : "Update clients that present this identity token to use the matching value. The token’s Enabled and Read-only settings, username bindings, and the shared identity pause remain unchanged.",
      confirmLabel: action === "remove" ? "Remove token" : action === "generate" ? "Generate token" : "Save token",
      tone: action === "remove" ? "danger" : "primary",
      onConfirm: () => change(action)
    });

  const status = metadata ? (metadata.configured ? "Configured" : "Not configured") : null;
  // Its Enabled and Read-only settings are the identity token row of Access paths above.
  const disabledNote = metadata && !metadata.enabled ? <p className="pt-prose">This identity token is disabled in Access paths. Fingerprint access is denied while the secret is kept.</p> : null;
  if (query.isError) return <SettingsSection title="Identity token"><ErrorState title="Couldn’t load identity token" error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /></SettingsSection>;
  if (!canWriteAdmin(session)) return <SettingsSection title="Identity token" description="Workspace identity metadata. Secret values require Administrator access." actions={status ? <Badge>{status}</Badge> : null}>
    {metadata ? <><p className="pt-prose">{status} · Updated <Time value={metadata.updatedAt} format="datetime" /></p>{disabledNote}</> : <SkeletonBlock lines={2} />}
  </SettingsSection>;
  return (
    <SettingsSection
      title="Identity token"
      description="Administrator-managed secret for trusted fingerprint access. Its Enabled and Read-only settings are in Access paths above and are kept when the secret changes. Issued Broker tokens are managed on the Tokens tab."
      actions={status ? <Badge tone={!metadata?.configured ? "neutral" : "success"}>{status}</Badge> : null}
    >
      {isPending || !metadata ? (
        <SkeletonBlock lines={3} />
      ) : (
        <>
          {disabledNote}
          <SettingsRow label="Current token" help={metadata.configured ? "Reveal or copy it; the value is never cached." : "No token is set."}>
            <Input mono readOnly type={revealed ? "text" : "password"} value={revealed ?? (metadata.configured ? "••••••••••••••••" : "")} autoComplete="off" aria-label="Current identity token" />
            <AdminIconButton
              variant="default"
              icon={revealed ? "eye-off" : "eye"}
              label={revealed ? "Hide identity token" : "Reveal identity token"}
              disabled={!metadata.configured || pending !== null}
              onClick={() => (revealed ? setRevealed(undefined) : void reveal(false))}
            />
            <AdminIconButton variant="default" icon="copy" label="Copy identity token" disabled={!metadata.configured || pending !== null} onClick={() => void reveal(true)} />
          </SettingsRow>
          <SettingsRow label="Set a token" help="An existing value from your workspace setup, or a replacement.">
            <AdminForm
              className="flex flex-1 gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                if (replacement) confirmChange("set");
              }}
            >
              <Input
                mono
                type="password"
                className="flex-1"
                value={replacement}
                onChange={(event) => setReplacement(event.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                aria-label="Existing or replacement identity token"
              />
              <AdminButton type="submit" disabled={!replacement}>
                Set token
              </AdminButton>
            </AdminForm>
          </SettingsRow>
          <FormError error={error} />
          <div className="wb-settings-actions">
            <AdminButton icon="refresh" onClick={() => confirmChange("generate")}>
              Generate token
            </AdminButton>
            <AdminButton variant="danger-ghost" icon="trash" disabled={!metadata.configured} onClick={() => confirmChange("remove")}>
              Remove token
            </AdminButton>
          </div>
        </>
      )}
    </SettingsSection>
  );
}
