import { useEffect, useRef, useState } from "react";
import { accessDraft, refreshAccessDraft, keepAccessDraft, accessDraftPatch, type AccessFields } from "../../lib/access-draft";

export function useAccessDraft<T extends AccessFields>(latest: T) {
  const [draft, setDraft] = useState(() => accessDraft(latest));
  const [kept, setKept] = useState(false);
  const current = useRef(draft);
  current.current = draft;
  const latestKey = JSON.stringify(latest);
  useEffect(() => { setDraft((value) => refreshAccessDraft(value, latest)); }, [latestKey]);
  function refresh(saved: T) {
    const next = refreshAccessDraft(current.current, saved);
    current.current = next;
    setDraft(next);
    return next;
  }
  return {
    ...draft,
    kept,
    changed: Object.keys(accessDraftPatch(draft)).length > 0,
    edit: (value: T) => setDraft((prior) => ({ ...prior, value })),
    discard: () => { setDraft(accessDraft(latest)); setKept(false); },
    keep: () => { setDraft((value) => keepAccessDraft(value, latest)); setKept(true); },
    refresh,
    committed: (value: T) => { setDraft(accessDraft(value)); setKept(false); },
  };
}
