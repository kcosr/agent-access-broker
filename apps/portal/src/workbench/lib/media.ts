import { useEffect, useState } from "react";

function matches(query: string | null | undefined): boolean {
  return (
    !!query &&
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia(query).matches
  );
}

/**
 * Whether the media query matches now, following changes (false without a
 * query or without matchMedia): `useMediaQuery("(max-width: 760px)")`.
 */
export function useMediaQuery(query: string | null | undefined): boolean {
  const [state, setState] = useState(() => matches(query));
  useEffect(() => {
    if (!query || typeof window.matchMedia !== "function") {
      setState(false);
      return;
    }
    const media = window.matchMedia(query);
    const update = () => setState(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [query]);
  return state;
}
