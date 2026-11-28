import { useLayoutEffect, useRef, useState } from "react";
import type { MouseEventHandler, ReactNode } from "react";
import { cx } from "../lib/cx";
import { IconButton } from "./Button";
import { useLinkComponent } from "./Link";
import { Menu } from "./Popover";
import type { MenuEntry } from "./Popover";

export interface NavigationTabsProps {
  label: string;
  children: ReactNode;
  /** Change when navigation selects another item or the inventory is filtered. */
  revealKey?: string | undefined;
  /** Wait until the inventory has loaded before revealing the current item. */
  settled?: boolean | undefined;
  className?: string | undefined;
}

/** A compact, scrolling row of page links. Polling does not undo manual scrolling. */
export function NavigationTabs({
  label,
  children,
  revealKey = "",
  settled = true,
  className,
}: NavigationTabsProps) {
  const track = useRef<HTMLDivElement>(null);
  const revealed = useRef({ key: revealKey, done: false });
  // A pointer selection already has a place in the viewport. Keep that place
  // while the selected page and its refreshed inventory arrive independently.
  const anchor = useRef<{
    link: HTMLAnchorElement;
    from: string | null;
    left: number;
    scroll: number;
    key: string;
    selected: boolean;
  } | null>(null);
  const [edges, setEdges] = useState({ start: false, end: false });
  const update = () => {
    const el = track.current;
    if (!el) return;
    const start = el.scrollLeft > 1;
    const end = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((current) =>
      current.start === start && current.end === end ? current : { start, end },
    );
  };
  const reveal = () => {
    const el = track.current;
    const item = el
      ?.querySelector('[aria-current="page"]')
      ?.closest<HTMLElement>(".wb-navigation-tab");
    if (!el || !item || el.clientWidth === 0) return false;
    const viewport = el.getBoundingClientRect();
    const bounds = item.getBoundingClientRect();
    if (bounds.left < viewport.left)
      el.scrollLeft += bounds.left - viewport.left;
    else if (bounds.right > viewport.right)
      el.scrollLeft += bounds.right - viewport.right;
    return true;
  };
  // Children can settle after the surrounding row, without changing its key.
  useLayoutEffect(() => {
    if (revealed.current.key !== revealKey)
      revealed.current = { key: revealKey, done: false };
    const el = track.current;
    const held = anchor.current;
    if (el && held) {
      const current =
        el.querySelector('[aria-current="page"]')?.getAttribute("href") ?? null;
      const href = held.link.getAttribute("href");
      if (
        el.clientWidth === 0 ||
        !el.contains(held.link) ||
        el.scrollLeft !== held.scroll ||
        (held.selected && held.key !== revealKey) ||
        (current !== href && current !== held.from)
      ) {
        anchor.current = null;
      } else {
        const item = held.link.closest<HTMLElement>(".wb-navigation-tab")!;
        const delta =
          item.getBoundingClientRect().left -
          el.getBoundingClientRect().left -
          held.left;
        if (delta !== 0) el.scrollLeft += delta;
        held.scroll = el.scrollLeft;
        // Scroll boundaries can prevent preserving the exact position.
        held.left =
          item.getBoundingClientRect().left - el.getBoundingClientRect().left;
        if (current === href) {
          held.selected = true;
          held.key = revealKey;
          revealed.current.done = true;
        }
        update();
        return;
      }
    }
    if (settled && !revealed.current.done) revealed.current.done = reveal();
    update();
  });
  useLayoutEffect(() => {
    const el = track.current;
    if (!el) return;
    let width = el.clientWidth;
    const resize = () => {
      const next = el.clientWidth;
      if (next !== width && next > 0 && settled) {
        anchor.current = null;
        revealed.current.done = reveal();
      }
      width = next;
      update();
    };
    const observer =
      typeof ResizeObserver === "function" ? new ResizeObserver(resize) : null;
    observer?.observe(el);
    return () => observer?.disconnect();
  }, [settled]);
  const scroll = (direction: number) => {
    anchor.current = null;
    const el = track.current;
    if (!el) return;
    el.scrollBy({
      left: direction * Math.max(100, el.clientWidth * 0.75),
      behavior: window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
        ? "instant"
        : "smooth",
    });
  };
  return (
    <nav className={cx("wb-navigation-tabs", className)} aria-label={label}>
      <IconButton
        icon="chevron-left"
        label={`Scroll ${label.toLowerCase()} left`}
        size="sm"
        variant="ghost"
        aria-disabled={!edges.start}
        tabIndex={edges.start || edges.end ? 0 : -1}
        onClick={() => {
          if (edges.start) scroll(-1);
        }}
        className="wb-navigation-tabs-arrow"
      />
      <div
        ref={track}
        className="wb-navigation-tabs-track"
        onPointerDown={() => {
          anchor.current = null;
        }}
        onWheel={() => {
          anchor.current = null;
        }}
        onScroll={() => {
          if (
            anchor.current &&
            track.current?.scrollLeft !== anchor.current.scroll
          )
            anchor.current = null;
          update();
        }}
        onClick={(event) => {
          if (
            event.defaultPrevented ||
            event.button !== 0 ||
            event.detail === 0 ||
            event.metaKey ||
            event.ctrlKey ||
            event.shiftKey ||
            event.altKey
          )
            return;
          const el = event.currentTarget;
          const link = (event.target as Element).closest<HTMLAnchorElement>(
            ".wb-navigation-tab-link",
          );
          if (
            !link ||
            !el.contains(link) ||
            link.target === "_blank" ||
            link.hasAttribute("download")
          )
            return;
          const item = link.closest<HTMLElement>(".wb-navigation-tab")!;
          anchor.current = {
            link,
            from:
              el.querySelector('[aria-current="page"]')?.getAttribute("href") ??
              null,
            left:
              item.getBoundingClientRect().left -
              el.getBoundingClientRect().left,
            scroll: el.scrollLeft,
            key: revealKey,
            selected: false,
          };
        }}
      >
        {children}
      </div>
      <IconButton
        icon="chevron-right"
        label={`Scroll ${label.toLowerCase()} right`}
        size="sm"
        variant="ghost"
        aria-disabled={!edges.end}
        tabIndex={edges.start || edges.end ? 0 : -1}
        onClick={() => {
          if (edges.end) scroll(1);
        }}
        className="wb-navigation-tabs-arrow"
      />
    </nav>
  );
}

export interface NavigationTabProps {
  href: string;
  title: string;
  current?: boolean | undefined;
  leading?: ReactNode;
  trailing?: ReactNode;
  actions?: readonly MenuEntry[] | undefined;
  onClick?: MouseEventHandler<HTMLAnchorElement> | undefined;
}

/** A page link and its actions; opening actions never follows or selects the link. */
export function NavigationTab({
  href,
  title,
  current,
  leading,
  trailing,
  actions,
  onClick,
}: NavigationTabProps) {
  const Link = useLinkComponent();
  const item = useRef<HTMLDivElement>(null);
  const showMenu = () => {
    const trigger = item.current?.querySelector<HTMLButtonElement>(
      ":scope > .wb-navigation-tab-more",
    );
    if (trigger && trigger.getAttribute("aria-expanded") !== "true")
      trigger.click();
  };
  const hasActions = !!actions?.length;
  const label = `Actions for ${title}`;
  return (
    <div
      ref={item}
      className={cx("wb-navigation-tab", current && "is-current")}
      onContextMenu={(event) => {
        // Menu content is portaled but its React events still bubble here.
        if (!hasActions) return;
        event.preventDefault();
        if (event.currentTarget.contains(event.target as Node)) showMenu();
      }}
      onKeyDown={(event) => {
        if (
          hasActions &&
          event.currentTarget.contains(event.target as Node) &&
          (event.key === "ContextMenu" ||
            (event.shiftKey && event.key === "F10"))
        ) {
          event.preventDefault();
          showMenu();
        }
      }}
    >
      <Link
        href={href}
        className="wb-navigation-tab-link"
        aria-current={current ? "page" : undefined}
        title={title}
        onClick={onClick}
      >
        {leading}
        <span className="wb-navigation-tab-title">{title}</span>
        {trailing}
      </Link>
      {hasActions ? (
        <Menu
          label={label}
          items={actions}
          trigger={(props) => (
            <IconButton
              {...props}
              icon="more-vertical"
              label={label}
              size="sm"
              variant="ghost"
              className="wb-navigation-tab-more"
            />
          )}
        />
      ) : null}
    </div>
  );
}
