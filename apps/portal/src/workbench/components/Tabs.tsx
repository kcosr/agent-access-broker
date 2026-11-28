import { useEffect, useId, useRef, useState } from "react";
import type {
  KeyboardEvent,
  MouseEventHandler,
  ReactNode,
  RefObject,
} from "react";
import { cx } from "../lib/cx";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { useLinkComponent } from "./Link";

export interface TabItem<T extends string = string> {
  value: T;
  label: ReactNode;
  icon?: IconName | undefined;
  count?: number | string | undefined;
  disabled?: boolean | undefined;
}

/** Id of the tab for `value` in the Tabs with id `tabsId`. */
export function tabId(tabsId: string, value: string): string {
  return `${tabsId}-tab-${idPart(value)}`;
}

/** Id of the tab panel for `value` in the Tabs with id `tabsId`. */
export function tabPanelId(tabsId: string, value: string): string {
  return `${tabsId}-panel-${idPart(value)}`;
}

// Ids can't contain whitespace.
function idPart(value: string): string {
  return value.replace(/\s+/g, "_");
}

/**
 * A tab row too narrow for its tabs scrolls: `is-fade-start` / `is-fade-end`
 * while more tabs hide past that edge, which then fades out. `content`
 * changes when the tabs do.
 */
function useOverflowFade(
  ref: RefObject<HTMLElement | null>,
  content: string,
): string | undefined {
  const [edges, setEdges] = useState({ start: false, end: false });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => {
      const start = el.scrollLeft > 1;
      const end = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
      setEdges((e) =>
        e.start === start && e.end === end ? e : { start, end },
      );
    };
    update();
    el.addEventListener("scroll", update, { passive: true });
    const observer =
      typeof ResizeObserver === "function" ? new ResizeObserver(update) : null;
    observer?.observe(el);
    return () => {
      el.removeEventListener("scroll", update);
      observer?.disconnect();
    };
  }, [ref, content]);
  return (
    cx(edges.start && "is-fade-start", edges.end && "is-fade-end") || undefined
  );
}

interface TabsBaseProps<T extends string> {
  /** Accessible name of the tab list. */
  label: string;
  value: T;
  onChange: (value: T) => void;
  items: readonly TabItem<T>[];
  /** Tighter tabs in smaller text, for a narrow pane or a phone. */
  compact?: boolean | undefined;
  className?: string | undefined;
}

export type TabsProps<T extends string> = TabsBaseProps<T> &
  (
    | {
        /** Content of the selected tab, rendered in the wired-up tabpanel. */
        children?: ReactNode;
        detached?: false | undefined;
        id?: string | undefined;
        panelClassName?: string | undefined;
      }
    | {
        /**
         * The panel is rendered elsewhere with <TabPanel tabsId={id}
         * value={value}> (e.g. tabs in Main's fixed `header`, content in
         * the scroll region). The selected tab points at it.
         */
        detached: true;
        /** Required: TabPanel refers to the tabs by it. */
        id: string;
        children?: undefined;
        panelClassName?: undefined;
      }
  );

/**
 * In-page underline tabs (ARIA tablist; arrows/Home/End move and select).
 * For URL-driven tabs use LinkTabs.
 */
export function Tabs<T extends string>(props: TabsProps<T>) {
  const { label, value, onChange, items, children, id, compact, className } =
    props;
  const auto = useId();
  const base = id ?? `wb-tabs-${auto}`;
  const list = useRef<HTMLDivElement | null>(null);
  const fade = useOverflowFade(list, items.map((t) => t.value).join("\n"));
  const hasPanel = props.detached === true || children !== undefined;
  const idOf = (v: string) => tabId(base, v);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const enabled = items.filter((t) => !t.disabled);
    const i = enabled.findIndex((t) => t.value === value);
    let next: TabItem<T> | undefined;
    if (e.key === "ArrowRight") next = enabled[(i + 1) % enabled.length];
    else if (e.key === "ArrowLeft")
      next = enabled[(i - 1 + enabled.length) % enabled.length];
    else if (e.key === "Home") next = enabled[0];
    else if (e.key === "End") next = enabled[enabled.length - 1];
    if (!next) return;
    e.preventDefault();
    onChange(next.value);
    list.current
      ?.querySelector<HTMLElement>(`#${CSS.escape(idOf(next.value))}`)
      ?.focus();
  };

  return (
    <>
      <div
        ref={list}
        role="tablist"
        aria-label={label}
        className={cx(
          "wb-tabs",
          compact && "wb-tabs--compact",
          fade,
          className,
        )}
        onKeyDown={onKeyDown}
      >
        {items.map((t) => {
          const selected = t.value === value;
          return (
            <button
              key={t.value}
              id={idOf(t.value)}
              type="button"
              role="tab"
              className="wb-tab"
              aria-selected={selected}
              aria-controls={
                hasPanel && selected ? tabPanelId(base, t.value) : undefined
              }
              tabIndex={selected ? 0 : -1}
              disabled={t.disabled}
              onClick={() => {
                if (!selected) onChange(t.value);
              }}
            >
              {t.icon ? <Icon name={t.icon} /> : null}
              {t.label}
              {t.count !== undefined ? (
                <>
                  {" "}
                  <span className="wb-tab-count">{t.count}</span>
                </>
              ) : null}
            </button>
          );
        })}
      </div>
      {children !== undefined && !props.detached ? (
        <TabPanel tabsId={base} value={value} className={props.panelClassName}>
          {children}
        </TabPanel>
      ) : null}
    </>
  );
}

/**
 * The panel of detached <Tabs detached id=…>: render it wherever the
 * content goes, with the same `tabsId` and the selected `value`.
 */
export function TabPanel({
  tabsId,
  value,
  children,
  className,
}: {
  tabsId: string;
  value: string;
  children?: ReactNode;
  className?: string | undefined;
}) {
  return (
    <div
      role="tabpanel"
      id={tabPanelId(tabsId, value)}
      aria-labelledby={tabId(tabsId, value)}
      tabIndex={0}
      className={cx("wb-tabpanel", className)}
    >
      {children}
    </div>
  );
}

export interface LinkTabItem {
  href: string;
  label: ReactNode;
  current: boolean;
  icon?: IconName | undefined;
  count?: number | string | undefined;
  /** E.g. to replace the history entry instead of adding one. */
  onClick?: MouseEventHandler<HTMLAnchorElement> | undefined;
}

/** URL-driven tabs: the same underline look, rendered as navigation links (aria-current="page"). */
export function LinkTabs({
  label,
  items,
  compact,
  className,
}: {
  label: string;
  items: readonly LinkTabItem[];
  /** Tighter tabs in smaller text, for a narrow pane or a phone. */
  compact?: boolean | undefined;
  className?: string | undefined;
}) {
  const Link = useLinkComponent();
  const nav = useRef<HTMLElement | null>(null);
  const fade = useOverflowFade(nav, items.map((t) => t.href).join("\n"));
  return (
    <nav
      ref={nav}
      aria-label={label}
      className={cx("wb-tabs", compact && "wb-tabs--compact", fade, className)}
    >
      {items.map((t) => (
        <Link
          key={t.href}
          href={t.href}
          className="wb-tab"
          aria-current={t.current ? "page" : undefined}
          onClick={t.onClick}
        >
          {t.icon ? <Icon name={t.icon} /> : null}
          {t.label}
          {t.count !== undefined ? (
            <>
              {" "}
              <span className="wb-tab-count">{t.count}</span>
            </>
          ) : null}
        </Link>
      ))}
    </nav>
  );
}
