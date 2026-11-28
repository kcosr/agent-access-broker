import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { CSSProperties, ReactNode } from "react";
import { cx } from "../lib/cx";
import {
  OverlayScope,
  tabbableIn,
  useFocusTrap,
  useLayer,
  useOverlayOwner,
} from "../lib/layers";
import { useMediaQuery } from "../lib/media";
import { readStorage, writeStorage } from "../lib/storage";
import { usePaneResize } from "../lib/panes";
import { IconButton } from "./Button";

export interface AppShellProps {
  /**
   * <TopBar>. Omit it when the sidebar carries the navigation (brand,
   * SidebarNav, SidebarFoot): the sidebar then runs the full height.
   */
  topBar?: ReactNode;
  /** <Sidebar>; omit on settings-style pages. */
  sidebar?: ReactNode;
  /**
   * A media query ("(max-width: 900px)") under which the sidebar leaves the
   * layout: a bar atop the main pane holds a Menu button that opens the
   * sidebar over the page. While it is open the page is inert under a scrim
   * and focus stays in the sidebar and the overlays opened from it. Escape,
   * the scrim, a link or a navigation closes it; focus then returns to Menu,
   * or goes to the main pane after a link to another page or a navigation.
   */
  narrow?: string | undefined;
  /**
   * How the narrow layout opens the sidebar: "drawer" (the default), over
   * part of the page beside a scrim, or "sheet", filling the viewport with a
   * Close menu button at its top.
   */
  narrowMenu?: "drawer" | "sheet" | undefined;
  /** The narrow bar's content after the Menu button (a Brand, a way back). */
  narrowBar?: ReactNode;
  /**
   * Keep the narrow sidebar open for selected links, such as section switches
   * inside the sidebar. Their matching URL change also keeps it open; other
   * links and browser navigation still close it.
   */
  keepMenuOpenForLink?: ((link: HTMLAnchorElement) => boolean) | undefined;
  /**
   * Keep the narrow sidebar open through any navigation to a matching
   * address (a link's, or the location after `hashchange` or `popstate`),
   * such as a page that opens it again on arrival.
   */
  keepMenuOpenAt?: ((url: URL) => boolean) | undefined;
  /**
   * localStorage key for the sidebar width (e.g. "my-app:sidebar-width");
   * the collapsed state is stored under `<key>:collapsed`.
   */
  sidebarStorageKey?: string | undefined;
  sidebarMin?: number | undefined;
  sidebarMax?: number | undefined;
  sidebarDefault?: number | undefined;
  /** <Drawer> when an item is open, else null. Pushes the layout (third column). */
  drawer?: ReactNode;
  /** Enable a pointer/keyboard separator on the drawer's left edge. */
  drawerResizable?: boolean | undefined;
  /** Persist a resizable drawer's width independently of its open/closed state. */
  drawerStorageKey?: string | undefined;
  drawerMin?: number | undefined;
  drawerMax?: number | undefined;
  drawerDefault?: number | undefined;
  /** The main pane (<Main>). */
  children?: ReactNode;
  /**
   * id of the <Main> focus target; Main inside the shell uses it by default
   * (default "wb-main").
   */
  mainId?: string | undefined;
  /**
   * Text of the "Skip to content" link rendered first in the shell, or
   * false to leave it out (default "Skip to content").
   */
  skipLink?: string | false | undefined;
  className?: string | undefined;
}

/** The main pane never gets narrower than this. */
const MAIN_MIN = 360;
/**
 * When an open drawer would leave the main pane less than this next to a
 * minimum-width sidebar, the sidebar collapses automatically (wide drawers
 * below ~1460px, any drawer below ~1160px).
 */
const MAIN_COMFORT = 480;
/** The drawer never narrows below this. */
const DRAWER_MIN = 320;
/** Width of the collapsed-sidebar rail (.wb-sidebar-rail). */
const RAIL_W = 44;

function readWidth(
  key: string | undefined,
  min: number,
  max: number,
  fallback: number,
): number {
  if (!key) return fallback;
  const v = Number(readStorage(key));
  return Number.isFinite(v) && v >= min && v <= max ? Math.round(v) : fallback;
}

export interface ShowSidebarOptions {
  /**
   * Move focus into the sidebar once it is visible: "first" (its first
   * control) or a function returning the element, e.g. its search field:
   * `(pane) => pane.querySelector("input")`.
   */
  focus?:
    | "first"
    | ((pane: HTMLElement) => HTMLElement | null | undefined)
    | undefined;
}

export interface AppShellState {
  /** The shell has a sidebar on this page. */
  hasSidebar: boolean;
  /** The sidebar is collapsed (by the user, or automatically for a drawer). */
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  /**
   * Expand the sidebar (it stays expanded while a drawer would collapse it
   * automatically); does nothing to one already shown, except focus.
   */
  showSidebar: (options?: ShowSidebarOptions) => void;
  /** Collapse the sidebar; does nothing to one already collapsed. */
  hideSidebar: () => void;
  /** id of the sidebar pane (for aria-controls). */
  sidebarId: string;
  /** id of the main pane (the skip link's target). */
  mainId: string;
  /**
   * The narrow layout (AppShellProps.narrow) is in effect: the sidebar opens
   * over the page from Menu, and the collapse controls above don't apply.
   */
  narrow: boolean;
  /** In the narrow layout, the sidebar is open over the page. */
  menuOpen: boolean;
  /**
   * Open the narrow layout's sidebar, as Menu does (no effect otherwise).
   * Closing it returns focus to the control focused when it opened, else
   * to Menu.
   */
  openMenu: () => void;
  /**
   * Close the narrow layout's open sidebar (no effect otherwise). Focus goes
   * back to Menu, or with "main" to the main pane: for a change made in the
   * sidebar that navigates without a link, such as switching a project.
   */
  closeMenu: (focus?: "menu" | "main") => void;
}

const AppShellContext = createContext<AppShellState | null>(null);

/**
 * Keyboard skip link: visually hidden until focused, then moves focus to the
 * element with `targetId` (without touching the URL, so hash routers are
 * safe). AppShell renders one; use this outside AppShell.
 */
export function SkipLink({
  targetId = DEFAULT_MAIN_ID,
  children = "Skip to content",
  className,
}: {
  targetId?: string | undefined;
  children?: ReactNode;
  className?: string | undefined;
}) {
  return (
    <a
      className={cx("wb-skip-link", className)}
      href={`#${targetId}`}
      onClick={(e) => {
        e.preventDefault();
        const target = document.getElementById(targetId);
        target?.focus();
        target?.scrollIntoView?.({ block: "nearest" });
      }}
    >
      {children}
    </a>
  );
}

export const DEFAULT_MAIN_ID = "wb-main";

/** Sidebar state of the surrounding AppShell (null outside one). */
export function useAppShell(): AppShellState | null {
  return useContext(AppShellContext);
}

/** Top-bar button that collapses/expands the sidebar; renders nothing without one. */
export function SidebarToggle({
  className,
}: {
  className?: string | undefined;
}) {
  const shell = useAppShell();
  if (!shell?.hasSidebar || shell.narrow) return null;
  return (
    <IconButton
      icon="sidebar"
      label={shell.sidebarCollapsed ? "Show sidebar" : "Hide sidebar"}
      aria-expanded={!shell.sidebarCollapsed}
      aria-controls={shell.sidebarId}
      className={className}
      onClick={shell.toggleSidebar}
    />
  );
}

function cssPx(el: Element, name: string): number {
  const v = parseFloat(getComputedStyle(el).getPropertyValue(name));
  return Number.isFinite(v) ? v : 0;
}

/**
 * The app frame: top bar across (optional), then sidebar | main | drawer. The document
 * never scrolls; only panes do. The sidebar is resizable (drag, or arrow keys
 * on the separator; double-click resets), collapsible (SidebarToggle or the
 * rail), and both are persisted. With a drawer open the layout keeps the main
 * pane at least 360px wide: the sidebar narrows or collapses and the drawer
 * narrows. Below the `narrow` query the sidebar opens over the page instead.
 */
export function AppShell({
  topBar,
  sidebar,
  narrow: narrowQuery,
  narrowMenu = "drawer",
  narrowBar,
  sidebarStorageKey,
  sidebarMin = 220,
  sidebarMax = 480,
  sidebarDefault = 268,
  drawer,
  drawerResizable = false,
  drawerStorageKey,
  drawerMin = 380,
  drawerMax: drawerBound = 900,
  drawerDefault = 540,
  children,
  mainId = DEFAULT_MAIN_ID,
  skipLink = "Skip to content",
  className,
  keepMenuOpenForLink,
  keepMenuOpenAt,
}: AppShellProps) {
  const frame = useRef<HTMLDivElement | null>(null);
  const drawerSlot = useRef<HTMLDivElement | null>(null);
  const pane = useRef<HTMLDivElement | null>(null);
  const rail = useRef<HTMLDivElement | null>(null);
  // Where focus should go once the sidebar is shown again.
  const focusAfter = useRef<ShowSidebarOptions["focus"]>(undefined);
  // Whether focus was last inside the sidebar (browsers may already have
  // moved a hidden element's focus to <body> when the collapse is handled).
  const focusInPane = useRef(false);
  const paneId = `wb-sidebar-${useId()}`;
  const drawerId = `wb-drawer-pane-${useId()}`;
  const collapsedKey = sidebarStorageKey
    ? `${sidebarStorageKey}:collapsed`
    : undefined;
  const [preferred, setPreferred] = useState(() =>
    readWidth(sidebarStorageKey, sidebarMin, sidebarMax, sidebarDefault),
  );
  const [drawerPreferred, setDrawerPreferred] = useState(() =>
    readWidth(drawerStorageKey, drawerMin, drawerBound, drawerDefault),
  );
  const [userCollapsed, setUserCollapsed] = useState(
    () => !!collapsedKey && readStorage(collapsedKey) === "1",
  );
  const [forceExpanded, setForceExpanded] = useState(false);
  const [geo, setGeo] = useState({ frame: 0, drawer: 0 });
  const hasTopBar = topBar !== undefined && topBar !== null && topBar !== false;
  const hasSidebar =
    sidebar !== undefined && sidebar !== null && sidebar !== false;
  const hasDrawer = drawer !== undefined && drawer !== null && drawer !== false;
  const narrow = useMediaQuery(narrowQuery) && hasSidebar;
  const sheet = narrow && narrowMenu === "sheet";
  const [menuWanted, setMenuWanted] = useState(false);
  const menuOpen = narrow && menuWanted;
  const keptMenuLocation = useRef<string | null>(null);
  // Where focus goes when the open narrow sidebar closes.
  const menuReturn = useRef<"menu" | "main" | null>(null);
  const menuButton = useRef<HTMLButtonElement | null>(null);
  // The control focused when the narrow sidebar opened (null: Menu).
  const menuOpener = useRef<HTMLElement | null>(null);
  // The check for a focus lost to a navigation that kept the sidebar open.
  const refocusFrame = useRef(0);

  // Measure the frame and the open drawer's preferred width (its CSS token,
  // not its rendered width, which this component may be limiting).
  useLayoutEffect(() => {
    const update = () => {
      const el = frame.current;
      if (!el) return;
      const d = drawerSlot.current?.firstElementChild;
      const drawerWidth = d
        ? d.classList.contains("wb-drawer")
          ? cssPx(
              d,
              d.classList.contains("wb-drawer--wide")
                ? "--wb-drawer-wide-w"
                : "--wb-drawer-w",
            )
          : (d as HTMLElement).offsetWidth
        : 0;
      setGeo((g) =>
        g.frame === el.clientWidth && g.drawer === drawerWidth
          ? g
          : { frame: el.clientWidth, drawer: drawerWidth },
      );
    };
    update();
    window.addEventListener("resize", update);
    const observer =
      typeof ResizeObserver === "function" ? new ResizeObserver(update) : null;
    if (frame.current) observer?.observe(frame.current);
    if (drawerSlot.current) observer?.observe(drawerSlot.current);
    return () => {
      window.removeEventListener("resize", update);
      observer?.disconnect();
    };
  }, [hasDrawer]);

  // An explicit "show" while a drawer forced the collapse lasts until it closes.
  useEffect(() => {
    if (!hasDrawer) setForceExpanded(false);
  }, [hasDrawer]);

  const laidOut = geo.frame > 0;
  const drawerDesired = hasDrawer
    ? drawerResizable
      ? Math.min(drawerPreferred, drawerBound)
      : geo.drawer
    : 0;
  const autoCollapsed =
    hasSidebar &&
    hasDrawer &&
    laidOut &&
    geo.frame - drawerDesired - sidebarMin < MAIN_COMFORT;
  const collapsed =
    hasSidebar && (userCollapsed || (autoCollapsed && !forceExpanded));
  const sidebarShown = hasSidebar && !collapsed && !narrow;

  const limit = laidOut
    ? Math.max(
        sidebarMin,
        Math.min(sidebarMax, geo.frame - drawerDesired - MAIN_MIN),
      )
    : sidebarMax;
  const width = Math.min(preferred, limit);
  const drawerMax =
    laidOut && hasDrawer
      ? Math.max(
          drawerResizable ? drawerMin : DRAWER_MIN,
          geo.frame -
            (sidebarShown ? width : hasSidebar ? RAIL_W : 0) -
            MAIN_MIN,
        )
      : null;

  const sidebarResize = usePaneResize(
    {
      label: "Sidebar width",
      controls: paneId,
      className: "wb-sidebar-resize",
      cssVar: "--wb-side-w",
      min: sidebarMin,
      max: sidebarMax,
      grow: 1,
    },
    frame,
    {
      enabled: sidebarShown,
      preferred,
      width,
      limit,
      save: (value) => {
        setPreferred(value);
        if (sidebarStorageKey) writeStorage(sidebarStorageKey, String(value));
      },
      reset: () => {
        setPreferred(sidebarDefault);
        if (sidebarStorageKey)
          writeStorage(sidebarStorageKey, String(sidebarDefault));
      },
    },
  );
  const drawerLimit = Math.min(drawerBound, drawerMax ?? drawerBound);
  const drawerWidth = Math.min(drawerPreferred, drawerLimit);
  const drawerResize = usePaneResize(
    {
      label: "Details panel width",
      controls: drawerId,
      cssVar: "--wb-resized-drawer-w",
      min: drawerMin,
      max: drawerBound,
      grow: -1,
    },
    frame,
    {
      enabled: hasDrawer && drawerResizable,
      preferred: drawerPreferred,
      width: drawerWidth,
      limit: drawerLimit,
      save: (value) => {
        setDrawerPreferred(value);
        if (drawerStorageKey) writeStorage(drawerStorageKey, String(value));
      },
      reset: () => {
        setDrawerPreferred(drawerDefault);
        if (drawerStorageKey) writeStorage(drawerStorageKey, null);
      },
    },
  );
  const handle = sidebarResize.handle;

  const focusSidebar = useCallback(
    (target: ShowSidebarOptions["focus"]) => {
      const el = pane.current;
      if (!el || !target) return;
      const to =
        target === "first" ? (tabbableIn(el)[0] ?? handle.current) : target(el);
      to?.focus();
    },
    [handle],
  );

  const showSidebar = useCallback(
    (options: ShowSidebarOptions = {}) => {
      if (!hasSidebar) return;
      if (!collapsed) {
        focusSidebar(options.focus);
        return;
      }
      focusAfter.current = options.focus;
      if (userCollapsed) {
        setUserCollapsed(false);
        if (collapsedKey) writeStorage(collapsedKey, null);
      }
      if (autoCollapsed) setForceExpanded(true);
    },
    [
      hasSidebar,
      collapsed,
      userCollapsed,
      autoCollapsed,
      collapsedKey,
      focusSidebar,
    ],
  );

  const hideSidebar = useCallback(() => {
    if (!hasSidebar || collapsed) return;
    focusAfter.current = undefined;
    if (autoCollapsed) {
      setForceExpanded(false);
    } else {
      setUserCollapsed(true);
      if (collapsedKey) writeStorage(collapsedKey, "1");
    }
  }, [hasSidebar, collapsed, autoCollapsed, collapsedKey]);

  const toggleSidebar = useCallback(() => {
    if (collapsed) showSidebar();
    else hideSidebar();
  }, [collapsed, showSidebar, hideSidebar]);

  const openMenu = useCallback(() => {
    if (!narrow || menuWanted) return;
    // Only a control outside the main pane (a button in the narrow bar)
    // gets focus back; the pane, or a field in it, would just take it again.
    const active = document.activeElement;
    menuOpener.current =
      active instanceof HTMLElement &&
      active !== document.body &&
      active !== menuButton.current &&
      !document.getElementById(mainId)?.contains(active)
        ? active
        : null;
    setMenuWanted(true);
  }, [narrow, menuWanted, mainId]);
  const closeMenu = useCallback((focus: "menu" | "main" = "menu") => {
    setMenuWanted((open) => {
      if (open) menuReturn.current = focus;
      return false;
    });
  }, []);
  // Widened past the query, the sidebar is back in place; narrowing again
  // starts closed.
  useEffect(() => {
    if (!narrow) setMenuWanted(false);
  }, [narrow]);
  // The open narrow sidebar is a layer (Escape closes it after the overlays
  // opened from it) that keeps Tab inside, those overlays included.
  const menuLayers = useLayer(menuOpen, () => closeMenu("menu"));
  const menuOwner = useOverlayOwner(pane);
  useFocusTrap(pane, menuOpen, {
    owner: menuOwner,
    layers: menuLayers,
    restoreFocus: false,
  });
  // The latest predicates, for listeners that stay registered while the menu
  // is open: a consumer rendering again on a navigation (a router, inline
  // functions) must not swap them out in the middle of its events.
  const keepForLink = useRef(keepMenuOpenForLink);
  const keepAt = useRef(keepMenuOpenAt);
  useLayoutEffect(() => {
    keepForLink.current = keepMenuOpenForLink;
    keepAt.current = keepMenuOpenAt;
  });
  // Section-switch links can keep the menu open through their own navigation.
  // Remember the destination across both popstate and hashchange, which can
  // describe the same click. A different navigation still closes the menu,
  // unless its destination is one kept open (`keepMenuOpenAt`).
  useEffect(() => {
    if (!menuOpen) {
      keptMenuLocation.current = null;
      return;
    }
    const el = pane.current;
    const onNavigate = () => {
      const href = window.location.href;
      if (href !== keptMenuLocation.current && !keepAt.current?.(new URL(href)))
        return closeMenu("main");
      // Kept open: if the page's update removed the focused control (a link
      // that led away from what the sidebar showed), focus its first again.
      cancelAnimationFrame(refocusFrame.current);
      refocusFrame.current = requestAnimationFrame(() => {
        const active = document.activeElement;
        if (!active || active === document.body) focusSidebar("first");
      });
    };
    const onClick = (e: MouseEvent) => {
      const link = (e.target as Element).closest<HTMLAnchorElement>("a[href]");
      if (
        !link ||
        e.defaultPrevented ||
        e.button !== 0 ||
        e.metaKey ||
        e.ctrlKey ||
        e.shiftKey ||
        e.altKey
      )
        return;
      if (keepForLink.current?.(link) || keepAt.current?.(new URL(link.href))) {
        keptMenuLocation.current = link.href;
        return;
      }
      keptMenuLocation.current = null;
      closeMenu(link.href === window.location.href ? "menu" : "main");
    };
    window.addEventListener("hashchange", onNavigate);
    window.addEventListener("popstate", onNavigate);
    el?.addEventListener("click", onClick);
    return () => {
      window.removeEventListener("hashchange", onNavigate);
      window.removeEventListener("popstate", onNavigate);
      el?.removeEventListener("click", onClick);
      // A refocus still pending when the menu closes (or the layout widens) must not move focus afterwards.
      cancelAnimationFrame(refocusFrame.current);
    };
  }, [menuOpen, closeMenu, focusSidebar]);
  // After the commit that lifts `inert`, so the target can take focus.
  useLayoutEffect(() => {
    if (menuOpen) return;
    const to = menuReturn.current;
    const opener = menuOpener.current;
    menuReturn.current = null;
    menuOpener.current = null;
    if (to === "menu")
      (opener?.isConnected ? opener : menuButton.current)?.focus();
    else if (to === "main")
      document.getElementById(mainId)?.focus({ preventScroll: true });
  }, [menuOpen, mainId]);

  // Keep keyboard focus alive across collapse/expand, without fighting other
  // focus owners (a closing drawer returning focus to its row): expanding
  // moves focus into the sidebar only when asked (the rail, showSidebar's
  // `focus`); collapsing moves it to the rail only when it was inside.
  const wasCollapsed = useRef(collapsed);
  useLayoutEffect(() => {
    if (wasCollapsed.current === collapsed) return;
    wasCollapsed.current = collapsed;
    const want = focusAfter.current;
    focusAfter.current = undefined;
    if (!collapsed) {
      focusSidebar(want);
    } else if (
      pane.current?.contains(document.activeElement) ||
      (focusInPane.current &&
        (!document.activeElement || document.activeElement === document.body))
    ) {
      rail.current?.querySelector<HTMLElement>("button")?.focus();
    }
  }, [collapsed]);

  const shellState = useMemo<AppShellState>(
    () => ({
      hasSidebar,
      sidebarCollapsed: collapsed,
      toggleSidebar,
      showSidebar,
      hideSidebar,
      sidebarId: paneId,
      mainId,
      narrow,
      menuOpen,
      openMenu,
      closeMenu,
    }),
    [
      hasSidebar,
      collapsed,
      toggleSidebar,
      showSidebar,
      hideSidebar,
      paneId,
      mainId,
      narrow,
      menuOpen,
      openMenu,
      closeMenu,
    ],
  );

  const style: Record<string, string> = {};
  if (sidebarShown) style["--wb-side-w"] = `${width}px`;
  if (drawerMax !== null) style["--wb-drawer-max"] = `${drawerMax}px`;
  if (drawerResizable) style["--wb-resized-drawer-w"] = `${drawerWidth}px`;

  return (
    <AppShellContext.Provider value={shellState}>
      <div
        ref={frame}
        className={cx(
          "wb-app",
          !hasTopBar && "wb-app--no-topbar",
          narrow && "wb-app--narrow",
          sheet && "wb-app--menu-sheet",
          menuOpen && "is-menu-open",
          (sidebarResize.dragging || drawerResize.dragging) && "is-resizing",
          className,
        )}
        style={style as CSSProperties}
      >
        {/* While the narrow sidebar is open the page is inert: the skip link would lead nowhere. */}
        {skipLink === false || menuOpen ? null : (
          <SkipLink targetId={mainId}>{skipLink}</SkipLink>
        )}
        {/* Its own box: the top bar is inert with the page while the narrow sidebar is open. */}
        {hasTopBar ? (
          <div className="wb-app-topbar" inert={menuOpen}>
            {topBar}
          </div>
        ) : null}
        {menuOpen && !sheet ? (
          <div
            className="wb-scrim wb-narrow-scrim"
            aria-hidden="true"
            onClick={() => closeMenu("menu")}
          />
        ) : null}
        {hasSidebar && collapsed && !narrow ? (
          <div className="wb-sidebar-rail" ref={rail}>
            <IconButton
              icon="sidebar"
              label="Show sidebar"
              aria-expanded={false}
              aria-controls={paneId}
              onClick={() => showSidebar({ focus: "first" })}
            />
          </div>
        ) : null}
        {hasSidebar ? (
          <div
            className="wb-sidebar-pane"
            id={paneId}
            ref={pane}
            hidden={narrow ? !menuOpen : collapsed}
            onFocus={() => {
              focusInPane.current = true;
            }}
            onBlur={(e) => {
              if (!e.currentTarget.contains(e.relatedTarget as Node | null))
                focusInPane.current = false;
            }}
          >
            {sheet ? (
              <div className="wb-menu-sheet-bar">
                <IconButton
                  icon="x"
                  label="Close menu"
                  onClick={() => closeMenu("menu")}
                />
              </div>
            ) : null}
            {narrowQuery ? (
              <OverlayScope layers={menuLayers} owner={menuOwner}>
                {sidebar}
              </OverlayScope>
            ) : (
              sidebar
            )}
            {sidebarResize.separator}
          </div>
        ) : null}
        <div className="wb-app-main" inert={menuOpen}>
          {narrow ? (
            <header className="wb-narrow-bar">
              <IconButton
                ref={menuButton}
                icon="list"
                label="Menu"
                aria-expanded={menuOpen}
                aria-controls={paneId}
                onClick={() => {
                  if (menuOpen) closeMenu("menu");
                  else {
                    menuOpener.current = null;
                    setMenuWanted(true);
                  }
                }}
              />
              {narrowBar}
            </header>
          ) : null}
          {children}
        </div>
        {hasDrawer ? (
          <div
            className={cx("wb-app-drawer", drawerResizable && "is-resizable")}
            inert={menuOpen}
            ref={drawerSlot}
            id={drawerId}
            data-wb-drawer-slot=""
          >
            {drawer}
            {drawerResizable ? drawerResize.separator : null}
          </div>
        ) : null}
      </div>
    </AppShellContext.Provider>
  );
}
