// The portal's single app-wide modal slot. Views and mutation hooks open
// dialogs by setting the modal state; `ModalHost` renders it.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation, useNavigationType } from "react-router";
import type { ConfirmModal, ModalState } from "../app-types";
import { modalHasOneTimeSecret } from "../lib/helpers";

export type ConfirmOptions = Omit<ConfirmModal, "type">;

type ModalValue = {
  modal: ModalState;
  setModal: (next: ModalState | ((current: ModalState) => ModalState)) => void;
  closeModal: () => void;
  /** Opens the portal's one confirmation dialog; `onConfirm` failures show inside it. */
  confirm: (options: ConfirmOptions) => void;
};

const ModalContext = createContext<ModalValue | null>(null);

export function ModalProvider({ children }: { children: ReactNode }) {
  const [modal, setModal] = useState<ModalState>(null);
  const location = useLocation();
  const navigationType = useNavigationType();
  // Browser history navigation never leaves a one-time secret on screen.
  useEffect(() => {
    if (navigationType === "POP") setModal((current) => (modalHasOneTimeSecret(current) ? null : current));
  }, [location.key, navigationType]);
  const closeModal = useCallback(() => setModal(null), []);
  const confirm = useCallback((options: ConfirmOptions) => setModal({ type: "confirm", ...options }), []);
  const value = useMemo(() => ({ modal, setModal, closeModal, confirm }), [modal, closeModal, confirm]);
  return <ModalContext.Provider value={value}>{children}</ModalContext.Provider>;
}

export function useModal() {
  const value = useContext(ModalContext);
  if (!value) throw new Error("useModal must be used inside ModalProvider");
  return value;
}
