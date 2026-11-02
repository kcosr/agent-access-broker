import { useLayoutEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Button } from "./Button";
import { Field, Textarea } from "./Form";
import type { TextareaProps } from "./Form";
import { Modal } from "./Modal";

export interface ExpandableTextareaProps extends Omit<
  TextareaProps,
  "ref" | "defaultValue"
> {
  /** Accessible name for the expanded editor and its launcher. */
  label: string;
  /** Both editors share this controlled value; closing never reverts edits. */
  value: string;
  /** Help and validation repeated inside the expanded editor. */
  expandedHint?: ReactNode;
  error?: ReactNode;
  /** Explains how the surrounding form saves the shared value. */
  footerNote?: ReactNode;
}

/** A vertically resizable textarea with a larger, focus-trapped editing view. */
export function ExpandableTextarea({
  label,
  expandedHint,
  error,
  footerNote,
  ...props
}: ExpandableTextareaProps) {
  const [expanded, setExpanded] = useState(false);
  const inline = useRef<HTMLTextAreaElement | null>(null);
  const editor = useRef<HTMLTextAreaElement | null>(null);
  const selection = useRef<{
    start: number;
    end: number;
    direction: "forward" | "backward" | "none";
    scroll: number;
  } | null>(null);
  const remember = (control: HTMLTextAreaElement | null) => {
    if (control)
      selection.current = {
        start: control.selectionStart,
        end: control.selectionEnd,
        direction: control.selectionDirection,
        scroll: control.scrollTop,
      };
  };
  const open = () => {
    remember(inline.current);
    setExpanded(true);
  };
  const close = () => {
    remember(editor.current);
    setExpanded(false);
  };
  useLayoutEffect(() => {
    const control = expanded ? editor.current : inline.current;
    const saved = selection.current;
    if (control && saved) {
      control.setSelectionRange(saved.start, saved.end, saved.direction);
      control.scrollTop = saved.scroll;
    }
  }, [expanded]);
  return (
    <>
      <div className="wb-expandable-textarea" inert={expanded}>
        <Textarea {...props} ref={inline} />
        <div className="wb-expandable-textarea-actions">
          <Button
            size="sm"
            aria-label={`Expand ${label}`}
            aria-haspopup="dialog"
            disabled={props.disabled}
            onClick={open}
          >
            Expand
          </Button>
        </div>
      </div>
      <Modal
        open={expanded}
        onClose={close}
        title={label}
        className="wb-textarea-editor"
        initialFocusRef={editor}
        footerNote={footerNote}
        footer={<Button onClick={close}>Done</Button>}
      >
        <Field label={label} hint={expandedHint} error={error}>
          <Textarea
            {...props}
            ref={editor}
            id={undefined}
            name={undefined}
            form={undefined}
            autoFocus={false}
            aria-label={undefined}
            aria-labelledby={undefined}
            aria-describedby={undefined}
            aria-invalid={error ? true : props["aria-invalid"]}
          />
        </Field>
      </Modal>
    </>
  );
}
