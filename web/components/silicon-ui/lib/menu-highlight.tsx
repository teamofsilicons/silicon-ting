"use client";

import { useEffect, useRef, useState } from "react";
import type { FocusEvent } from "react";
import { motion, useReducedMotion } from "motion/react";
import { motionTokens } from "./motion-tokens";

type Highlight = { top: number; height: number; danger: boolean; glide: boolean };

/**
 * One highlight that glides between the items of a Radix menu or listbox for the pointer, and jumps instantly for the keyboard.
 * Radix focuses the highlighted item, so the highlight follows focus inside the content. Spread `contentProps` on the content,
 * call `reset` when it opens, and render `<MenuHighlight state={highlight} className={styles.highlight} />` as its first child.
 * Items mark a destructive tone with `data-tone="danger"`.
 */
export function useMenuHighlight(itemSelector = '[role="menuitem"], [role="option"]') {
  const [highlight, setHighlight] = useState<Highlight | null>(null);
  const pointer = useRef(false);
  const clearTimer = useRef(0);
  useEffect(() => () => window.clearTimeout(clearTimer.current), []);

  function onFocus(event: FocusEvent<HTMLElement>) {
    const item = event.target instanceof HTMLElement ? event.target.closest<HTMLElement>(itemSelector) : null;
    window.clearTimeout(clearTimer.current);
    if (!item) {
      // A short grace period keeps the highlight gliding across separators and item gaps.
      clearTimer.current = window.setTimeout(() => setHighlight(null), pointer.current ? 70 : 0);
      return;
    }
    const next = { top: item.offsetTop, height: item.offsetHeight, danger: item.dataset.tone === "danger" };
    const glide = pointer.current;
    setHighlight(current => ({ ...next, glide: glide && current !== null }));
  }

  return {
    highlight,
    reset: () => { window.clearTimeout(clearTimer.current); setHighlight(null); },
    contentProps: {
      onFocus,
      onPointerMoveCapture: () => { pointer.current = true; },
      onKeyDownCapture: () => { pointer.current = false; },
    },
  };
}

/** The gliding highlight itself. Position it absolutely inside the content, under the items. */
export function MenuHighlight({ state, className }: { state: Highlight | null; className?: string }) {
  const reduced = useReducedMotion();
  return <motion.span className={className} data-tone={state?.danger ? "danger" : undefined} aria-hidden="true" initial={false}
    animate={state ? { y: state.top, height: state.height, opacity: 1 } : { opacity: 0 }}
    transition={{ default: state?.glide && !reduced ? motionTokens.spring.snappy : { duration: 0 }, opacity: { duration: reduced ? 0 : .08 } }} />;
}
