'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type Identity, type List } from './api';
import { enc } from './utils';

export type ListState<T> = {
  items: T[];
  cursor?: string;
  loading: boolean;
  error: unknown;
  reload: () => Promise<void>;
  more: () => Promise<void>;
};

// Responses from an older path, revision or account never replace newer results.
export function useList<T>(path: string | undefined, revision: number, identity: Identity | undefined): ListState<T> {
  const [items, setItems] = useState<T[]>([]);
  const [cursor, setCursor] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const generation = useRef(0);
  const current = useRef<{ path?: string; actor?: Identity; cursor?: string }>({});

  const load = useCallback(async (more = false) => {
    const base = current.current.path;
    if (!base) return;
    const active = ++generation.current;
    setLoading(true); setError(undefined);
    try {
      const next = current.current.cursor;
      const result = await api<List<T>>(base + (more && next ? `${base.includes('?') ? '&' : '?'}cursor=${enc(next)}` : ''));
      if (active !== generation.current) return;
      setItems(previous => more ? [...previous, ...result.items] : result.items);
      current.current.cursor = result.next_cursor; setCursor(result.next_cursor);
    } catch (error) { if (active === generation.current) setError(error); }
    finally { if (active === generation.current) setLoading(false); }
  }, []);

  useEffect(() => {
    generation.current++;
    if (current.current.path !== path || current.current.actor !== identity) setItems([]);
    current.current = { path, actor: identity, cursor: undefined };
    setCursor(undefined); setError(undefined);
    if (path) void load(); else setLoading(false);
    return () => { generation.current++; };
  }, [path, revision, identity, load]);

  const reload = useCallback(() => load(), [load]);
  const more = useCallback(() => load(true), [load]);
  return { items, cursor, loading, error, reload, more };
}
