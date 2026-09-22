export type List<T> = { items: T[]; next_cursor?: string };
export type Identity = { id: string; kind: 'carbon' | 'silicon'; authenticated: boolean };
export type Org = { id: string; name: string };
export type TingApp = { app_id: string; name: string; can_manage_tings: boolean };
export type TingType = { type: string; description: string; defaults: { carbon: boolean; silicon: boolean } };
export type Ting = { id: string; type: string; created_at: string; for: string; key: string; read: boolean; silent: boolean; data?: Record<string, unknown>; metadata?: Record<string, unknown> };
export type Preference = { app_id: string; service: string | null; type: string | null; enabled: boolean };
export type Subscription = { id: string; app_id: string; for: string; active: boolean; required_delivery?: boolean };
export type Hook = { id: string; for: string; state: 'connected' | 'disconnected' | 'paused' | 'detached'; pending: number; receiver_id: string | null };
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public hint?: string) { super(message); }
}
// All browser credentials stay in the HttpOnly, host-only cookie.
export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  let response: Response;
  try { response = await fetch(path, { method, credentials: 'same-origin', signal: AbortSignal.timeout(25_000), headers: method === 'GET' ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); }
  catch { throw new ApiError(503, 'service_unavailable', 'Ting could not reach the service.', 'Check your connection and try again.'); }
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) throw new ApiError(response.status || 503, 'service_unavailable', 'Ting could not reach the service.', 'Please try again in a moment.');
  let result;
  try { result = await response.json(); }
  catch { throw new ApiError(503, 'invalid_response', 'The service returned an unreadable response.', 'Please try again in a moment.'); }
  if (!response.ok) throw new ApiError(response.status, result.error?.code || 'request_failed', result.error?.message || 'This request could not be completed.', result.error?.hint);
  return result as T;
}
