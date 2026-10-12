export type List<T> = { items: T[]; next_cursor?: string };
export type Identity = { id: string; uuid: string; kind: 'carbon' | 'silicon'; authenticated: boolean; expires_at: string };
export type TingApp = { app_id: string; name: string; can_manage_tings: boolean };
export type TingType = { type: string; description: string; defaults: { carbon: boolean; silicon: boolean } };
export type Ting = { id: string; type: string; created_at: string; for: string; key: string; read: boolean; silent: boolean; data?: Record<string, unknown>; metadata?: Record<string, unknown> };
export type Preference = { app_id: string; service: string | null; type: string | null; enabled: boolean };
export type Subscription = { id: string; app_id: string; for: string; active: boolean; required_delivery?: boolean };
export type Hook = { id: string; for: string; state: 'connected' | 'disconnected' | 'paused' | 'detached'; pending: number; receiver_id: string | null };
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public hint?: string) { super(message); }
}
let sessionGeneration = 0;
export function sessionChanged() { sessionGeneration++; }
// All browser credentials stay in the HttpOnly, host-only cookie.
export async function api<T>(path: string, method = 'GET', body?: unknown, headers?: Record<string, string>): Promise<T> {
  const generation = sessionGeneration;
  let response: Response;
  try { response = await fetch(path, { method, credentials: 'same-origin', signal: AbortSignal.timeout(25_000), headers: { Accept: 'application/json', ...(method === 'GET' ? {} : { 'Content-Type': 'application/json' }), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); }
  catch { throw new ApiError(503, 'service_unavailable', 'Ting could not reach the service.', 'Check your connection and try again.'); }
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) throw new ApiError(response.status || 503, 'service_unavailable', 'Ting could not reach the service.', 'Please try again in a moment.');
  let result;
  try { result = await response.json(); }
  catch { throw new ApiError(503, 'invalid_response', 'The service returned an unreadable response.', 'Please try again in a moment.'); }
  if (response.status === 401 && generation === sessionGeneration && !(path === '/v1/session' && method === 'POST')) window.dispatchEvent(new Event('ting:session-expired'));
  if (!response.ok) throw new ApiError(response.status, result.error?.code || 'request_failed', result.error?.message || 'This request could not be completed.', result.error?.hint);
  return result as T;
}
