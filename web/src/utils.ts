export const enc = encodeURIComponent;
export const orgPath = (org: string, path: string) => `/v1/orgs/${enc(org)}/${path}`;
export function query(values: Record<string, string | number | boolean | undefined | null>) {
  const result = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) if (value !== undefined && value !== null && value !== '') result.set(key, String(value));
  return result.size ? `?${result}` : '';
}
export function typeError(app: string, type: string, description: string): string | undefined {
  if (!/^[a-z][a-z0-9_-]{0,79}$/.test(app)) return 'Use the bare IAM application ID. Refresh application metadata after identifier migration.';
  const suffix = type.slice(app.length + 1);
  if (!type.startsWith(`${app}.`) || !/^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$/.test(suffix)) return 'Use app_id.service.event, with lowercase service and event names.';
  if (new TextEncoder().encode(type).length > 255) return 'Type names must be at most 255 UTF-8 bytes.';
  if (!description.trim() || new TextEncoder().encode(description).length > 1000) return 'Add a description of 1–1,000 UTF-8 bytes.';
}
export function safeLink(value: unknown): string | undefined {
  if (typeof value !== 'string') return;
  try { const url = new URL(value); if (url.protocol === 'https:' || url.protocol === 'http:') return url.href; } catch { /* An arbitrary payload is not a link. */ }
}
export function timeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const mins = Math.floor((Date.now() - date.getTime()) / 60_000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
export function watchDelay(attempt: number, random = Math.random()) { return Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5) * (1 + random * .2)); }
