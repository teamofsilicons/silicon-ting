// Keep an upstream outage or an unrelated browser extension from generating a request storm.
export function telemetryTransport(send: typeof fetch, origin: string, now = Date.now): typeof fetch {
  let retryAfter = 0;
  return async (input, init) => {
    if (now() < retryAfter) throw new Error('Telemetry is cooling down after an upstream failure.');
    const body = JSON.parse(String(init?.body));
    body.events = body.events.filter((event: { type: string; data?: { kind?: string; source?: string } }) => {
      if (event.type !== 'error') return true;
      // The SDK omits rejection provenance. Only collect runtime errors attributable to our origin.
      if (event.data?.kind === 'unhandledrejection') return false;
      if (event.data?.kind !== 'runtime') return true;
      try { return new URL(event.data.source || '').origin === origin; } catch { return false; }
    });
    if (!body.events.length) return new Response(null, { status: 204 });
    try {
      const response = await send(input, { ...init, body: JSON.stringify(body) });
      if (!response.ok) retryAfter = now() + 60_000;
      return response;
    } catch (error) {
      retryAfter = now() + 60_000;
      throw error;
    }
  };
}
