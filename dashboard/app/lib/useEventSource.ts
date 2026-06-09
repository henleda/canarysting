'use client';

import { useEffect, useRef } from 'react';

export interface EventSourceCallbacks {
  // Called with the `data:` payload of each frame.
  onMessage: (data: string) => void;
  // Called when the connection opens (or re-opens after a reconnect).
  onOpen?: () => void;
  // Called when the connection drops (before a reconnect is scheduled).
  onError?: () => void;
}

// useEventSource opens a persistent SSE connection to `url` and invokes the
// callbacks. The dashboard-backend pushes NAMED events ("event: overview"), so
// we listen on that named event (EventSource.onmessage only fires for unnamed
// `message` frames and would miss every overview push). Reconnects with
// exponential backoff (1s base, capped at 15s). Closes cleanly on unmount.
export function useEventSource(url: string, callbacks: EventSourceCallbacks): void {
  const cbRef = useRef(callbacks);
  cbRef.current = callbacks;

  useEffect(() => {
    let es: EventSource | null = null;
    let backoff = 1000;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    const handleData = (e: MessageEvent) => {
      backoff = 1000; // reset backoff on any successful frame
      cbRef.current.onMessage(e.data);
    };

    function connect() {
      if (cancelled) return;
      es = new EventSource(url);

      es.onopen = () => {
        backoff = 1000;
        cbRef.current.onOpen?.();
      };

      // Backend emits `event: overview`; also accept the default `message`
      // event so a future plain-SSE backend still works.
      es.addEventListener('overview', handleData as EventListener);
      es.onmessage = handleData;

      es.onerror = () => {
        cbRef.current.onError?.();
        es?.close();
        es = null;
        if (!cancelled) {
          timer = setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 15000);
        }
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      es?.close();
    };
  }, [url]);
}
