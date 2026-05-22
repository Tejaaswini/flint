/**
 * useDecisionStream — wraps the WS /api/v1/stream endpoint.
 *
 * Returns a ring buffer of the last 500 frames, deduped by
 * (session_id, event_seq, direction).
 *
 * In mock mode, uses the addWSListener emitter from mock.ts instead of
 * opening a real WebSocket.
 *
 * To switch to real: set USE_MOCK=false in client.ts (same constant; the
 * WS hook reads it from the shared config below). Or set VITE_USE_MOCK=false
 * as an env variable.
 */

import { useEffect, useReducer, useRef } from "react";
import type {
  WSDecisionFrame,
  WSFindingFrame,
  WSFrame,
  WSRoutingDecisionFrame,
  DecisionRow,
  RoutingDecision,
} from "./types";
import { addWSListener, MOCK_DECISIONS, addRouterWSListener, MOCK_ROUTING_DECISIONS } from "./mock";
import { USE_MOCK } from "./client";

// ─── Config ───────────────────────────────────────────────────────────────────
const WS_URL = (import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:7475")
  .replace(/^http/, "ws")
  .concat("/api/v1/stream");

const BUFFER_CAP = 500;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface StreamState {
  frames: DecisionRow[];
  latestFinding: WSFindingFrame["data"] | null;
  isConnected: boolean;
  error: string | null;
}

type StreamAction =
  | { type: "connected" }
  | { type: "disconnected" }
  | { type: "error"; message: string }
  | { type: "decision"; row: DecisionRow }
  | { type: "finding"; data: WSFindingFrame["data"] }
  | { type: "clear_finding" };

// ─── Dedup key ────────────────────────────────────────────────────────────────

function dedupKey(row: DecisionRow): string {
  return `${row.session_id}:${row.event_seq}:${row.direction}`;
}

// ─── Reducer ──────────────────────────────────────────────────────────────────

function streamReducer(state: StreamState, action: StreamAction): StreamState {
  switch (action.type) {
    case "connected":
      return { ...state, isConnected: true, error: null };
    case "disconnected":
      return { ...state, isConnected: false };
    case "error":
      return { ...state, error: action.message, isConnected: false };
    case "decision": {
      const key = dedupKey(action.row);
      const existing = state.frames.some((f) => dedupKey(f) === key);
      if (existing) return state;
      const next = [action.row, ...state.frames].slice(0, BUFFER_CAP);
      return { ...state, frames: next };
    }
    case "finding":
      return { ...state, latestFinding: action.data };
    case "clear_finding":
      return { ...state, latestFinding: null };
    default:
      return state;
  }
}

// ─── Initial state (pre-populate with mock data) ──────────────────────────────

function makeInitialState(): StreamState {
  if (USE_MOCK) {
    // Pre-seed with the most recent 50 decisions sorted newest-first
    const sorted = [...MOCK_DECISIONS].sort(
      (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
    );
    return {
      frames: sorted.slice(0, 50),
      latestFinding: null,
      isConnected: true,
      error: null,
    };
  }
  return { frames: [], latestFinding: null, isConnected: false, error: null };
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useDecisionStream(): StreamState & { clearFinding: () => void } {
  const [state, dispatch] = useReducer(streamReducer, undefined, makeInitialState);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    // Track all finding-banner auto-dismiss timeouts so we can cancel them
    // on unmount (React 18 strict-mode double-mount, route change, etc).
    const findingTimers = new Set<ReturnType<typeof setTimeout>>();
    const scheduleClearFinding = () => {
      const t = setTimeout(() => {
        findingTimers.delete(t);
        dispatch({ type: "clear_finding" });
      }, 4000);
      findingTimers.add(t);
    };

    if (USE_MOCK) {
      // Mock mode: subscribe to the in-process emitter
      const remove = addWSListener((frame: WSDecisionFrame | WSFindingFrame) => {
        if (frame.type === "decision") {
          dispatch({ type: "decision", row: frame.data });
        } else if (frame.type === "finding") {
          dispatch({ type: "finding", data: frame.data });
          scheduleClearFinding();
        }
      });
      dispatch({ type: "connected" });
      return () => {
        findingTimers.forEach(clearTimeout);
        findingTimers.clear();
        remove();
      };
    }

    // Real WebSocket mode
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let mounted = true;

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => dispatch({ type: "connected" });
      ws.onclose = () => {
        dispatch({ type: "disconnected" });
        if (mounted) {
          reconnectTimeout = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => {
        dispatch({ type: "error", message: "WebSocket connection failed" });
      };
      ws.onmessage = (evt) => {
        try {
          const frame = JSON.parse(evt.data as string) as WSFrame;
          if (frame.type === "hello") {
            // hello is informational — just note we're connected
            return;
          }
          if (frame.type === "decision") {
            dispatch({ type: "decision", row: frame.data });
          } else if (frame.type === "finding") {
            dispatch({ type: "finding", data: frame.data });
            scheduleClearFinding();
          }
          // agent_seen frames are ignored in the stream; they update agent list via REST polling
        } catch {
          // Ignore malformed frames
        }
      };
    }

    connect();
    return () => {
      mounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      findingTimers.forEach(clearTimeout);
      findingTimers.clear();
      wsRef.current?.close();
    };
  }, []);

  return {
    ...state,
    clearFinding: () => dispatch({ type: "clear_finding" }),
  };
}

// ---------------------------------------------------------------------------
// useRoutingStream — subscribes to /api/v1/router/stream
// Returns a ring buffer of the last 500 routing decisions, deduped by request_id.
// ---------------------------------------------------------------------------

const ROUTER_WS_URL = (import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:7475")
  .replace(/^http/, "ws")
  .concat("/api/v1/router/stream");

const ROUTER_BUFFER_CAP = 500;

export interface RoutingStreamState {
  frames: RoutingDecision[];
  isConnected: boolean;
  error: string | null;
}

type RoutingStreamAction =
  | { type: "connected" }
  | { type: "disconnected" }
  | { type: "error"; message: string }
  | { type: "decision"; row: RoutingDecision };

function routingStreamReducer(
  state: RoutingStreamState,
  action: RoutingStreamAction
): RoutingStreamState {
  switch (action.type) {
    case "connected":
      return { ...state, isConnected: true, error: null };
    case "disconnected":
      return { ...state, isConnected: false };
    case "error":
      return { ...state, error: action.message, isConnected: false };
    case "decision": {
      const existing = state.frames.some(
        (f) => f.request_id === action.row.request_id
      );
      if (existing) return state;
      const next = [action.row, ...state.frames].slice(0, ROUTER_BUFFER_CAP);
      return { ...state, frames: next };
    }
    default:
      return state;
  }
}

function makeRoutingInitialState(): RoutingStreamState {
  if (USE_MOCK) {
    const sorted = [...MOCK_ROUTING_DECISIONS].sort(
      (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
    );
    return {
      frames: sorted.slice(0, 30),
      isConnected: true,
      error: null,
    };
  }
  return { frames: [], isConnected: false, error: null };
}

export function useRoutingStream(): RoutingStreamState {
  const [state, dispatch] = useReducer(
    routingStreamReducer,
    undefined,
    makeRoutingInitialState
  );
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (USE_MOCK) {
      const remove = addRouterWSListener((frame: WSRoutingDecisionFrame) => {
        dispatch({ type: "decision", row: frame.data });
      });
      dispatch({ type: "connected" });
      return () => {
        remove();
      };
    }

    // Real WebSocket mode
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let mounted = true;

    function connect() {
      const ws = new WebSocket(ROUTER_WS_URL);
      wsRef.current = ws;

      ws.onopen = () => dispatch({ type: "connected" });
      ws.onclose = () => {
        dispatch({ type: "disconnected" });
        if (mounted) {
          reconnectTimeout = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => {
        dispatch({ type: "error", message: "Router WebSocket connection failed" });
      };
      ws.onmessage = (evt) => {
        try {
          const frame = JSON.parse(evt.data as string) as WSFrame | WSRoutingDecisionFrame;
          if (frame.type === "routing_decision") {
            dispatch({ type: "decision", row: (frame as WSRoutingDecisionFrame).data });
          }
          // hello frames are informational; ignore others
        } catch {
          // Ignore malformed frames
        }
      };
    }

    connect();
    return () => {
      mounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      wsRef.current?.close();
    };
  }, []);

  return state;
}
