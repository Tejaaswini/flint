/**
 * API client — TanStack Query hooks + fetch wrappers.
 *
 * HOW TO SWITCH FROM MOCK TO REAL:
 *   1. Set `USE_MOCK = false` below.
 *   2. Set `API_BASE` to the control plane URL (default: http://127.0.0.1:7475).
 *   3. Done. All hooks call the real REST API.
 *
 * The mock → real boundary lives entirely in this file. No other file needs editing.
 */

import {
  useQuery,
  useMutation,
  type UseQueryResult,
  type UseMutationResult,
  useQueryClient,
} from "@tanstack/react-query";
import type {
  Agent,
  AgentDetail,
  Binding,
  Connection,
  ConnectionDetail,
  DecisionsResponse,
  Role,
  RolePutResponse,
  RouterDecisionsResponse,
  RouterPolicyPutResponse,
  RouterPolicyView,
  RouterStats,
  Session,
} from "./types";
import {
  MOCK_AGENTS,
  MOCK_AGENT_DETAILS,
  MOCK_CONNECTIONS,
  MOCK_CONNECTION_DETAILS,
  getMockRoles,
  MOCK_BINDINGS,
  MOCK_SESSIONS,
  getMockDecisions,
  putMockRole,
  MOCK_ROUTER_POLICY,
  MOCK_ROUTER_POLICY_RAW,
  MOCK_ROUTER_STATS,
  getMockRouterDecisions,
  putMockRouterPolicy,
} from "./mock";

// ─── Config ───────────────────────────────────────────────────────────────────

// Driven by VITE_USE_MOCK env var (default: false → use real control plane).
// Set VITE_USE_MOCK=true in ui/.env.local to develop the UI without a backend.
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:7475";
const REFETCH_INTERVAL_MS = 5_000;

// ─── Fetch helper ─────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// ─── Agents ───────────────────────────────────────────────────────────────────

export function useAgents(): UseQueryResult<Agent[]> {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_AGENTS)
        : apiFetch<Agent[]>("/api/v1/agents"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useAgent(id: string): UseQueryResult<AgentDetail> {
  return useQuery({
    queryKey: ["agents", id],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(
            MOCK_AGENT_DETAILS[id] ?? { ...MOCK_AGENTS[0], effective_permissions: [], recent_denials: [] }
          )
        : apiFetch<AgentDetail>(`/api/v1/agents/${encodeURIComponent(id)}`),
    enabled: !!id,
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

// ─── Connections ──────────────────────────────────────────────────────────────

export function useConnections(): UseQueryResult<Connection[]> {
  return useQuery({
    queryKey: ["connections"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_CONNECTIONS)
        : apiFetch<Connection[]>("/api/v1/connections"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useConnection(name: string): UseQueryResult<ConnectionDetail> {
  return useQuery({
    queryKey: ["connections", name],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(
            MOCK_CONNECTION_DETAILS[name] ?? {
              ...MOCK_CONNECTIONS[0],
              tools: [],
            }
          )
        : apiFetch<ConnectionDetail>(`/api/v1/connections/${encodeURIComponent(name)}`),
    enabled: !!name,
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

// ─── Roles ────────────────────────────────────────────────────────────────────

export function useRoles(): UseQueryResult<Role[]> {
  return useQuery({
    queryKey: ["roles"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(getMockRoles())
        : apiFetch<Role[]>("/api/v1/roles"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useRole(name: string): UseQueryResult<Role> {
  return useQuery({
    queryKey: ["roles", name],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(getMockRoles().find((r) => r.name === name) ?? { name, rules: [] })
        : apiFetch<Role>(`/api/v1/roles/${encodeURIComponent(name)}`),
    enabled: !!name,
  });
}

export function usePutRole(): UseMutationResult<
  RolePutResponse,
  Error,
  { name: string; role: Role }
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, role }) =>
      USE_MOCK
        ? Promise.resolve(putMockRole(name, role))
        : apiFetch<RolePutResponse>(`/api/v1/roles/${encodeURIComponent(name)}`, {
            method: "PUT",
            body: JSON.stringify(role),
          }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles"] });
    },
  });
}

// ─── Bindings ─────────────────────────────────────────────────────────────────

export function useBindings(): UseQueryResult<Binding[]> {
  return useQuery({
    queryKey: ["bindings"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_BINDINGS)
        : apiFetch<Binding[]>("/api/v1/bindings"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

export function useSessions(): UseQueryResult<Session[]> {
  return useQuery({
    queryKey: ["sessions"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_SESSIONS)
        : apiFetch<Session[]>("/api/v1/sessions"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useSession(id: string): UseQueryResult<Session> {
  return useQuery({
    queryKey: ["sessions", id],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_SESSIONS.find((s) => s.id === id) ?? MOCK_SESSIONS[0])
        : apiFetch<Session>(`/api/v1/sessions/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
}

// ─── Decisions ────────────────────────────────────────────────────────────────

export function useDecisions(
  params: { limit?: number; since?: string } = {}
): UseQueryResult<DecisionsResponse> {
  const limit = params.limit ?? 100;
  const since = params.since;
  return useQuery({
    queryKey: ["decisions", limit, since],
    queryFn: () => {
      if (USE_MOCK) {
        return Promise.resolve(getMockDecisions(limit, since));
      }
      const q = new URLSearchParams();
      q.set("limit", String(limit));
      if (since) q.set("since", since);
      return apiFetch<DecisionsResponse>(`/api/v1/decisions?${q}`);
    },
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

// ─── Router ───────────────────────────────────────────────────────────────────

export function useRouterPolicy(): UseQueryResult<RouterPolicyView> {
  return useQuery({
    queryKey: ["router", "policy"],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_ROUTER_POLICY)
        : apiFetch<RouterPolicyView>("/api/v1/router/policy"),
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useRouterPolicyRaw(): UseQueryResult<string> {
  return useQuery({
    queryKey: ["router", "policy", "raw"],
    queryFn: async () => {
      if (USE_MOCK) return MOCK_ROUTER_POLICY_RAW;
      const res = await fetch(`${API_BASE}/api/v1/router/policy/raw`);
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`API ${res.status}: ${body}`);
      }
      return res.text();
    },
  });
}

export async function putRouterPolicy(
  yaml: string,
  dryRun?: boolean
): Promise<RouterPolicyPutResponse> {
  if (USE_MOCK) {
    return putMockRouterPolicy(yaml);
  }
  const url = dryRun
    ? `${API_BASE}/api/v1/router/policy?dry_run=true`
    : `${API_BASE}/api/v1/router/policy`;
  const res = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "text/yaml" },
    body: yaml,
  });
  if (!res.ok && res.status !== 400) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<RouterPolicyPutResponse>;
}

export function useRouterDecisions(
  params: { limit?: number; since?: string } = {}
): UseQueryResult<RouterDecisionsResponse> {
  const limit = params.limit ?? 100;
  const since = params.since;
  return useQuery({
    queryKey: ["router", "decisions", limit, since],
    queryFn: () => {
      if (USE_MOCK) {
        return Promise.resolve(getMockRouterDecisions(limit, since));
      }
      const q = new URLSearchParams();
      q.set("limit", String(limit));
      if (since) q.set("since", since);
      return apiFetch<RouterDecisionsResponse>(`/api/v1/router/decisions?${q}`);
    },
    refetchInterval: REFETCH_INTERVAL_MS,
  });
}

export function useRouterStats(
  window: "session" | "24h" | "1h" | "5m" | "1m" | "all" = "session"
): UseQueryResult<RouterStats> {
  return useQuery({
    queryKey: ["router", "stats", window],
    queryFn: () =>
      USE_MOCK
        ? Promise.resolve(MOCK_ROUTER_STATS)
        : apiFetch<RouterStats>(`/api/v1/router/stats?window=${window}`),
    refetchInterval: 5_000,
  });
}
