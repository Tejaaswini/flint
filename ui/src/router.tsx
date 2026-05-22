import { Routes, Route, Navigate } from "react-router-dom";
import { ConnectionsRoute } from "@/routes/connections";
import { ConnectionDetailRoute } from "@/routes/connection-detail";
import { AgentsRoute } from "@/routes/agents";
import { SessionsRoute } from "@/routes/sessions";
import { RolesRoute } from "@/routes/roles";
import { RouterLiveRoute } from "@/routes/router-live";
import { RouterRoutesRoute } from "@/routes/router-routes";

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<ConnectionsRoute />} />
      <Route path="/connections" element={<Navigate to="/" replace />} />
      <Route path="/connections/:name" element={<ConnectionDetailRoute />} />
      <Route path="/agents" element={<AgentsRoute />} />
      <Route path="/sessions" element={<SessionsRoute />} />
      <Route path="/router/live" element={<RouterLiveRoute />} />
      <Route path="/router/routes" element={<RouterRoutesRoute />} />
      <Route path="/roles" element={<RolesRoute />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
