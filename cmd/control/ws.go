package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"flint/pkg/api"
)

const (
	wsPingInterval  = 20 * time.Second
	wsPongDeadline  = 60 * time.Second
	wsBacklogMax    = 200
	wsWriteDeadline = 10 * time.Second
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Browsers send Origin on cross-origin requests. Validate it against
		// the same allowlist the CORS middleware uses. Same-origin requests
		// (and non-browser clients like curl/wscat) send no Origin — allow.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return origin == "http://127.0.0.1:5173" || origin == "http://localhost:5173"
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

// handleWS upgrades the HTTP connection to WebSocket and streams live decisions.
func handleWS(state *State, bus *Bus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Warn("ws: upgrade failed", "err", err)
			return
		}
		defer conn.Close()

		// Set up pong handler to reset the read deadline on each pong.
		conn.SetReadDeadline(time.Now().Add(wsPongDeadline))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(wsPongDeadline))
			return nil
		})

		// Subscribe to live events.
		sub := bus.Subscribe()
		defer bus.Unsubscribe(sub)

		// --- Send hello frame ---------------------------------------------------
		backlog := state.RecentDecisions(wsBacklogMax)
		helloFrame := api.WSFrame{
			Type: "hello",
			Data: api.WSHello{
				SchemaVersion: api.AuditSchemaVersion,
				BacklogCount:  len(backlog),
			},
		}
		if err := writeJSON(conn, helloFrame); err != nil {
			slog.Debug("ws: hello write failed", "err", err)
			return
		}

		// --- Send backlog -------------------------------------------------------
		for _, row := range backlog {
			frame := api.WSFrame{Type: "decision", Data: row}
			if err := writeJSON(conn, frame); err != nil {
				slog.Debug("ws: backlog write failed", "err", err)
				return
			}
		}

		// --- Ping ticker --------------------------------------------------------
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()

		// --- Drain loop ---------------------------------------------------------
		// A separate goroutine reads from the connection to receive pong frames
		// (and any client frames — currently none are expected). We use a done
		// channel to coordinate shutdown.
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					return
				}
			}
		}()

		for {
			select {
			case <-done:
				return

			case frame, ok := <-sub.Chan():
				if !ok {
					// Subscription closed — bus was shut down.
					return
				}
				conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
					slog.Debug("ws: write failed", "err", err)
					return
				}

			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					slog.Debug("ws: ping failed", "err", err)
					return
				}
			}
		}
	}
}

// writeJSON marshals v and sends it as a text WebSocket message.
func writeJSON(conn *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
	return conn.WriteMessage(websocket.TextMessage, b)
}
