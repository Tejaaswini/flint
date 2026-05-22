package main

import "sync"

// Bus is a simple in-memory pub/sub broker for WebSocket frames.
// Slow consumers receive dropped frames; the UI deduplicates on reconnect.
type Bus struct {
	mu   sync.Mutex
	subs map[*Subscription]struct{}
}

// Subscription is a single subscriber's receive channel.
type Subscription struct {
	ch chan []byte
}

// NewBus creates an empty Bus.
func NewBus() *Bus {
	return &Bus{
		subs: make(map[*Subscription]struct{}),
	}
}

// Subscribe creates and registers a new Subscription. The caller must call
// Unsubscribe when done to avoid leaking the goroutine / channel.
func (b *Bus) Subscribe() *Subscription {
	sub := &Subscription{
		ch: make(chan []byte, 64),
	}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()
	return sub
}

// Unsubscribe removes the subscription and closes its channel so the consumer
// goroutine exits cleanly.
func (b *Bus) Unsubscribe(sub *Subscription) {
	b.mu.Lock()
	delete(b.subs, sub)
	b.mu.Unlock()
	// Close the channel after removing from the map; no further Publish can
	// send to it once it is absent from the map.
	close(sub.ch)
}

// Publish sends a serialized frame to all subscribers. Non-blocking: if a
// subscriber's channel is full the frame is dropped for that subscriber.
func (b *Bus) Publish(frame []byte) {
	b.mu.Lock()
	subs := make([]*Subscription, 0, len(b.subs))
	for sub := range b.subs {
		subs = append(subs, sub)
	}
	b.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub.ch <- frame:
		default:
			// Channel full — drop frame for this slow consumer.
		}
	}
}

// Chan returns the read-only channel for this subscription.
func (s *Subscription) Chan() <-chan []byte {
	return s.ch
}
