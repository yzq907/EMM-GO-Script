package protocol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"pam-loadtest/internal/pam"
	"pam-loadtest/internal/transport"
)

type WebRTCDescription = pam.WebRTCDescription
type WebRTCOffer = pam.WebRTCOffer
type WebRTCAnswer = pam.WebRTCAnswer
type WebRTCCandidate = pam.WebRTCCandidate

type WebPAM interface {
	CreateWebSession(context.Context, string, string) (pam.Session, error)
	Connect(context.Context, string) error
	WebRTCOffer(context.Context, string, WebRTCOffer) (WebRTCAnswer, error)
	WebRTCCandidate(context.Context, string, WebRTCCandidate) error
	WebNavigate(context.Context, string, string) error
	WebResize(context.Context, string, int, int) error
	CloseWebSession(context.Context, string) error
}

type CleanupError struct {
	Err error
}

func (e *CleanupError) Error() string { return "web direct cleanup: " + e.Err.Error() }
func (e *CleanupError) Unwrap() error { return e.Err }

type WebOptions struct {
	AssetID           string
	AccountID         string
	Width             int
	Height            int
	Quality           string
	ActivityInterval  time.Duration
	InactivityTimeout time.Duration
	ConnectTimeout    time.Duration
	OnConnected       func()
}

func RunWeb(ctx context.Context, client WebPAM, options WebOptions) (stats transport.Stats, runErr error) {
	if client == nil || options.AssetID == "" || options.AccountID == "" {
		return transport.Stats{}, fmt.Errorf("web direct asset binding is required")
	}
	if options.Width <= 0 {
		options.Width = 1280
	}
	if options.Height <= 0 {
		options.Height = 720
	}
	if options.ActivityInterval <= 0 {
		options.ActivityInterval = time.Second
	}
	if options.InactivityTimeout <= 0 {
		options.InactivityTimeout = 15 * time.Second
	}
	if options.ConnectTimeout <= 0 {
		options.ConnectTimeout = 60 * time.Second
	}

	session, err := client.CreateWebSession(ctx, options.AssetID, options.AccountID)
	if err != nil {
		return transport.Stats{}, err
	}
	if session.ID == "" {
		return transport.Stats{}, fmt.Errorf("web direct session ID is empty")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.CloseWebSession(cleanupCtx, session.ID); err != nil {
			runErr = errors.Join(runErr, &CleanupError{Err: err})
		}
	}()
	_ = client.WebResize(ctx, session.ID, options.Width, options.Height)

	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return transport.Stats{}, fmt.Errorf("create web peer: %w", err)
	}
	defer peer.Close()
	ordered := false
	packetLifetime := uint16(1000)
	channel, err := peer.CreateDataChannel("web-frame", &webrtc.DataChannelInit{Ordered: &ordered, MaxPacketLifeTime: &packetLifetime})
	if err != nil {
		return transport.Stats{}, fmt.Errorf("create web frame channel: %w", err)
	}

	var sentMessages, receivedMessages, sentBytes, receivedBytes atomic.Int64
	var lastReceived atomic.Int64
	opened := make(chan struct{}, 1)
	failed := make(chan error, 1)
	channel.OnOpen(func() {
		lastReceived.Store(time.Now().UnixNano())
		select {
		case opened <- struct{}{}:
		default:
		}
	})
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		receivedMessages.Add(1)
		receivedBytes.Add(int64(len(message.Data)))
		lastReceived.Store(time.Now().UnixNano())
	})
	channel.OnError(func(err error) {
		select {
		case failed <- fmt.Errorf("web frame channel failed: %w", err):
		default:
		}
	})
	peer.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		go func() {
			for {
				packet, _, err := track.ReadRTP()
				if err != nil {
					return
				}
				receivedMessages.Add(1)
				receivedBytes.Add(int64(packet.MarshalSize()))
				lastReceived.Store(time.Now().UnixNano())
			}
		}()
	})
	peer.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		value := candidate.ToJSON()
		go func() {
			_ = client.WebRTCCandidate(ctx, session.ID, WebRTCCandidate{Candidate: value.Candidate, SDPMid: value.SDPMid, SDPMLineIndex: value.SDPMLineIndex, UsernameFragment: value.UsernameFragment})
		}()
	})

	offer, err := peer.CreateOffer(nil)
	if err != nil {
		return transport.Stats{}, fmt.Errorf("create web offer: %w", err)
	}
	if err := peer.SetLocalDescription(offer); err != nil {
		return transport.Stats{}, fmt.Errorf("set web local description: %w", err)
	}
	gatherCtx, gatherCancel := context.WithTimeout(ctx, 2*time.Second)
	select {
	case <-webrtc.GatheringCompletePromise(peer):
	case <-gatherCtx.Done():
	}
	gatherCancel()
	local := peer.LocalDescription()
	if local == nil || local.SDP == "" {
		return transport.Stats{}, fmt.Errorf("web local offer is empty")
	}
	answer, err := client.WebRTCOffer(ctx, session.ID, WebRTCOffer{Type: local.Type.String(), SDP: local.SDP, Width: options.Width, Height: options.Height, FPS: 0, Quality: options.Quality})
	if err != nil {
		return transport.Stats{}, err
	}
	if answer.Fallback || strings.ToLower(answer.Mode) != "webrtc" || answer.Answer.SDP == "" {
		return transport.Stats{}, fmt.Errorf("web direct server did not accept WebRTC: %s", pam.Redact(answer.Reason))
	}
	if err := client.Connect(ctx, session.ID); err != nil {
		return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), fmt.Errorf("connect web direct session: %w", err)
	}
	answerType := webrtc.NewSDPType(answer.Answer.Type)
	if answerType == webrtc.SDPTypeUnknown {
		return transport.Stats{}, fmt.Errorf("web direct answer type is invalid")
	}
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: answerType, SDP: answer.Answer.SDP}); err != nil {
		return transport.Stats{}, fmt.Errorf("set web remote description: %w", err)
	}

	connectTimer := time.NewTimer(options.ConnectTimeout)
	defer connectTimer.Stop()
	select {
	case <-ctx.Done():
		return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), ctx.Err()
	case err := <-failed:
		return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), err
	case <-connectTimer.C:
		return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), fmt.Errorf("web direct data channel connection timed out")
	case <-opened:
	}
	if options.OnConnected != nil {
		options.OnConnected()
	}

	activity := time.NewTicker(options.ActivityInterval)
	defer activity.Stop()
	livenessInterval := options.InactivityTimeout / 2
	if livenessInterval < time.Millisecond {
		livenessInterval = time.Millisecond
	}
	liveness := time.NewTicker(livenessInterval)
	defer liveness.Stop()
	sequence := 0
	for {
		select {
		case <-ctx.Done():
			return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), ctx.Err()
		case err := <-failed:
			return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), err
		case <-liveness.C:
			if time.Since(time.Unix(0, lastReceived.Load())) >= options.InactivityTimeout {
				return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), fmt.Errorf("web direct inbound traffic inactive for %s", options.InactivityTimeout)
			}
		case <-activity.C:
			sequence++
			width := options.Width
			if sequence%2 == 1 && width > 1 {
				width--
			}
			if err := client.WebResize(ctx, session.ID, width, options.Height); err != nil {
				return webStats(&sentMessages, &receivedMessages, &sentBytes, &receivedBytes, &lastReceived), fmt.Errorf("web direct resize failed: %w", err)
			}
			sentBytes.Add(int64(len(`{"width":1280,"height":720}`)))
			sentMessages.Add(1)
		}
	}
}

func webStats(sentMessages, receivedMessages, sentBytes, receivedBytes, lastActivity *atomic.Int64) transport.Stats {
	stats := transport.Stats{SentMessages: sentMessages.Load(), ReceivedMessages: receivedMessages.Load(), SentBytes: sentBytes.Load(), ReceivedBytes: receivedBytes.Load()}
	if value := lastActivity.Load(); value > 0 {
		stats.LastActivity = time.Unix(0, value)
	}
	return stats
}
