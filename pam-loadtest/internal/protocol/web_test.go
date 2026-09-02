package protocol

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"pam-loadtest/internal/pam"
)

type fakeWebPAM struct {
	mu          sync.Mutex
	peer        *webrtc.PeerConnection
	navigations []string
	resizes     int
	closes      int
	closeCtxErr error
	closeErr    error
}

func (f *fakeWebPAM) CreateWebSession(context.Context, string, string) (pam.Session, error) {
	return pam.Session{ID: "web-session"}, nil
}
func (f *fakeWebPAM) Connect(context.Context, string) error { return nil }

func (f *fakeWebPAM) WebRTCOffer(ctx context.Context, _ string, offer WebRTCOffer) (WebRTCAnswer, error) {
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return WebRTCAnswer{}, err
	}
	f.mu.Lock()
	f.peer = peer
	f.mu.Unlock()
	peer.OnDataChannel(func(channel *webrtc.DataChannel) {
		channel.OnOpen(func() {
			_ = channel.SendText(`{"type":"frame_start","frameId":"one","total":1}`)
			_ = channel.SendText(`{"type":"frame_chunk","frameId":"one","seq":0,"data":"active"}`)
			_ = channel.SendText(`{"type":"frame_end","frameId":"one"}`)
		})
	})
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.SDP}); err != nil {
		return WebRTCAnswer{}, err
	}
	answer, err := peer.CreateAnswer(nil)
	if err != nil {
		return WebRTCAnswer{}, err
	}
	if err := peer.SetLocalDescription(answer); err != nil {
		return WebRTCAnswer{}, err
	}
	<-webrtc.GatheringCompletePromise(peer)
	local := peer.LocalDescription()
	return WebRTCAnswer{Mode: "webrtc", Media: "frames", State: "connecting", Answer: WebRTCDescription{Type: local.Type.String(), SDP: local.SDP}}, nil
}

func (f *fakeWebPAM) WebRTCCandidate(context.Context, string, WebRTCCandidate) error { return nil }
func (f *fakeWebPAM) WebNavigate(_ context.Context, _ string, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.navigations = append(f.navigations, action)
	return nil
}
func (f *fakeWebPAM) WebResize(context.Context, string, int, int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes++
	return nil
}

func (f *fakeWebPAM) CloseWebSession(ctx context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	f.closeCtxErr = ctx.Err()
	return f.closeErr
}

func TestRunWebDirectReceivesFramesWithoutRenegotiationBreakingReloads(t *testing.T) {
	closeErr := errors.New("close failed")
	fake := &fakeWebPAM{closeErr: closeErr}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stats, err := RunWeb(ctx, fake, WebOptions{AssetID: "asset", AccountID: "account", Width: 1280, Height: 720, ActivityInterval: 50 * time.Millisecond, InactivityTimeout: 3 * time.Second})
	fake.mu.Lock()
	if fake.peer != nil {
		_ = fake.peer.Close()
	}
	navigations := append([]string(nil), fake.navigations...)
	resizes := fake.resizes
	closes := fake.closes
	closeCtxErr := fake.closeCtxErr
	fake.mu.Unlock()
	if err == nil || ctx.Err() == nil {
		t.Fatalf("err=%v context=%v", err, ctx.Err())
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("cleanup error missing from result: %v", err)
	}
	if stats.ReceivedMessages < 3 || stats.ReceivedBytes == 0 {
		t.Fatalf("stats=%+v navigations=%v", stats, navigations)
	}
	if len(navigations) != 0 || resizes == 0 {
		t.Fatalf("reloads=%d resizes=%d", len(navigations), resizes)
	}
	if closes != 1 || closeCtxErr != nil {
		t.Fatalf("closes=%d close context error=%v", closes, closeCtxErr)
	}
}

type silentWebPAM struct{ fakeWebPAM }

func (f *silentWebPAM) WebRTCOffer(_ context.Context, _ string, offer WebRTCOffer) (WebRTCAnswer, error) {
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return WebRTCAnswer{}, err
	}
	f.mu.Lock()
	f.peer = peer
	f.mu.Unlock()
	peer.OnDataChannel(func(*webrtc.DataChannel) {})
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.SDP}); err != nil {
		return WebRTCAnswer{}, err
	}
	answer, err := peer.CreateAnswer(nil)
	if err != nil {
		return WebRTCAnswer{}, err
	}
	if err := peer.SetLocalDescription(answer); err != nil {
		return WebRTCAnswer{}, err
	}
	<-webrtc.GatheringCompletePromise(peer)
	local := peer.LocalDescription()
	return WebRTCAnswer{Mode: "webrtc", Media: "frames", Answer: WebRTCDescription{Type: local.Type.String(), SDP: local.SDP}}, nil
}

func TestRunWebDirectFailsWhenDataChannelIsInactive(t *testing.T) {
	fake := &silentWebPAM{}
	_, err := RunWeb(context.Background(), fake, WebOptions{AssetID: "asset", AccountID: "account", Width: 1280, Height: 720, ActivityInterval: 10 * time.Millisecond, InactivityTimeout: 40 * time.Millisecond})
	fake.mu.Lock()
	if fake.peer != nil {
		_ = fake.peer.Close()
	}
	fake.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("err=%v", err)
	}
}
