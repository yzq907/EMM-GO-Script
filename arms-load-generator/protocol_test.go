package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestEncodeFrameLayout(t *testing.T) {
	requestID := "b3d0151d-eb6e-485c-be67-8e12dc388b0b"
	body := []byte("payload")
	frame, err := EncodeFrame(0x63, 0x02, 42, requestID, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != FrameHeaderSize+len(body) {
		t.Fatalf("frame length = %d", len(frame))
	}
	if string(frame[0:4]) != "arms" || binary.BigEndian.Uint16(frame[4:6]) != 1 {
		t.Fatalf("bad magic or version: %x", frame[:6])
	}
	if frame[6] != 0x63 || frame[7] != 0x02 {
		t.Fatalf("bad type/subtype: %x/%x", frame[6], frame[7])
	}
	if binary.BigEndian.Uint64(frame[8:16]) != 42 {
		t.Fatalf("bad sequence: %d", binary.BigEndian.Uint64(frame[8:16]))
	}
	if string(frame[16:52]) != requestID {
		t.Fatalf("bad request ID: %q", frame[16:52])
	}
	if binary.BigEndian.Uint64(frame[52:60]) != uint64(len(body)) {
		t.Fatalf("bad body length: %d", binary.BigEndian.Uint64(frame[52:60]))
	}
	if !bytes.Equal(frame[60:72], make([]byte, 12)) {
		t.Fatalf("reserved bytes are not zero: %x", frame[60:72])
	}
	if !bytes.Equal(frame[72:], body) {
		t.Fatalf("bad body: %q", frame[72:])
	}
}

func TestHeartbeatFrame(t *testing.T) {
	heartbeat := EncodeHeartbeat()
	if len(heartbeat) != FrameHeaderSize {
		t.Fatalf("heartbeat length = %d", len(heartbeat))
	}
	wantPrefix := []byte{'a', 'r', 'm', 's', 0, 1}
	if !bytes.Equal(heartbeat[:6], wantPrefix) || !bytes.Equal(heartbeat[6:], make([]byte, 66)) {
		t.Fatalf("unexpected heartbeat: %x", heartbeat)
	}
}

func TestBuildTransaction(t *testing.T) {
	config, err := LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	transaction, nextSequence, requestID, frameCount, err := BuildTransaction(config, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	if nextSequence != 11 || len(requestID) != 36 || frameCount != 4 {
		t.Fatalf("next sequence=%d request ID=%q frameCount=%d", nextSequence, requestID, frameCount)
	}

	frames, err := parseFrames(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("frame count = %d", len(frames))
	}
	wantTypes := [][2]byte{{0x01, 0x01}, {0x63, 0x02}, {0x63, 0x03}, {0x63, 0x63}}
	for index, frame := range frames {
		if frame.messageType != wantTypes[index][0] || frame.subtype != wantTypes[index][1] {
			t.Fatalf("frame %d type=%x/%x", index, frame.messageType, frame.subtype)
		}
		if frame.sequence != uint64(7+index) || frame.requestID != requestID {
			t.Fatalf("frame %d sequence/request ID mismatch", index)
		}
	}
	if len(frames[3].body) != 0 {
		t.Fatalf("completion frame body length = %d, want 0", len(frames[3].body))
	}
	var metadata map[string]any
	if err := json.Unmarshal(frames[0].body, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["requestid"] != requestID || metadata["appname"] != config.AppName {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
}

func TestBuildTransactionSplitsLargeResponse(t *testing.T) {
	config, err := LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	config.ResponseBody = "0123456789"
	config.ResponseBodySize = 70
	config.ResponseChunkSize = 40

	transaction, nextSequence, requestID, frameCount, err := BuildTransaction(config, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := parseFrames(transaction)
	if err != nil {
		t.Fatal(err)
	}
	responseFrameCount := 0
	for _, frame := range frames {
		if frame.messageType == 0x63 && frame.subtype == 0x03 {
			responseFrameCount++
		}
	}
	if responseFrameCount < 2 {
		t.Fatalf("response frame count=%d, want at least 2", responseFrameCount)
	}
	if len(frames) != frameCount || nextSequence != uint64(100+len(frames)) {
		t.Fatalf("frames=%d frameCount=%d nextSequence=%d", len(frames), frameCount, nextSequence)
	}
	for index, frame := range frames {
		if frame.sequence != uint64(100+index) || frame.requestID != requestID {
			t.Fatalf("frame %d sequence/request ID mismatch", index)
		}
	}
	if frames[0].messageType != 0x01 || frames[0].subtype != 0x01 || frames[1].messageType != 0x63 || frames[1].subtype != 0x02 {
		t.Fatalf("bad leading frame types: %+v", frames[:2])
	}
	if frames[len(frames)-1].messageType != 0x63 || frames[len(frames)-1].subtype != 0x63 {
		t.Fatalf("bad completion frame: %+v", frames[len(frames)-1])
	}
	for index := 2; index < len(frames)-1; index++ {
		if frames[index].messageType != 0x63 || frames[index].subtype != 0x03 {
			t.Fatalf("frame %d type=%x/%x", index, frames[index].messageType, frames[index].subtype)
		}
	}
	if len(frames[2].body) != 40 {
		t.Fatalf("first response chunk length=%d", len(frames[2].body))
	}
	responseBody := make([]byte, 0)
	for index := 2; index < len(frames)-1; index++ {
		if len(frames[index].body) <= 0 || len(frames[index].body) > 40 {
			t.Fatalf("response chunk %d length=%d", index, len(frames[index].body))
		}
		responseBody = append(responseBody, frames[index].body...)
	}
	if !bytes.Contains(responseBody, []byte("Content-Length: 70")) {
		t.Fatalf("response chunks do not contain configured content length")
	}
}

type parsedFrame struct {
	messageType byte
	subtype     byte
	sequence    uint64
	requestID   string
	body        []byte
}

func parseFrames(data []byte) ([]parsedFrame, error) {
	frames := make([]parsedFrame, 0, 3)
	for len(data) > 0 {
		if len(data) < FrameHeaderSize {
			return nil, errMalformedFrame
		}
		bodyLength := binary.BigEndian.Uint64(data[52:60])
		frameLength := uint64(FrameHeaderSize) + bodyLength
		if frameLength > uint64(len(data)) {
			return nil, errMalformedFrame
		}
		frames = append(frames, parsedFrame{
			messageType: data[6], subtype: data[7],
			sequence:  binary.BigEndian.Uint64(data[8:16]),
			requestID: string(data[16:52]),
			body:      append([]byte(nil), data[72:frameLength]...),
		})
		data = data[frameLength:]
	}
	return frames, nil
}
