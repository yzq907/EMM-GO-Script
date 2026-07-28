package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const FrameHeaderSize = 72

const defaultResponseChunkSize = 32 * 1024

var errMalformedFrame = errors.New("malformed ARMS frame")

type metadataBody struct {
	AppName    string `json:"appname"`
	ServerID   int    `json:"serverid"`
	Username   string `json:"username"`
	RequestID  string `json:"requestid"`
	SessionID  string `json:"sessionid"`
	ClientAddr string `json:"cliaddr"`
	ServerAddr string `json:"svraddr"`
	DeviceID   string `json:"deviceid"`
	DeviceType string `json:"devicetype"`
	TokenID    string `json:"tokenid"`
}

func EncodeFrame(messageType, subtype byte, sequence uint64, requestID string, body []byte) ([]byte, error) {
	if len(requestID) != 36 {
		return nil, fmt.Errorf("request ID must contain exactly 36 ASCII bytes")
	}
	frame := make([]byte, FrameHeaderSize+len(body))
	copy(frame[0:4], "arms")
	binary.BigEndian.PutUint16(frame[4:6], 1)
	frame[6] = messageType
	frame[7] = subtype
	binary.BigEndian.PutUint64(frame[8:16], sequence)
	copy(frame[16:52], requestID)
	binary.BigEndian.PutUint64(frame[52:60], uint64(len(body)))
	copy(frame[FrameHeaderSize:], body)
	return frame, nil
}

func EncodeHeartbeat() []byte {
	heartbeat := make([]byte, FrameHeaderSize)
	copy(heartbeat[0:4], "arms")
	binary.BigEndian.PutUint16(heartbeat[4:6], 1)
	return heartbeat
}

func BuildTransaction(config Config, sequence uint64, workerID int) ([]byte, uint64, string, int, error) {
	requestID, err := newUUID()
	if err != nil {
		return nil, sequence, "", 0, err
	}
	compactID := strings.ReplaceAll(requestID, "-", "")
	metadata, err := json.Marshal(metadataBody{
		AppName: config.AppName, ServerID: config.ServerID,
		Username: config.UsernamePrefix + strconv.Itoa(workerID), RequestID: requestID,
		SessionID:  config.SessionPrefix + compactID,
		ClientAddr: fmt.Sprintf("%s:%d", config.ClientIP, 40000+(workerID%20000)),
		ServerAddr: config.ServerAddress, DeviceID: compactID,
		DeviceType: "load_generator", TokenID: compactID,
	})
	if err != nil {
		return nil, sequence, "", 0, fmt.Errorf("encode metadata: %w", err)
	}

	requestBody := []byte(fmt.Sprintf(
		"%s %s HTTP/1.0\r\nX-Forwarded-For: %s\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ARMSLoadGenerator/1.0\r\nX-Requested-With: com.leagsoft.emm\r\n\r\n",
		config.RequestMethod, config.RequestPath, config.ClientIP, config.RequestHost,
	))
	statusText := http.StatusText(config.ResponseStatus)
	if statusText == "" {
		statusText = "Synthetic"
	}
	responseContent := buildResponseContent(config)
	responseBody := []byte(fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nServer: arms-load-generator\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		config.ResponseStatus, statusText, len(responseContent), responseContent,
	))

	metadataFrame, err := EncodeFrame(0x01, 0x01, sequence, requestID, metadata)
	if err != nil {
		return nil, sequence, "", 0, err
	}
	requestFrame, err := EncodeFrame(0x63, 0x02, sequence+1, requestID, requestBody)
	if err != nil {
		return nil, sequence, "", 0, err
	}
	responseFrames, nextSequence, err := EncodeResponseFrames(sequence+2, requestID, responseBody, config.ResponseChunkSize)
	if err != nil {
		return nil, sequence, "", 0, err
	}
	completionFrame, err := EncodeFrame(0x63, 0x63, nextSequence, requestID, nil)
	if err != nil {
		return nil, sequence, "", 0, err
	}
	transaction := make([]byte, 0, len(metadataFrame)+len(requestFrame)+len(responseBody)+len(responseFrames)*FrameHeaderSize+len(completionFrame))
	transaction = append(transaction, metadataFrame...)
	transaction = append(transaction, requestFrame...)
	for _, frame := range responseFrames {
		transaction = append(transaction, frame...)
	}
	transaction = append(transaction, completionFrame...)
	frameCount := 2 + len(responseFrames) + 1
	return transaction, nextSequence + 1, requestID, frameCount, nil
}

func EncodeResponseFrames(sequence uint64, requestID string, responseBody []byte, chunkSize int) ([][]byte, uint64, error) {
	if chunkSize == 0 {
		chunkSize = len(responseBody)
	}
	if chunkSize <= 0 {
		chunkSize = defaultResponseChunkSize
	}
	frames := make([][]byte, 0, (len(responseBody)+chunkSize-1)/chunkSize)
	for start := 0; start < len(responseBody); start += chunkSize {
		end := start + chunkSize
		if end > len(responseBody) {
			end = len(responseBody)
		}
		frame, err := EncodeFrame(0x63, 0x03, sequence, requestID, responseBody[start:end])
		if err != nil {
			return nil, sequence, err
		}
		frames = append(frames, frame)
		sequence++
	}
	return frames, sequence, nil
}

func buildResponseContent(config Config) string {
	if config.ResponseBodySize == 0 {
		return config.ResponseBody
	}
	seed := config.ResponseBody
	if seed == "" {
		seed = "ARMS load generator response body\n"
	}
	content := make([]byte, 0, config.ResponseBodySize)
	for len(content) < config.ResponseBodySize {
		remaining := config.ResponseBodySize - len(content)
		if remaining >= len(seed) {
			content = append(content, seed...)
			continue
		}
		content = append(content, seed[:remaining]...)
	}
	return string(content)
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded), nil
}
