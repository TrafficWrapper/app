package device

import (
	"errors"
	"fmt"
)

// Upper bounds enforced on AWG parameters set over UAPI. They are far wider
// than any dialect a TrafficWrapper worker generates (Jc<=16, Jmax<=264,
// S1/S2<=150, S3<=64, S4<=32); they only exclude values that would make the
// packet paths panic or allocate unbounded buffers.
const (
	maxAWGJunkCount = 128
	maxAWGJunkSize  = MaxSegmentSize
)

// awgParams is an immutable snapshot of the AmneziaWG obfuscation settings.
// Packet goroutines load it once per packet through Device.awgParams; UAPI
// set builds a complete replacement, validates it and swaps the pointer, so
// readers never observe a half-applied or invalid combination.
type awgParams struct {
	junkCount int
	junkMin   int
	junkMax   int

	initPadding      int
	responsePadding  int
	cookiePadding    int
	transportPadding int

	initHeader      *magicHeader
	responseHeader  *magicHeader
	cookieHeader    *magicHeader
	transportHeader *magicHeader

	ipackets [5]*obfChain
}

func defaultAWGParams() *awgParams {
	return &awgParams{
		initHeader:      &magicHeader{start: MessageInitiationType, end: MessageInitiationType},
		responseHeader:  &magicHeader{start: MessageResponseType, end: MessageResponseType},
		cookieHeader:    &magicHeader{start: MessageCookieReplyType, end: MessageCookieReplyType},
		transportHeader: &magicHeader{start: MessageTransportType, end: MessageTransportType},
	}
}

// awgParams returns the current AWG settings. The result must be treated as
// read-only.
func (device *Device) awgParams() *awgParams {
	if p := device.awg.Load(); p != nil {
		return p
	}
	return defaultAWGParams()
}

func (p *awgParams) clone() *awgParams {
	out := *p
	return &out
}

// validate checks the whole parameter set. tunMTU is the current inner MTU,
// used to make sure transport padding still fits the message buffer.
func (p *awgParams) validate(tunMTU int) error {
	if p.junkCount < 0 || p.junkCount > maxAWGJunkCount {
		return fmt.Errorf("jc must be in [0,%d], got %d", maxAWGJunkCount, p.junkCount)
	}
	if p.junkMin < 0 || p.junkMin > maxAWGJunkSize || p.junkMax < 0 || p.junkMax > maxAWGJunkSize {
		return fmt.Errorf("jmin and jmax must be in [0,%d], got jmin=%d jmax=%d", maxAWGJunkSize, p.junkMin, p.junkMax)
	}
	if p.junkMin > p.junkMax {
		return fmt.Errorf("jmin must be <= jmax, got jmin=%d jmax=%d", p.junkMin, p.junkMax)
	}
	paddings := []struct {
		name    string
		padding int
		size    int
	}{
		{"s1", p.initPadding, MessageInitiationSize},
		{"s2", p.responsePadding, MessageResponseSize},
		{"s3", p.cookiePadding, MessageCookieReplySize},
		{"s4", p.transportPadding, MessageTransportSize},
	}
	for _, pad := range paddings {
		if pad.padding < 0 || pad.padding > MaxSegmentSize-pad.size {
			return fmt.Errorf("%s must be in [0,%d], got %d", pad.name, MaxSegmentSize-pad.size, pad.padding)
		}
	}
	// Transport padding is inserted in place in front of a full-MTU packet
	// inside a MaxMessageSize buffer.
	if tunMTU > 0 && p.transportPadding > 0 {
		contentMax := tunMTU
		if contentMax > MaxContentSize {
			contentMax = MaxContentSize
		}
		if p.transportPadding+MessageTransportSize+contentMax+PaddingMultiple > MaxMessageSize {
			return fmt.Errorf("s4=%d does not fit mtu %d", p.transportPadding, tunMTU)
		}
	}
	headers := []*magicHeader{p.initHeader, p.responseHeader, p.cookieHeader, p.transportHeader}
	for i, h := range headers {
		if h == nil {
			return fmt.Errorf("h%d is not set", i+1)
		}
		if h.start > h.end {
			return fmt.Errorf("h%d range is inverted", i+1)
		}
		for j := i + 1; j < len(headers); j++ {
			other := headers[j]
			if other != nil && h.start <= other.end && other.start <= h.end {
				return errors.New("headers must not overlap")
			}
		}
	}
	for i, chain := range p.ipackets {
		if chain != nil && chain.ObfuscatedLen(0) > MaxSegmentSize {
			return fmt.Errorf("i%d is longer than %d bytes", i+1, MaxSegmentSize)
		}
	}
	return nil
}
