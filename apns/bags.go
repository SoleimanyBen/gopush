package apns

import (
	"bytes"
	"crypto/tls"
	"howett.net/plist"
	"io"
	"net/http"
)

type OldStyleBag struct {
	APNSCourierHostname                                      string
	APNSVerifiedCourierHostname                              string
	APNSCourierHostcount                                     int
	ClientConnectionRetryAttempts                            int
	APNSCourierStatus                                        bool
	MinConsecutiveKeepAlivesMaintainingWiFiConnection        int `plist:"minConsecutiveKeepAlivesMaintainingWiFiConnection"`
	MinutesDisableSwitchingToWiFiFromCellular                int `plist:"minutesDisableSwitchingToWiFiFromCellular"`
	APNSNumberOfCriticalMessageKeepAlivesBeforeDisconnecting int
	APNSCriticalMessageKeepAliveTimerDuration                float64
	APNSCriticalMessageTimeout                               float64
	APNSWWANTrackedLinkQualityTimeInterval                   float64
	APNSWWANTrackedLinkQualityOffTransitions                 int
	APNSAWDSlowReceiveThreshold                              float64
	APNSLowPriorityMessageBatchSize                          int
	APNSActiveInterval                                       int
	APNSForcedShortTimeoutInterval                           float64
	APNSCostDrivenDualChannelAttempts                        int
	APNSPiggybackDualChannelAttempts                         int
	APNSMaximumLowPriorityBatchesPerHour                     int
	APNSDisableCostDrivenDualChannel                         bool
	APNSLowPriorityBurstWindow                               float64
	APNSLowPriorityBurstDelay                                float64
	APNSLowPriorityBurstSendProbability                      float64
	KeepAliveV2TimeDriftMaximum                              int
	KeepAliveV2TimeDriftMaxAllowed                           int
	APNSIPCachingTTLMinutes                                  int
	APNSIPCachingPercentage                                  int
	Environment                                              string
	APNSNagleEnabled                                         bool
	APNSMinimumIntervalFallbackEnabled                       bool
	APNSIPCachingTTLMinutesV2                                int
	APNSWiFiKeepAliveEarlyFireConstantInterval               int
	APNSCourierHostsPrimaryIPv6                              []byte
	APNSCourierHostsSecondaryIPv4                            []byte
	APNSCourierHostsDefaultIPv4                              []byte
	APNSCourierHostsDefaultIPv6                              []byte
	APNSBagExpiry                                            int
	APNSDeferredHostTimeout                                  int
	APNSFirstUnlockDeliveryStatusProbability                 int
	APNSEnableAlertDowngrade                                 bool
	APNSDelayedReconnectMinIntervalTrigger                   int
	APNSDelayedReconnectIntervalAll                          int
	APNSDelayedReconnectMaxIntervalTrigger                   int
	APNSDelayedReconnectMaxInterval                          int
	APNSDelayedReconnectTLSIntervalTrigger                   int
	APNSDelayedReconnectTLSInterval                          int
	APNSAllowTLS1_3                                          int
	APNSCloudChannelRetryCount                               int
	APNSCloudChannelRequestTimeoutSeconds                    int
	APNSWebPushEndpointPath                                  string
	APNSEnableSimulatorConnection                            bool
	APNSMinPresenceSaltRotationIntervalMinutes               int
	APNSFilterOptimizationEnabledV1                          bool
}

type bag struct {
	Signature []byte   `plist:"signature"`
	Certs     [][]byte `plist:"certs"`
	Bag       []byte   `plist:"bag"`
}

type NewStyleBag = bag
type IDSBag = bag

func NewBagger() (*Bagger, error) {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return &Bagger{client}, nil
}

type Bagger struct {
	client http.Client
}

func (b *Bagger) OldStyle() (OldStyleBag, error) {
	res, err := b.client.Get("https://init.push.apple.com/bag")
	if err != nil {
		return OldStyleBag{}, err
	}

	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, res.Body); err != nil {
		return OldStyleBag{}, err
	}

	var oldBag OldStyleBag
	if _, err := plist.Unmarshal(buf.Bytes(), &oldBag); err != nil {
		return OldStyleBag{}, err
	}

	return oldBag, nil
}

func (b *Bagger) NewStyle() (NewStyleBag, error) {
	res, err := b.client.Get("http://init-p01st.push.apple.com/bag")
	if err != nil {
		return IDSBag{}, err
	}

	bagData, err := b.parseBag(res.Body)
	if err != nil {
		return bagData, err
	}

	return bagData, nil
}

func (b *Bagger) IDSBag() (IDSBag, error) {
	res, err := b.client.Get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")
	if err != nil {
		return IDSBag{}, err
	}

	bagData, err := b.parseBag(res.Body)
	if err != nil {
		return bagData, err
	}

	return bagData, nil
}

func (b *Bagger) parseBag(r io.Reader) (bag, error) {
	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, r); err != nil {
		return bag{}, err
	}

	var bagData bag
	if _, err := plist.Unmarshal(buf.Bytes(), &bagData); err != nil {
		return bag{}, err
	}

	return bagData, nil
}
