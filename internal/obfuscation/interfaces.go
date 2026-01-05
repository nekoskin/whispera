package obfuscation

import (
	"context"
	"time"

	"whispera/internal/obfuscation/core/types"
)

// ObfuscationEngine defines the interface for traffic obfuscation
type ObfuscationEngine interface {
	ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error)
	SetActiveProfile(name string) error
	GetActiveProfile() string
	GetProfileNames() []string
}

// MLPredictor defines the interface for ML predictions
type MLPredictor interface {
	PredictTraffic(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	DetectDPI(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	DetectAnomaly(data []byte, protocol string, direction string) (*MLPredictionResponse, error)
	HealthCheck() error
}

// ProfileManager defines the interface for profile management
type ProfileManager interface {
	SetActiveProfile(name string) error
	GetActiveProfile() string
	GetProfileNames() []string
	SwitchProfile(targetProfile string, reason string) error
	GetProfileSwitchHistory() []ProfileSwitch
}

// TrafficAnalyzer defines the interface for traffic analysis
type TrafficAnalyzer interface {
	AnalyzeUserBehavior() string
	AnalyzeThreatLevel() int
	UpdateNetworkConditions()
	GetContext() *ContextAnalyzer
	GetNetworkConditions() *NetworkAnalyzer
}

// APIClient defines the interface for API clients
type APIClient interface {
	GenerateRealisticTraffic(service string, data []byte) ([]byte, error)
	HealthCheck() error
	IsRateLimited(service string) bool
}

// FailSafeManager defines the interface for fail-safe operations
type FailSafeManager interface {
	CheckFailures(ctx context.Context, metrics *FailSafeMetrics) ([]*FailSafeAction, error)
	ExecuteAction(ctx context.Context, action *FailSafeAction) error
	GetActionHistory() []*FailSafeAction
	GetDetectorStatus() []*FailureDetector
}

// HardwareEvasionInterface defines the interface for hardware evasion
type HardwareEvasionInterface interface {
	BypassRestrictions(ctx context.Context, restrictionType string) error
	EmulateHardware(ctx context.Context, targetHardware string) error
	SpoofHardwareIdentity(ctx context.Context, targetIdentity string) error
	GetActiveProfile() string
}

// BehavioralMimicryInterface defines the interface for behavioral mimicry
type BehavioralMimicryInterface interface {
	SetApplicationProfile(name string) error
	GetApplicationProfile() string
	ProcessPacket(data []byte) ([]byte, error)
	GenerateTimingDelay() time.Duration
	GenerateHeartbeat() ([]byte, map[string]string)
	GenerateSessionEvent() map[string]interface{}
}

// UnifiedMLSystemInterface is now defined in internal/obfuscation/core/types
// This alias is kept for backward compatibility
type UnifiedMLSystemInterface = types.UnifiedMLSystemInterface

// UnifiedTrafficContext represents traffic context for ML processing
type UnifiedTrafficContext struct {
	Direction   string    `json:"direction"`
	Protocol    string    `json:"protocol"`
	Size        int       `json:"size"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Port        int       `json:"port"`
}

// MLStats is now defined in internal/obfuscation/core/types
// This alias is kept for backward compatibility
type MLStats = types.MLStats

// FailSafeMetrics contains metrics for fail-safe operations
type FailSafeMetrics struct {
	ObfuscationScore       float64       `json:"obfuscation_score"`
	SessionQuality         float64       `json:"session_quality"`
	ErrorRate              float64       `json:"error_rate"`
	PerformanceScore       float64       `json:"performance_score"`
	Latency                time.Duration `json:"latency"`
	Throughput             int64         `json:"throughput"`
	PacketLoss             float64       `json:"packet_loss"`
	Stability              float64       `json:"stability"`
	ProfilesActivated      int64         `json:"profiles_activated"`
	FailuresDetected       int64         `json:"failures_detected"`
	ActionsExecuted        int64         `json:"actions_executed"`
	RollbacksPerformed     int64         `json:"rollbacks_performed"`
	OperationsExecuted     int64         `json:"operations_executed"`
	FunctionsDisabled      int64         `json:"functions_disabled"`
	RealOperationsExecuted int64         `json:"real_operations_executed"`
	LastUpdate             time.Time     `json:"last_update"`
}

// FailSafeAction represents an action to be taken when fail-safe triggers
type FailSafeAction struct {
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Priority  int                    `json:"priority"`
	Executed  bool                   `json:"executed"`
	Timestamp time.Time              `json:"timestamp"`
	Reason    string                 `json:"reason"`
	Details   map[string]interface{} `json:"details"`
}

// FailureDetector detects various types of failures
type FailureDetector struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Threshold   float64       `json:"threshold"`
	Window      time.Duration `json:"window"`
	LastTrigger time.Time     `json:"last_trigger"`
	Count       int           `json:"count"`
}

// MLPredictionResponse represents ML prediction response
type MLPredictionResponse struct {
	Predictions []MLPrediction `json:"predictions"`
	Confidence  float64        `json:"confidence"`
	Model       string         `json:"model"`
	Timestamp   time.Time      `json:"timestamp"`
}

// MLPrediction represents a single ML prediction
type MLPrediction struct {
	ClassID      int     `json:"class_id"`
	ClassName    string  `json:"class_name"`
	Confidence   float64 `json:"confidence"`
	DPIType      int     `json:"dpi_type"`
	DPIName      string  `json:"dpi_name"`
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"`
}

// ProfileSwitch represents a profile switch event
type ProfileSwitch struct {
	FromProfile string    `json:"from_profile"`
	ToProfile   string    `json:"to_profile"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
}

// ContextAnalyzer represents context analysis results
type ContextAnalyzer struct {
	UserBehavior   string `json:"user_behavior"`
	ThreatLevel    int    `json:"threat_level"`
	NetworkQuality string `json:"network_quality"`
	DeviceType     string `json:"device_type"`
	Location       string `json:"location"`
	TimeOfDay      string `json:"time_of_day"`
}

// NetworkAnalyzer represents network analysis results
type NetworkAnalyzer struct {
	Latency    time.Duration `json:"latency"`
	Bandwidth  int64         `json:"bandwidth"`
	Stability  float64       `json:"stability"`
	PacketLoss float64       `json:"packet_loss"`
	Jitter     time.Duration `json:"jitter"`
}

// TrafficContext represents traffic context for processing
type TrafficContext struct {
	Direction    string    `json:"direction"`
	Protocol     string    `json:"protocol"`
	Size         int       `json:"size"`
	Timestamp    time.Time `json:"timestamp"`
	Source       string    `json:"source"`
	Destination  string    `json:"destination"`
	Port         int       `json:"port"`
	NetworkType  string    `json:"network_type"`
	UserBehavior string    `json:"user_behavior"`
	ThreatLevel  int       `json:"threat_level"`
}

// ObfuscationRule represents a rule for obfuscation
type ObfuscationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     map[string]interface{} `json:"actions"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
}

// TrafficState represents the current state of traffic
type TrafficState struct {
	PacketCount int64     `json:"packet_count"`
	ByteCount   int64     `json:"byte_count"`
	Protocol    string    `json:"protocol"`
	Direction   string    `json:"direction"`
	LastUpdate  time.Time `json:"last_update"`
}
