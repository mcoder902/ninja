package remotego

import "time"

// EventType نشان‌دهنده مرحله جاری چرخه عمر اتصال است
type EventType string

const (
	EventDialing        EventType = "DIALING"
	EventConnected      EventType = "CONNECTED"
	EventHandshaking    EventType = "HANDSHAKING"
	EventAuthenticating EventType = "AUTHENTICATING"
	EventSuccess        EventType = "SUCCESS"
	EventFailed         EventType = "FAILED"
)

// ProbeEvent ساختار داده‌ای یک رویداد لحظه‌ای است
type ProbeEvent struct {
	Target    Target
	Type      EventType
	Timestamp time.Time
	Detail    string
}

// EventCallback نوع تابع کال‌بک برای دریافت رویدادهاست
type EventCallback func(event ProbeEvent)
