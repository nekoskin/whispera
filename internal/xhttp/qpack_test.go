package xhttp

import (
    "reflect"
    "testing"
)

func TestQPACKAdapterRoundTrip(t *testing.T) {
    adapter := NewQPACKAdapter()

    headers := map[string]string{
        ":method": "GET",
        ":path":   "/test",
        // 'host' exists in static table (empty value), this should exercise name-indexed literal
        "host":    "example.com",
        "user-agent": "whispera-test/1.0",
    }

    enc := adapter.EncodeHeaders(headers)
    dec, err := adapter.DecodeHeaders(enc)
    if err != nil {
        t.Fatalf("DecodeHeaders error: %v", err)
    }

    if !reflect.DeepEqual(headers, dec) {
        t.Fatalf("round-trip mismatch\nexpected: %#v\nactual:   %#v", headers, dec)
    }
}

func TestQPACKDynamicTableInsertion(t *testing.T) {
    adapter := NewQPACKAdapter()

    h := map[string]string{"x-test-dyn": "value1"}

    // First encode: should emit insertion (0x20) and add to adapter dynamic table
    enc1 := adapter.EncodeHeaders(h)
    dec1, err := adapter.DecodeHeaders(enc1)
    if err != nil {
        t.Fatalf("first decode error: %v", err)
    }
    if dec1["x-test-dyn"] != "value1" {
        t.Fatalf("first decode mismatch: %#v", dec1)
    }

    // Second encode: adapter should now detect exact dynamic match and emit dynamic index 0xC0
    enc2 := adapter.EncodeHeaders(h)
    dec2, err := adapter.DecodeHeaders(enc2)
    if err != nil {
        t.Fatalf("second decode error: %v", err)
    }
    if dec2["x-test-dyn"] != "value1" {
        t.Fatalf("second decode mismatch: %#v", dec2)
    }
}
