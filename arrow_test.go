package arrow

import (
	"github.com/jdhxyy/lagan"
	"testing"
	"time"
)

func TestCase1(t *testing.T) {
	lagan.SetFilterLevel(lagan.LevelDebug)

	err := Load(0x41000105, 0x7f000001, 1234, 0x41000002, 0x7f000001, 14129)
	if err != nil {
		t.Error()
		return
	}

	select {
	case <-time.After(time.Second * 10):
	}
}
