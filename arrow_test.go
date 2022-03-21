package arrow

import (
	"fmt"
	"github.com/jdhxyy/lagan"
	"github.com/jdhxyy/utz"
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

func TestCase2(t *testing.T) {
	lagan.SetFilterLevel(lagan.LevelDebug)

	err := Load(0x41000105, 0x7f000001, 1234, 0x41000002, 0x7f000001, 14129)
	if err != nil {
		t.Error()
		return
	}

	select {
	case <-time.After(time.Second * 5):
	}

	fmt.Println("send frame")
	Send(utz.HeaderCcp, 2, nil, 0x41000005)

	select {
	case <-time.After(time.Second * 5):
	}
}
