// Copyright 2022-2022 The jdh99 Authors. All rights reserved.
// 申请从机
// Authors: jdh99 <jdh821@163.com>

package arrow

import (
	"github.com/jdhxyy/knock"
	"github.com/jdhxyy/lagan"
	sbc "github.com/jdhxyy/sbc-golang"
	"github.com/jdhxyy/standardlayer"
	"github.com/jdhxyy/utz"
	"time"
)

var gSlaveIA = uint32(utz.IAInvalid)
var gSlaveIP uint32
var gSlavePort uint16
var gIsApplyOK = false

func init() {
	knock.Register(utz.HeaderCmp, uint16(utz.GetAckCmd(utz.CmpApplySlave)), dealAckApplySlave)
	go apply()
}

func dealAckApplySlave(req []uint8, params ...interface{}) []uint8 {
	var ack utz.CmpAckApplySlave
	if ack.Result != utz.CmpApplySlaveResultOK {
		lagan.Error(tag, "apply slave result failed:%d", ack.Result)
		return nil
	}

	err := sbc.BytesToStruct(req, &ack)
	if err != nil {
		lagan.Error(tag, "apply slave failed.bytes to struct failed:%s", err)
		return nil
	}

	lagan.Info(tag, "ack apply slave.slave:0x%08x,addr:0x%08x:%d", ack.SlaveIA, ack.SlaveIP, ack.SlavePort)

	gSlaveIA = ack.SlaveIA
	gSlaveIP = ack.SlaveIP
	gSlavePort = ack.SlavePort

	gIsApplyOK = true

	return nil
}

func apply() {
	for {
		if gIsApplyOK == true || gCoreIA == utz.IAInvalid {
			time.Sleep(time.Second)
			continue
		}

		sendApply()
		time.Sleep(time.Second * 5)
	}
}

func sendApply() {
	var header utz.StandardHeader
	header.SrcIA = gLocalIA
	header.DstIA = gCoreIA
	header.NextHead = utz.HeaderCmp
	header.FrameIndex = utz.GetFrameIndex()

	var req utz.CmpReqApplySlave
	req.AssignedSlaveIA = gSlaveIA

	reqBytes, err := sbc.StructToBytes(&req)
	if err != nil {
		lagan.Error(tag, "apply failed.struct to bytes failed:%s", err)
		return
	}

	lagan.Info(tag, "send apply slave frame")

	frame := make([]uint8, 1)
	frame[0] = utz.CmpApplySlave
	frame = append(frame, reqBytes...)
	standardlayer.Send(utz.BytesToCcpFrame(frame), &header, gCoreIP, gCorePort)
}

func startApply() {
	if gIsApplyOK == true {
		gIsApplyOK = false
		gSlaveIA = utz.IAInvalid
		gSlaveIP = 0
		gSlavePort = 0
	}
}
