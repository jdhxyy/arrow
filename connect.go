// Copyright 2022-2022 The jdh99 Authors. All rights reserved.
// 连接父路由
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

const retryConnectMax = 5

var gIsConnectAck = false
var gIsConnectParent = false

func init() {
	knock.Register(utz.HeaderCmp, uint16(utz.GetAckCmd(utz.CmpConnectParent)), dealAckConnectParent)
	go connect()
}

func dealAckConnectParent(req []uint8, params ...interface{}) []uint8 {
	var ack utz.CmpAckConnectParent

	err := sbc.BytesToStruct(req, &ack)
	if err != nil {
		lagan.Error(tag, "apply slave failed.bytes to struct failed:%s", err)
		return nil
	}

	if ack.Result != utz.CmpConnectParentResultOK {
		lagan.Error(tag, "connect parent result failed:%d", ack.Result)
		return nil
	}
	lagan.Info(tag, "parent ia:0x%08x addr:0x%08x:%d cost:%d", gSlaveIA, gSlaveIP, gSlavePort, ack.Cost)
	gIsConnectAck = true
	return nil
}

func connect() {
	retry := 0

	for {
		// 未申请父节点成功则不用连接
		if gIsApplyOK == false {
			time.Sleep(time.Second)
			continue
		}

		gIsConnectAck = false
		retry++
		sendConnect()
		time.Sleep(time.Second)
		if gIsConnectAck == true {
			retry = 0
			gIsConnectParent = true
			time.Sleep(time.Minute)
		} else {
			if retry > retryConnectMax {
				retry = 0
				gIsConnectParent = false
				startApply()
				time.Sleep(time.Second * 5)
			}
		}
	}
}

func sendConnect() {
	lagan.Info(tag, "send connect frame")
	var header utz.StandardHeader
	header.SrcIA = gLocalIA
	header.DstIA = gSlaveIA
	header.NextHead = utz.HeaderCmp
	header.FrameIndex = utz.GetFrameIndex()

	standardlayer.Send(utz.BytesToCcpFrame([]uint8{utz.CmpConnectParent}), &header, gSlaveIP, gSlavePort)
}
