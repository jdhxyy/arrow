// Copyright 2022-2022 The jdh99 Authors. All rights reserved.
// 物联网服务sdk
// Authors: jdh99 <jdh821@163.com>

package arrow

import (
	"errors"
	"github.com/jdhxyy/knock"
	"github.com/jdhxyy/lagan"
	"github.com/jdhxyy/standardlayer"
	"github.com/jdhxyy/udp"
	"github.com/jdhxyy/utz"
)

const (
	tag = "arrow"
)

var gLocalIA uint32 = utz.IAInvalid
var gCoreIP uint32
var gCorePort uint16
var gCoreIA uint32

// Load 模块载入
func Load(ia uint32, localIP uint32, localPort uint16, coreIA uint32, coreIP uint32, corePort uint16) error {
	lagan.Info(tag, "load")

	err := udp.Load(localIP, localPort, 4096)
	if err != nil {
		lagan.Error(tag, "load failed because udp load failed:%s", err)
		return err
	}

	gLocalIA = ia
	gCoreIA = coreIA
	gCoreIP = coreIP
	gCorePort = corePort
	standardlayer.RegisterRxObserver(dealSlRx)
	return nil
}

// dealSlRx 处理标准层回调函数
func dealSlRx(data []uint8, standardHeader *utz.StandardHeader, ip uint32, port uint16) {
	if gLocalIA == utz.IAInvalid || standardHeader.DstIA != gLocalIA {
		return
	}
	if standardHeader.NextHead != utz.HeaderCcp && standardHeader.NextHead != utz.HeaderCmp &&
		standardHeader.NextHead != utz.HeaderDup {
		return
	}

	cmp := utz.CcpFrameToBytes(data)
	if cmp == nil || len(cmp) == 0 {
		lagan.Warn(tag, "ccp frame to bytes failed.ia:0x%x ip:0x%x port:%d", standardHeader.SrcIA, ip, port)
		return
	}
	if len(cmp) == 0 {
		lagan.Warn(tag, "data len is wrong.ia:0x%x ip:0x%x port:%d", standardHeader.SrcIA, ip, port)
		return
	}

	resp := knock.Call(uint16(standardHeader.NextHead), uint16(cmp[0]), cmp[1:], standardHeader.SrcIA, ip, port)
	if resp == nil {
		return
	}

	// 加命令字回复
	respReal := make([]uint8, 1)
	respReal[0] = utz.GetAckCmd(cmp[0])
	respReal = append(respReal, resp...)

	var ackHeader utz.StandardHeader
	ackHeader.Version = utz.ProtocolVersion
	ackHeader.NextHead = utz.HeaderCmp
	ackHeader.SrcIA = gLocalIA
	ackHeader.DstIA = standardHeader.SrcIA

	// 加命令字回复
	standardlayer.Send(utz.BytesToCcpFrame(respReal), &ackHeader, ip, port)
}

// Register 注册服务
// 回调服务有3个参数:IA地址:uint32,IP:uint32,端口:uint16
// 回复时不需要带命令字,自动带回复命令字
func Register(protocol uint8, cmd uint8, callback knock.CallbackFunc) {
	knock.Register(uint16(protocol), uint16(cmd), callback)
}

// Send 基于CCP协议发送数据
func Send(cmd uint8, data []uint8, protocol uint8, dstIA uint32) error {
	if gIsConnectParent == false {
		return errors.New("is not connect")
	}

	var header utz.StandardHeader
	header.Version = utz.ProtocolVersion
	header.NextHead = protocol
	header.SrcIA = gLocalIA
	header.DstIA = dstIA

	arr := make([]uint8, 1+len(data))
	arr[0] = cmd
	arr = append(arr, data...)
	standardlayer.Send(utz.BytesToCcpFrame(arr), &header, gCoreIP, gCorePort)
	return nil
}

// IsConnect 是否连接核心网
func IsConnect() bool {
	return gIsConnectParent
}
