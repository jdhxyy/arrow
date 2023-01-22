// Copyright 2022-2022 The jdh99 Authors. All rights reserved.
// 物联网服务sdk
// Authors: jdh99 <jdh821@163.com>

package arrow

import (
	"errors"
	"github.com/jdhxyy/dfdetector"
	"github.com/jdhxyy/fsp"
	"github.com/jdhxyy/knock"
	"github.com/jdhxyy/lagan"
	sbc "github.com/jdhxyy/sbc-golang"
	"github.com/jdhxyy/standardlayer"
	"github.com/jdhxyy/udp"
	"github.com/jdhxyy/utz"
	vsocket "github.com/jdhxyy/vsocket-golang"
)

const (
	tag          = "arrow"
	gFrameMaxLen = 4096
)

var gLocalIA uint32 = utz.IAInvalid
var gCoreIP uint32
var gCorePort uint16
var gCoreIA uint32
var gPipe uint64

// Load 模块载入
func Load(ia uint32, localIP uint32, localPort uint16, coreIA uint32, coreIP uint32, corePort uint16) error {
	lagan.Info(tag, "load")

	dfdetector.Load(5000, 250)
	err := udp.Load(localIP, localPort, gFrameMaxLen)
	if err != nil {
		lagan.Error(tag, "load failed because udp load failed:%s", err)
		return err
	}

	gPipe = (uint64(localIP) << 32) + uint64(localPort)
	vsocket.Create(&vsocket.SocketInfo{Pipe: gPipe,
		IsAllowSend: func() bool {
			return true
		},
		Send: func(data []uint8, ip uint32, port uint16) {
			udp.Send(fsp.BytesToFrame(data, false), ip, port)
		}})

	udp.RegisterObserver(func(data []uint8, ip uint32, port uint16) {
		pipe := (uint64(ip) << 32) + uint64(port)
		fsp.Receive(data, pipe, ip, port)
	})

	fsp.RegisterObserver(func(data []uint8, pipe uint64, params ...any) {
		vsocket.Receive(&vsocket.RxParam{Pipe: gPipe, Data: data, IP: params[0].(uint32), Port: params[1].(uint16)})
	})

	gLocalIA = ia
	gCoreIA = coreIA
	gCoreIP = coreIP
	gCorePort = corePort
	standardlayer.RegisterRxObserver(dealSlRx)
	return nil
}

// dealSlRx 处理标准层回调函数
func dealSlRx(data []uint8, standardHeader *utz.StandardHeader, pipe uint64, ip uint32, port uint16) {
	if gLocalIA == utz.IAInvalid || standardHeader.DstIA != gLocalIA {
		return
	}

	offset := 0
	nextHead := standardHeader.NextHead

	var agentHeader *utz.AgentHeader = nil
	var tcpHeader *utz.TcpHeader = nil
	if standardHeader.NextHead == utz.HeaderTcp {
		tcpHeader, offset = utz.BytesToTcpHeader(data)
		if tcpHeader == nil || offset == 0 {
			lagan.Warn(tag, "bytes to tcp header failed.ia:0x%08x addr:0x%08x:%d", standardHeader.SrcIA, ip,
				port)
			return
		}
		if tcpHeader.DstRelayIA != gLocalIA {
			lagan.Error(tag, "tcp dst relay ia is not me:0x%08x", tcpHeader.DstRelayIA)
			return
		}
		nextHead = tcpHeader.NextHead
		rtAdd(standardHeader.SrcIA, tcpHeader.SrcRelayIA, true)

		// 回复应答帧
		sendAckFrame(standardHeader, tcpHeader)
		// 如果非重复帧则处理
		if dfdetector.Insert(standardHeader.SrcIA, uint32(standardHeader.FrameIndex)) == false {
			lagan.Warn(tag, "repeat frame.ia:0x%08x addr:0x%08x:%d index:%d", standardHeader.SrcIA, ip, port,
				standardHeader.FrameIndex)
			return
		}
	} else if standardHeader.NextHead == utz.HeaderAgent {
		agentHeader, offset = utz.BytesToAgentHeader(data)
		if agentHeader == nil || offset == 0 {
			lagan.Warn(tag, "bytes to agent header failed.ia:0x%08x addr:0x%08x:%d", standardHeader.SrcIA, ip,
				port)
			return
		}
		nextHead = agentHeader.NextHead
		rtAdd(standardHeader.SrcIA, agentHeader.IA, false)
	}

	if nextHead != utz.HeaderCcp && nextHead != utz.HeaderCmp && nextHead != utz.HeaderDup {
		return
	}

	cmp := utz.CcpFrameToBytes(data[offset:])
	if cmp == nil || len(cmp) == 0 {
		lagan.Warn(tag, "ccp frame to bytes failed.ia:0x%x addr:0x%08x:%d", standardHeader.SrcIA, ip, port)
		return
	}
	if len(cmp) == 0 {
		lagan.Warn(tag, "data len is wrong.ia:0x%x addr:0x%08x:%d", standardHeader.SrcIA, ip, port)
		return
	}

	resp := knock.Call(uint16(nextHead), uint16(cmp[0]), cmp[1:], standardHeader.SrcIA, ip, port)
	if resp == nil {
		return
	}
	resp = utz.BytesToCcpFrame(resp)

	var ackHeader utz.StandardHeader
	ackHeader.NextHead = nextHead
	ackHeader.SrcIA = gLocalIA
	ackHeader.DstIA = standardHeader.SrcIA
	ackHeader.FrameIndex = utz.GetFrameIndex()

	if tcpHeader != nil {
		tcpHeader.NextHead = ackHeader.NextHead
		tcpHeader.DstRelayIA = tcpHeader.SrcRelayIA
		tcpHeader.SrcRelayIA = gLocalIA

		ackHeader.NextHead = utz.HeaderTcp
		resp = append(tcpHeader.Bytes(), resp...)
	} else if agentHeader != nil {
		// 如果发过来有代理头部,则回复需要加路由头部
		var routeHeader utz.RouteHeader
		routeHeader.NextHead = ackHeader.NextHead
		routeHeader.IA = agentHeader.IA

		ackHeader.NextHead = utz.HeaderRoute
		resp = append(routeHeader.Bytes(), resp...)
	}

	standardlayer.Send(resp, &ackHeader, gPipe, ip, port)
}

func sendAckFrame(standardHeader *utz.StandardHeader, tcpHeader *utz.TcpHeader) {
	var ackStandardHeader utz.StandardHeader
	ackStandardHeader = *standardHeader
	ackStandardHeader.DstIA = tcpHeader.SrcRelayIA
	ackStandardHeader.SrcIA = gLocalIA

	var ackTcpHeader utz.TcpHeader
	ackTcpHeader = *tcpHeader
	ackTcpHeader.DstRelayIA = tcpHeader.SrcRelayIA
	ackTcpHeader.SrcRelayIA = gLocalIA
	ackTcpHeader.NextHead = utz.HeaderTcpcmp

	var payload []uint8
	payload = append(payload, utz.TcpCmdAck)

	var ack utz.TcpAck
	ack.IA = standardHeader.SrcIA
	ack.Index = standardHeader.FrameIndex
	ackBytes, err := sbc.StructToBytes(&ack)
	if err != nil {
		lagan.Error(tag, "send ack failed.struct to bytes failed.error:%s", err)
		return
	}
	payload = append(payload, ackBytes...)

	var frame []uint8
	frame = append(frame, ackTcpHeader.Bytes()...)
	frame = append(frame, utz.BytesToCcpFrame(payload)...)

	standardlayer.Send(frame, &ackStandardHeader, gPipe, gCoreIP, gCorePort)
}

// Register 注册服务
// 回调服务有3个参数:IA地址:uint32,IP:uint32,端口:uint16
// 回复时不需要带命令字,自动带回复命令字
func Register(protocol uint8, cmd uint8, callback knock.CallbackFunc) {
	knock.Register(uint16(protocol), uint16(cmd), callback)
}

// Send 基于CCP协议发送数据
func Send(protocol uint8, cmd uint8, data []uint8, dstIA uint32) error {
	if gIsConnectParent == false {
		return errors.New("is not connect")
	}

	// 是否tcp节点规则
	// 路由表如果能查到，按照路由表来定
	// 路由表如果查不到，且是固定单播地址，则默认是tcp节点
	isTcp := false
	rtItem := rtGet(dstIA)
	if rtItem != nil {
		isTcp = rtItem.IsTcp
	} else {
		if utz.IsGlobalIA(dstIA) == false {
			isTcp = true
		}
	}

	var header utz.StandardHeader
	header.NextHead = protocol
	header.SrcIA = gLocalIA
	header.DstIA = dstIA
	header.FrameIndex = utz.GetFrameIndex()

	arr := make([]uint8, 1)
	arr[0] = cmd
	arr = append(arr, data...)
	arr = utz.BytesToCcpFrame(arr)

	if isTcp == true {
		var tcpHeader utz.TcpHeader
		tcpHeader.SrcRelayIA = gLocalIA
		tcpHeader.DstRelayIA = gCoreIA
		tcpHeader.ControlWord.IsQos1 = true
		tcpHeader.ControlWord.IsContinueSend = false
		tcpHeader.ControlWord.IsAckSend = false
		tcpHeader.ControlWord.IsReceiveAckSend = false
		tcpHeader.AgingTime = 0
		tcpHeader.NextHead = header.NextHead

		header.NextHead = utz.HeaderTcp
		arr = append(tcpHeader.Bytes(), arr...)
	} else {
		var item *Item = nil
		if utz.IsGlobalIA(dstIA) == false {
			// 不是全球单播地址,则需要代理
			item = rtItem
			if item == nil {
				return errors.New("ia is not global")
			}
		}

		if item != nil {
			// 固定单播地址需要加路由头部
			var routeHeader utz.RouteHeader
			routeHeader.NextHead = header.NextHead
			routeHeader.IA = item.AgentIA

			header.NextHead = utz.HeaderRoute
			arr = append(routeHeader.Bytes(), arr...)
		}
	}

	standardlayer.Send(arr, &header, gPipe, gCoreIP, gCorePort)
	return nil
}

// IsConnect 是否连接核心网
func IsConnect() bool {
	return gIsConnectParent
}

// GetParentIA 读取父节点IA
func GetParentIA() uint32 {
	return gSlaveIA
}

// GetParentIP 读取父节点IP
func GetParentIP() uint32 {
	return gSlaveIP
}

// GetParentPort 读取父节点端口
func GetParentPort() uint16 {
	return gSlavePort
}
