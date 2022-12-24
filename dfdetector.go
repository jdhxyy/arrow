// Copyright 2019-2022 The jdh99 Authors. All rights reserved.
// 重复帧检测模块
// duplicate frame简称df
// Authors: jdh99 <jdh821@163.com>

package arrow

import (
	"container/list"
	"github.com/jdhxyy/lagan"
	"time"
)

const (
	// expirationTime 过期时间.单位:s
	expirationTime = 5
	// deltaIndexMax 最大不同的序号
	deltaIndexMax = 250
)

type tDFItem struct {
	id    uint32
	index uint32
	// 时间戳.单位:s
	timestamp int64
}

var gDFList *list.List

func init() {
	gDFList = list.New()
}

// dfQuery 查询是否有重复帧.查询时会清除过期节点
func dfQuery(id uint32, index uint32) bool {
	node := gDFList.Back()
	if node == nil {
		return false
	}

	var nodePrev *list.Element
	var item *tDFItem
	now := time.Now().Unix()
	for {
		nodePrev = node.Prev()

		item = node.Value.(*tDFItem)
		// 有过期节点则前面所有节点都是过期节点
		if now-item.timestamp > expirationTime {
			removeAllExpirationNode(node)
			return false
		}

		if item.id == id && item.index == index {
			return true
		}

		if item.id == id && abs(item.index, index) > deltaIndexMax {
			lagan.Error(tag, "remove delta index max node:0x%08x %d", item.id, item.index)
			gDFList.Remove(node)
		}

		node = nodePrev
		if node == nil {
			return false
		}
	}
}

func abs(num1 uint32, num2 uint32) uint32 {
	if num1 > num2 {
		return num1 - num2
	} else {
		return num2 - num1
	}
}

// removeAllExpirationNode 删除从首节点到startNode节点的所有过期节点
func removeAllExpirationNode(startNode *list.Element) {
	var node *list.Element
	for {
		node = gDFList.Front()
		if node == nil {
			return
		}
		gDFList.Remove(node)
		if node == startNode {
			return
		}
	}
}

// dfInsert 插入帧信息.如果是重复帧,则插入失败
func dfInsert(id uint32, index uint32) bool {
	if dfQuery(id, index) == true {
		return false
	}

	var item tDFItem
	item.id = id
	item.index = index
	item.timestamp = time.Now().Unix()
	gDFList.PushBack(&item)
	return true
}
