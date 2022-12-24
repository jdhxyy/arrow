package arrow

import (
	"github.com/jdhxyy/lagan"
	"github.com/jdhxyy/skiplist"
	"sync"
	"time"
)

const (
	// 路由条目超时时间.单位:s
	rtTimeout = 3600
)

// Item 路由表条目.本表存储的全都是自组网节点数据
type Item struct {
	IA uint32
	// 代理地址
	AgentIA uint32
	// 是否TCP节点.TCP节点的代理地址与核心网一致
	IsTcp bool
	// 更新时间戳.单位:s
	timestamp int64
}

var rtList *skiplist.SkipList

// 资源锁
var lock sync.RWMutex

func init() {
	lagan.Info(tag, "rt init")

	rtList = skiplist.New(skiplist.Uint32)
	go rtCheckTimeout()
}

func rtCheckTimeout() {
	var item *Item
	var elem *skiplist.Element
	var elemNext *skiplist.Element
	var now int64

	for {
		lock.Lock()

		if elem == nil || (elem.Prev() == nil && elem.Next() == nil) {
			elem = rtList.Front()
		}
		now = time.Now().Unix()

		for i := 0; i < 10; i++ {
			if elem == nil {
				break
			}
			elemNext = elem.Next()

			item = elem.Value.(*Item)
			if now-item.timestamp > rtTimeout {
				lagan.Warn(tag, "item timeout.ia:0x%08x", item.IA)
				rtList.Remove(item.IA)
			}

			elem = elemNext
		}

		lock.Unlock()

		time.Sleep(100 * time.Millisecond)
	}
}

// rtAdd 增加条目.条目如果存在则会更新
func rtAdd(ia uint32, agentIA uint32, isTcp bool) {
	lagan.Debug(tag, "rt add:ia:0x%08x agent:0x%08x", ia, agentIA)

	lock.Lock()
	defer lock.Unlock()

	elem := rtList.Get(ia)
	var value *Item

	if elem == nil {
		value = new(Item)
		rtList.Set(ia, value)
	} else {
		value = elem.Value.(*Item)
	}
	value.IA = ia
	value.AgentIA = agentIA
	value.IsTcp = isTcp
	value.timestamp = time.Now().Unix()
}

// rtDelete 删除条目
func rtDelete(ia uint32) {
	lock.Lock()
	defer lock.Unlock()

	elem := rtList.Get(ia)
	if elem == nil {
		return
	}
	lagan.Debug(tag, "lrt delete item.ia:0x%x", ia)
	rtList.Remove(ia)
}

// rtGet 获取代理节点地址.返回nil表示获取失败
func rtGet(ia uint32) *Item {
	lock.Lock()
	defer lock.Unlock()

	elem := rtList.Get(ia)
	if elem == nil {
		return nil
	} else {
		return elem.Value.(*Item)
	}
}
