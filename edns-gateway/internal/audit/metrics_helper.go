package audit

import "sync/atomic"

// droppedAudit 统计因队列满而丢弃的审计事件（暴露给 metrics 包）。
var droppedAudit atomic.Uint64

// DroppedCount 返回丢弃计数。
func DroppedCount() uint64 { return droppedAudit.Load() }
