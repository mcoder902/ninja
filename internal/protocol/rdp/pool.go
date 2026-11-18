package rdp

import (
	"sync"
)

// بافر پولی برای پکت‌های RDP با اندازه‌های مختلف (تا ۶۴ کیلوبایت)
var rdpBufferPool = sync.Pool{
	New: func() interface{} {
		// تخصیص اولیه یک آرایه ۶۴ کیلوبایتی (حداکثر سایز استاندارد TPKT)
		b := make([]byte, maxTPKTLength)
		return &b
	},
}

// GetBuffer یک بافر از استخر دریافت می‌کند
func GetBuffer(size int) []byte {
	if size <= maxTPKTLength {
		ptr := rdpBufferPool.Get().(*[]byte)
		return (*ptr)[:size]
	}
	// اگر سایز درخاستی بزرگ‌تر از حد استاندارد بود، مستقیم تخصیص داده می‌شود
	return make([]byte, size)
}

// PutBuffer بافر را پس از استفاده به استخر برمی‌گرداند
func PutBuffer(buf []byte) {
	// «==» نه «>=»: بافرهای بزرگ‌تر از حد استاندارد (تخصیص یک‌باره در
	// GetBuffer) نباید وارد استخر شوند؛ وگرنه برای همیشه در استخر
	// می‌مانند و حافظه‌ی اشغال‌شده آزاد نمی‌شود.
	if cap(buf) == maxTPKTLength {
		// بازگرداندن اسلایس با ظرفیت کامل به استخر
		fullSlice := buf[:cap(buf)]
		rdpBufferPool.Put(&fullSlice)
	}
}
