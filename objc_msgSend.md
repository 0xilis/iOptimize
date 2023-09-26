# objc_msgSend writeup

todo, wip, barely covers anything at all

(post-iOptimize patch, which saves one mov instruction when it needs to load from cache / call objc_msgSend_uncached)

```asm
cmp x0, #0x0 
b.le loc_
```
Compares x0 / self to 0. Handles cases when objc_msgSend is called with 0, but also keep in mind that if self is a tagged pointer it may be negative.
Assuming it's not negative:

```asm
ldr        x13, [x0]
and        x15, x13, #0x7ffffffffffff8
```

Afterwards x15 should contain self's class pointer

Then
```asm
ldr        x10, [x15, #0x10]
lsr        x11, x10, #0x30
and        x10, x10, #0xffffffffffff
and        w12, w1, w11
add        x13, x10, x12, lsl #4
```

first instruction loads x15+16 aka where the cache is in the class into the x10 register

x10 should now be mask|buckets (upper 16 bits are mask and lower 32 bits are buckets)

it then saves mask into x11 and buckets by itself into x10

w12 is _cmd & mask
