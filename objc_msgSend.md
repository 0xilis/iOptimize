# objc_msgSend writeup

todo, wip, barely covers anything at all

if you want an actually good writeup of every instruction of objc_msgSend, check out https://www.mikeash.com/pyblog/friday-qa-2017-06-30-dissecting-objc_msgsend-on-arm64.html. It was a major help for me understanding how objc_msgSend functioned. It's written in 2017, but for the most part it's accurate to the "current" version, with some exceptions that I'll touch on.

Be aware this writeup is regarding objc_msgSend in iOS 15.2. Future versions may differ.

```asm
cmp x0, #0x0 
b.le LNilOrTagged
```
Compares x0 / self to 0. Handles cases when objc_msgSend is called with 0, but also keep in mind that if self is a tagged pointer it may be negative.

Assuming it's not negative and a normal pointer:

```asm
ldr x13, [x0]
and x16, x13, #0x7ffffffffffff8
; under this is LGetIsaDone
```

Afterwards x16 should contain self's class pointer.

If it's 0 / a tagged pointer however, we reach out to this instruction:

```asm
LNilOrTagged:
 b.eq LReturnZero
 GetTaggedClass
 b LGetIsaDone
```

If x0 is 0, it branches out to handle it.

```asm
LReturnZero:
 mov x1, #0x0
 movi d0, #0x0
 movi d1, #0x0
 movi d2, #0x0
 movi d3, #0x0
 ret
```
I should note: while this will not boost performance, this segment is equivalent to objc_msgNil. I've not tried this admittedly, but you *should* be able to replace `b.eq LReturnZero` with `b.eq __objc_msgNil`, which will result in the same speed, and allow you to remove these 6 instrutions from objc_msgSend. Once again though, this is really only a size benefit, not speed.

If the `b.eq` does not branch, then x0 is negative; it's a tagged pointer.

```asm
.macro GetTaggedClass
 and x10, x0, #0x7
 asr x11, x0, #0x37
 cmp x10, #0x7
 csel x12, x11, x10, eq
 adrp x10, _objc_debug_taggedpointer_classes@PAGE
 add x10, x10, _objc_debug_taggedpointer_classes@PAGEOFF
 ldr x16, [x10, x12, lsl #3]
```

The iOptimize patch saves an instruction here. Here's my patch:

```asm
.macro GetTaggedClass
 asr x11, x0, #0x37
 ands x10, x0, #0x7
 csel x12, x11, x10, eq
 adrp x10, _objc_debug_taggedpointer_classes@PAGE
 add x10, x10, _objc_debug_taggedpointer_classes@PAGEOFF
 ldr x16, [x10, x12, lsl #3]
```

Now, x16 should be the pointer to self's class.

Then
```asm
LGetIsaDone:
 mov x15, x16
 ldr x10, [x16, #0x10]
 lsr x11, x10, #0x30
 and x10, x10, #0xffffffffffff
 and w12, w1, w11
 add x13, x10, x12, lsl #4
```

first instruction loads x15+16 aka where the cache is in the class into the x10 register

x10 should now be mask|buckets (upper 16 bits are mask and lower 32 bits are buckets)

it then saves mask into x11 and buckets by itself into x10

w12 is _cmd & mask


finish later
