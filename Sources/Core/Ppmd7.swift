import Foundation

// PPMd variant H (Dmitry Shkarin's PPMd, order up to 64), used by RAR 3/4, 7z and ZIP.
// Written from the published description of the model. The memory allocator is reproduced unit for unit because the
// moment the model runs out of memory (and restarts) is part of the format: encoder and decoder must agree on it.

protocol PpmdByteInput: AnyObject {
    func nextByte() throws -> Int
}

extension RBits: PpmdByteInput {
    func nextByte() throws -> Int { try take(8) }
}

final class Ppmd7 {
    var input: PpmdByteInput?
    private(set) var ready = false
    private let rarMode: Bool

    private static let maxFreq = 124
    private static let unitSize = 12
    private static let numIndexes = 38
    private static let binScale = 1 << 14
    private static let periodBits = 7
    private static let intBits = 7
    private static let top: UInt32 = 1 << 24
    private static let bot: UInt32 = 1 << 15
    private static let initBinEsc = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051]
    private static let expEscape = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2]

    // static tables
    private var indx2Units = [Int](repeating: 0, count: 38)
    private var units2Indx = [Int](repeating: 0, count: 128)
    private var ns2Indx = [Int](repeating: 0, count: 256)
    private var ns2BSIndx = [Int](repeating: 0, count: 256)
    private var hb2Flag = [Int](repeating: 0, count: 256)

    // memory arena; "references" are byte offsets into it and 0 means null
    private var mem: UnsafeMutablePointer<UInt8>?
    private var size = 0
    private var alignOffset = 0

    private var minContext = 0, maxContext = 0, foundState = 0
    private var orderFall = 0, initEsc = 0, prevSuccess = 0, maxOrder = 0, hiBitsFlag = 0
    private var runLength = 0, initRL = 0
    private var glueCount = 0
    private var text = 0, unitsStart = 0, loUnit = 0, hiUnit = 0
    private var freeList = [Int](repeating: 0, count: 38)
    private var seeSumm = [Int](repeating: 0, count: 401)       // 25 × 16, plus the dummy at 400
    private var seeShift = [Int](repeating: 0, count: 401)
    private var seeCount = [Int](repeating: 0, count: 401)
    private var binSumm = [Int](repeating: 0, count: 128 * 64)
    private var charMask = [UInt8](repeating: 0xff, count: 256)
    private var ps = [Int](repeating: 0, count: 256)

    private var range: UInt32 = 0, code: UInt32 = 0, low: UInt32 = 0

    init(rar: Bool = true) {
        rarMode = rar
        var k = 0
        for i in 0..<Ppmd7.numIndexes {
            var step = i >= 12 ? 4 : (i >> 2) + 1
            repeat { units2Indx[k] = i; k += 1; step -= 1 } while step > 0
            indx2Units[i] = k
        }
        ns2BSIndx[0] = 0; ns2BSIndx[1] = 2
        for i in 2..<11 { ns2BSIndx[i] = 4 }
        for i in 11..<256 { ns2BSIndx[i] = 6 }
        for i in 0..<3 { ns2Indx[i] = i }
        var m = 3, kk = 1
        for i in 3..<256 {
            ns2Indx[i] = m
            kk -= 1
            if kk == 0 { m += 1; kk = m - 2 }
        }
        for i in 0x40..<0x100 { hb2Flag[i] = 8 }
    }

    deinit { if let m = mem { free(m) } }

    // MARK: raw memory

    @inline(__always) private func u8(_ o: Int) -> Int { Int(mem![o]) }
    @inline(__always) private func w8(_ o: Int, _ v: Int) { mem![o] = UInt8(truncatingIfNeeded: v) }
    @inline(__always) private func u16(_ o: Int) -> Int { Int(UnsafeRawPointer(mem! + o).load(as: UInt16.self)) }
    @inline(__always) private func w16(_ o: Int, _ v: Int) { UnsafeMutableRawPointer(mem! + o).storeBytes(of: UInt16(truncatingIfNeeded: v), as: UInt16.self) }
    @inline(__always) private func u32(_ o: Int) -> Int { Int(UnsafeRawPointer(mem! + o).load(as: UInt32.self)) }
    @inline(__always) private func w32(_ o: Int, _ v: Int) { UnsafeMutableRawPointer(mem! + o).storeBytes(of: UInt32(truncatingIfNeeded: v), as: UInt32.self) }

    // context: NumStats u16 @0, SummFreq u16 @2, Stats u32 @4, Suffix u32 @8; a lone state lives at @2
    @inline(__always) private func numStats(_ c: Int) -> Int { u16(c) }
    @inline(__always) private func summFreq(_ c: Int) -> Int { u16(c + 2) }
    @inline(__always) private func stats(_ c: Int) -> Int { u32(c + 4) }
    @inline(__always) private func suffix(_ c: Int) -> Int { u32(c + 8) }
    @inline(__always) private func oneState(_ c: Int) -> Int { c + 2 }
    // state: Symbol @0, Freq @1, Successor (two u16) @2
    @inline(__always) private func sym(_ s: Int) -> Int { u8(s) }
    @inline(__always) private func freq(_ s: Int) -> Int { u8(s + 1) }
    @inline(__always) private func succ(_ s: Int) -> Int { u16(s + 2) | u16(s + 4) << 16 }
    @inline(__always) private func setSucc(_ s: Int, _ v: Int) { w16(s + 2, v & 0xffff); w16(s + 4, v >> 16) }
    @inline(__always) private func copyState(_ dst: Int, _ src: Int) {
        for i in 0..<6 { mem![dst + i] = mem![src + i] }
    }
    @inline(__always) private func swapStates(_ a: Int, _ b: Int) {
        for i in 0..<6 { let t = mem![a + i]; mem![a + i] = mem![b + i]; mem![b + i] = t }
    }

    // MARK: allocator

    @inline(__always) private func i2u(_ i: Int) -> Int { indx2Units[i] }
    @inline(__always) private func u2i(_ nu: Int) -> Int { units2Indx[nu - 1] }
    @inline(__always) private func u2b(_ nu: Int) -> Int { nu * 12 }

    private func insertNode(_ node: Int, _ indx: Int) {
        w32(node, freeList[indx])
        freeList[indx] = node
    }

    private func removeNode(_ indx: Int) -> Int {
        let node = freeList[indx]
        freeList[indx] = u32(node)
        return node
    }

    private func splitBlock(_ ptr: Int, _ oldIndx: Int, _ newIndx: Int) {
        let nu = i2u(oldIndx) - i2u(newIndx)
        let p = ptr + u2b(i2u(newIndx))
        var i = u2i(nu)
        if i2u(i) != nu {
            i -= 1
            let k = i2u(i)
            insertNode(p + u2b(k), nu - k - 1)
        }
        insertNode(p, i)
    }

    // free-block node: Stamp u16 @0, NU u16 @2, Next u32 @4, Prev u32 @8
    private func glueFreeBlocks() {
        let head = alignOffset + size
        var n = head
        glueCount = 255
        for i in 0..<Ppmd7.numIndexes {
            let nu = i2u(i)
            var next = freeList[i]
            freeList[i] = 0
            while next != 0 {
                let node = next
                w32(node + 4, n)                  // node.Next = n
                w32(n + 8, next)                  // n.Prev = next
                n = next
                next = u32(node)
                w16(node, 0)                      // Stamp
                w16(node + 2, nu)                 // NU
            }
        }
        w16(head, 1)
        w32(head + 4, n)
        w32(n + 8, head)
        if loUnit != hiUnit { w16(loUnit, 1) }

        while n != head {
            let node = n
            var nu = u16(node + 2)
            while true {
                let node2 = node + nu * 12
                nu += u16(node2 + 2)
                if u16(node2) != 0 || nu >= 0x10000 { break }
                w32(u32(node2 + 8) + 4, u32(node2 + 4))      // node2.Prev.Next = node2.Next
                w32(u32(node2 + 4) + 8, u32(node2 + 8))      // node2.Next.Prev = node2.Prev
                w16(node + 2, nu)
            }
            n = u32(node + 4)
        }

        n = u32(head + 4)
        while n != head {
            var node = n
            let next = u32(node + 4)
            var nu = u16(node + 2)
            while nu > 128 {
                insertNode(node, Ppmd7.numIndexes - 1)
                nu -= 128; node += 128 * 12
            }
            var i = u2i(nu)
            if i2u(i) != nu {
                i -= 1
                let k = i2u(i)
                insertNode(node + k * 12, nu - k - 1)
            }
            insertNode(node, i)
            n = next
        }
    }

    private func allocUnitsRare(_ indx: Int) -> Int {
        if glueCount == 0 {
            glueFreeBlocks()
            if freeList[indx] != 0 { return removeNode(indx) }
        }
        var i = indx
        repeat {
            i += 1
            if i == Ppmd7.numIndexes {
                let numBytes = u2b(i2u(indx))
                glueCount -= 1
                if unitsStart - text > numBytes { unitsStart -= numBytes; return unitsStart }
                return 0
            }
        } while freeList[i] == 0
        let r = removeNode(i)
        splitBlock(r, i, indx)
        return r
    }

    private func allocUnits(_ indx: Int) -> Int {
        if freeList[indx] != 0 { return removeNode(indx) }
        let numBytes = u2b(i2u(indx))
        if numBytes <= hiUnit - loUnit {
            let r = loUnit
            loUnit += numBytes
            return r
        }
        return allocUnitsRare(indx)
    }

    private func shrinkUnits(_ oldPtr: Int, _ oldNU: Int, _ newNU: Int) -> Int {
        let i0 = u2i(oldNU), i1 = u2i(newNU)
        if i0 == i1 { return oldPtr }
        if freeList[i1] != 0 {
            let ptr = removeNode(i1)
            memcpy(mem! + ptr, mem! + oldPtr, newNU * 12)
            insertNode(oldPtr, i0)
            return ptr
        }
        splitBlock(oldPtr, i0, i1)
        return oldPtr
    }

    // MARK: model

    /// Allocates the model memory (`memory` bytes) and starts a fresh model of the given order.
    func start(order: Int, memory: Int) throws {
        guard memory >= 2048, memory <= 0xFFFF_FFFF - 12 * 3, order >= 2, order <= 64 else { throw AXError.corrupt("bad PPMd parameters") }
        if memory != size || mem == nil {
            if let m = mem { free(m); mem = nil }
            alignOffset = 4 - (memory & 3)
            guard let raw = calloc(alignOffset + memory + Ppmd7.unitSize, 1) else { throw AXError.io("Not enough memory for PPMd.") }
            mem = raw.assumingMemoryBound(to: UInt8.self)
            size = memory
        }
        maxOrder = order
        restartModel()
        seeShift[400] = Ppmd7.periodBits; seeSumm[400] = 0; seeCount[400] = 64
        ready = true
    }

    private func restartModel() {
        for i in 0..<freeList.count { freeList[i] = 0 }
        text = alignOffset
        hiUnit = text + size
        loUnit = hiUnit - size / 8 / 12 * 7 * 12
        unitsStart = loUnit
        glueCount = 0

        orderFall = maxOrder
        initRL = -(maxOrder < 12 ? maxOrder : 12) - 1
        runLength = initRL
        prevSuccess = 0

        hiUnit -= 12
        minContext = hiUnit; maxContext = hiUnit
        w32(minContext + 8, 0)
        w16(minContext, 256)
        w16(minContext + 2, 257)
        foundState = loUnit
        w32(minContext + 4, foundState)
        loUnit += u2b(256 / 2)
        for i in 0..<256 {
            let s = foundState + i * 6
            w8(s, i); w8(s + 1, 1); setSucc(s, 0)
        }
        for i in 0..<128 {
            for k in 0..<8 {
                let val = Ppmd7.binScale - Ppmd7.initBinEsc[k] / (i + 2)
                var m = 0
                while m < 64 { binSumm[i * 64 + k + m] = val; m += 8 }
            }
        }
        for i in 0..<25 {
            for k in 0..<16 {
                seeShift[i * 16 + k] = Ppmd7.periodBits - 4
                seeSumm[i * 16 + k] = (5 * i + 10) << (Ppmd7.periodBits - 4)
                seeCount[i * 16 + k] = 4
            }
        }
    }

    private func createSuccessors(skip: Bool) -> Int {
        var c = minContext
        let upBranch = succ(foundState)
        var numPs = 0
        if !skip { ps[numPs] = foundState; numPs += 1 }
        let fsSym = sym(foundState)
        while suffix(c) != 0 {
            c = suffix(c)
            var s: Int
            if numStats(c) != 1 {
                s = stats(c)
                while sym(s) != fsSym { s += 6 }
            } else { s = oneState(c) }
            let successor = succ(s)
            if successor != upBranch {
                c = successor
                if numPs == 0 { return c }
                break
            }
            ps[numPs] = s; numPs += 1
        }
        let upSym = u8(upBranch)
        let upSucc = upBranch + 1
        var upFreq: Int
        if numStats(c) == 1 { upFreq = freq(oneState(c)) }
        else {
            var s = stats(c)
            while sym(s) != upSym { s += 6 }
            let cf = freq(s) - 1
            let s0 = summFreq(c) - numStats(c) - cf
            upFreq = 1 + (2 * cf <= s0 ? (5 * cf > s0 ? 1 : 0) : (2 * cf + 3 * s0 - 1) / (2 * s0))
        }
        repeat {
            var c1: Int
            if hiUnit != loUnit { hiUnit -= 12; c1 = hiUnit }
            else if freeList[0] != 0 { c1 = removeNode(0) }
            else {
                c1 = allocUnitsRare(0)
                if c1 == 0 { return 0 }
            }
            w16(c1, 1)
            let os = oneState(c1)
            w8(os, upSym); w8(os + 1, upFreq); setSucc(os, upSucc)
            w32(c1 + 8, c)
            numPs -= 1
            setSucc(ps[numPs], c1)
            c = c1
        } while numPs != 0
        return c
    }

    private func updateModel() {
        let fs = foundState
        let fsSym = sym(fs), fsFreq = freq(fs)
        var fSuccessor = succ(fs)

        if fsFreq < Ppmd7.maxFreq / 4 && suffix(minContext) != 0 {
            let c = suffix(minContext)
            if numStats(c) == 1 {
                let s = oneState(c)
                if freq(s) < 32 { w8(s + 1, freq(s) + 1) }
            } else {
                var s = stats(c)
                if sym(s) != fsSym {
                    repeat { s += 6 } while sym(s) != fsSym
                    if freq(s) >= freq(s - 6) { swapStates(s, s - 6); s -= 6 }
                }
                if freq(s) < Ppmd7.maxFreq - 9 {
                    w8(s + 1, freq(s) + 2)
                    w16(c + 2, summFreq(c) + 2)
                }
            }
        }

        if orderFall == 0 {
            minContext = createSuccessors(skip: true)
            maxContext = minContext
            if minContext == 0 { restartModel(); return }
            setSucc(foundState, minContext)
            return
        }

        w8(text, fsSym); text += 1
        var successor = text
        if text >= unitsStart { restartModel(); return }

        if fSuccessor != 0 {
            if fSuccessor <= successor {
                let cs = createSuccessors(skip: false)
                if cs == 0 { restartModel(); return }
                fSuccessor = cs
            }
            orderFall -= 1
            if orderFall == 0 {
                successor = fSuccessor
                if maxContext != minContext { text -= 1 }
            }
        } else {
            setSucc(foundState, successor)
            fSuccessor = minContext
        }

        let ns = numStats(minContext)
        let s0 = summFreq(minContext) - ns - (freq(foundState) - 1)
        var c = maxContext
        while c != minContext {
            let ns1 = numStats(c)
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let oldNU = ns1 >> 1
                    let i = u2i(oldNU)
                    if i != u2i(oldNU + 1) {
                        let ptr = allocUnits(i + 1)
                        if ptr == 0 { restartModel(); return }
                        let oldPtr = stats(c)
                        memcpy(mem! + ptr, mem! + oldPtr, oldNU * 12)
                        insertNode(oldPtr, i)
                        w32(c + 4, ptr)
                    }
                }
                let sf = summFreq(c)
                w16(c + 2, sf + (2 * ns1 < ns ? 1 : 0) + 2 * ((4 * ns1 <= ns ? 1 : 0) & (sf <= 8 * ns1 ? 1 : 0)))
            } else {
                let s = allocUnits(0)
                if s == 0 { restartModel(); return }
                copyState(s, oneState(c))
                w32(c + 4, s)
                let f = freq(s)
                if f < Ppmd7.maxFreq / 4 - 1 { w8(s + 1, f << 1) } else { w8(s + 1, Ppmd7.maxFreq - 4) }
                w16(c + 2, freq(s) + initEsc + (ns > 3 ? 1 : 0))
            }
            var cf = 2 * freq(foundState) * (summFreq(c) + 6)
            let sf = s0 + summFreq(c)
            if cf < 6 * sf {
                cf = 1 + (cf > sf ? 1 : 0) + (cf >= 4 * sf ? 1 : 0)
                w16(c + 2, summFreq(c) + 3)
            } else {
                cf = 4 + (cf >= 9 * sf ? 1 : 0) + (cf >= 12 * sf ? 1 : 0) + (cf >= 15 * sf ? 1 : 0)
                w16(c + 2, summFreq(c) + cf)
            }
            let s = stats(c) + ns1 * 6
            setSucc(s, successor)
            w8(s, fsSym)
            w8(s + 1, cf)
            w16(c, ns1 + 1)
            c = suffix(c)
        }
        maxContext = fSuccessor
        minContext = fSuccessor
    }

    private func rescale() {
        let st = stats(minContext)
        var s = foundState
        if s != st {
            var tmp = [UInt8](repeating: 0, count: 6)
            for i in 0..<6 { tmp[i] = mem![s + i] }
            repeat { copyState(s, s - 6); s -= 6 } while s != st
            for i in 0..<6 { mem![s + i] = tmp[i] }
        }
        var escFreq = summFreq(minContext) - freq(s)
        w8(s + 1, freq(s) + 4)
        let adder = orderFall != 0 ? 1 : 0
        w8(s + 1, (freq(s) + adder) >> 1)
        var sumFreq = freq(s)

        var i = numStats(minContext) - 1
        repeat {
            s += 6
            escFreq -= freq(s)
            w8(s + 1, (freq(s) + adder) >> 1)
            sumFreq += freq(s)
            if freq(s) > freq(s - 6) {
                var s1 = s
                var tmp = [UInt8](repeating: 0, count: 6)
                for k in 0..<6 { tmp[k] = mem![s1 + k] }
                repeat { copyState(s1, s1 - 6); s1 -= 6 } while s1 != st && Int(tmp[1]) > freq(s1 - 6)
                for k in 0..<6 { mem![s1 + k] = tmp[k] }
            }
            i -= 1
        } while i != 0

        if freq(s) == 0 {
            let ns = numStats(minContext)
            i = 0
            repeat { i += 1; s -= 6 } while freq(s) == 0
            escFreq += i
            w16(minContext, numStats(minContext) - i)
            if numStats(minContext) == 1 {
                var tmp = [UInt8](repeating: 0, count: 6)
                for k in 0..<6 { tmp[k] = mem![st + k] }
                repeat {
                    tmp[1] = UInt8(Int(tmp[1]) - (Int(tmp[1]) >> 1))
                    escFreq >>= 1
                } while escFreq > 1
                insertNode(st, u2i((ns + 1) >> 1))
                foundState = oneState(minContext)
                for k in 0..<6 { mem![foundState + k] = tmp[k] }
                return
            }
            let n0 = (ns + 1) >> 1, n1 = (numStats(minContext) + 1) >> 1
            if n0 != n1 { w32(minContext + 4, shrinkUnits(st, n0, n1)) }
        }
        w16(minContext + 2, sumFreq + escFreq - (escFreq >> 1))
        foundState = stats(minContext)
    }

    private func makeEscFreq(_ numMasked: Int) -> (see: Int, esc: Int) {
        let ns = numStats(minContext)
        if ns != 256 {
            let nonMasked = ns - numMasked
            let see = ns2Indx[nonMasked - 1] * 16
                + (nonMasked < numStats(suffix(minContext)) - ns ? 1 : 0)
                + 2 * (summFreq(minContext) < 11 * ns ? 1 : 0)
                + 4 * (numMasked > nonMasked ? 1 : 0)
                + hiBitsFlag
            let r = seeSumm[see] >> seeShift[see]
            seeSumm[see] = (seeSumm[see] - r) & 0xffff
            return (see, r + (r == 0 ? 1 : 0))
        }
        return (400, 1)
    }

    private func nextContext() {
        let c = succ(foundState)
        if orderFall == 0 && c > text { minContext = c; maxContext = c } else { updateModel() }
    }

    private func update1() {
        var s = foundState
        w8(s + 1, freq(s) + 4)
        w16(minContext + 2, summFreq(minContext) + 4)
        if freq(s) > freq(s - 6) {
            swapStates(s, s - 6)
            s -= 6
            foundState = s
            if freq(s) > Ppmd7.maxFreq { rescale() }
        }
        nextContext()
    }

    private func update1_0() {
        prevSuccess = 2 * freq(foundState) > summFreq(minContext) ? 1 : 0
        runLength += prevSuccess
        w16(minContext + 2, summFreq(minContext) + 4)
        w8(foundState + 1, freq(foundState) + 4)
        if freq(foundState) > Ppmd7.maxFreq { rescale() }
        nextContext()
    }

    private func updateBin() {
        let f = freq(foundState)
        w8(foundState + 1, f + (f < 128 ? 1 : 0))
        prevSuccess = 1
        runLength += 1
        nextContext()
    }

    private func update2() {
        w16(minContext + 2, summFreq(minContext) + 4)
        w8(foundState + 1, freq(foundState) + 4)
        if freq(foundState) > Ppmd7.maxFreq { rescale() }
        runLength = initRL
        updateModel()
    }

    // MARK: range decoder

    private func nextByte() throws -> UInt32 {
        guard let i = input else { throw AXError.corrupt("PPMd without input") }
        return UInt32(try i.nextByte())
    }

    /// Reads the start of a PPMd stream (RAR: 4 bytes; 7z/ZIP: a zero byte then 4 bytes).
    func initRange() throws {
        code = 0; low = 0; range = 0xffff_ffff
        if !rarMode, try nextByte() != 0 { throw AXError.corrupt("bad PPMd stream") }
        for _ in 0..<4 { code = code << 8 | (try nextByte()) }
        if code == 0xffff_ffff { throw AXError.corrupt("bad PPMd stream") }
    }

    private func normalize() throws {
        if rarMode {
            while true {
                if (low ^ (low &+ range)) < Ppmd7.top { }
                else if range < Ppmd7.bot { range = (0 &- low) & (Ppmd7.bot - 1) }
                else { break }
                code = code << 8 | (try nextByte()); range <<= 8; low <<= 8
            }
        } else if range < Ppmd7.top {
            code = code << 8 | (try nextByte()); range <<= 8
            if range < Ppmd7.top { code = code << 8 | (try nextByte()); range <<= 8 }
        }
    }

    private func threshold(_ total: Int) throws -> Int {
        range /= UInt32(total)
        guard range != 0 else { throw AXError.corrupt("damaged PPMd data") }
        return Int((code &- low) / range)
    }

    private func decode(_ start: Int, _ sz: Int) throws {
        if rarMode { low = low &+ UInt32(start) &* range } else { code = code &- UInt32(start) &* range }
        range = range &* UInt32(sz)
        try normalize()
    }

    private func decodeBit(_ size0: Int, _ total: Int) throws -> Int {
        var bit: Int
        if rarMode {
            // the RAR coder scales the range once and keeps that scaled range for both outcomes
            range = range / UInt32(total)
            let bound = range &* UInt32(size0)
            if (code &- low) < bound { bit = 0; range = bound }
            else { bit = 1; low = low &+ bound; range = range &* UInt32(total - size0) }
        } else {
            let bound = (range / UInt32(total)) &* UInt32(size0)
            if code < bound { bit = 0; range = bound }
            else { bit = 1; code = code &- bound; range = range &- bound }
        }
        try normalize()
        return bit
    }

    // MARK: symbol decoding

    /// The next byte, or -1 if the data is damaged.
    func decodeChar() throws -> Int {
        guard ready else { return -1 }
        if numStats(minContext) != 1 {
            var s = stats(minContext)
            let sf = summFreq(minContext)
            let count = try threshold(sf)
            var hiCnt = freq(s)
            if count < hiCnt {
                try decode(0, hiCnt)
                foundState = s
                let symbol = sym(s)
                update1_0()
                return symbol
            }
            prevSuccess = 0
            var i = numStats(minContext) - 1
            repeat {
                s += 6
                hiCnt += freq(s)
                if hiCnt > count {
                    try decode(hiCnt - freq(s), freq(s))
                    foundState = s
                    let symbol = sym(s)
                    update1()
                    return symbol
                }
                i -= 1
            } while i != 0
            if count >= sf { return -1 }
            hiBitsFlag = hb2Flag[sym(foundState)]
            try decode(hiCnt, sf - hiCnt)
            for k in 0..<256 { charMask[k] = 0xff }
            charMask[sym(s)] = 0
            i = numStats(minContext) - 1
            repeat { s -= 6; charMask[sym(s)] = 0; i -= 1 } while i != 0
        } else {
            let os = oneState(minContext)
            hiBitsFlag = hb2Flag[sym(foundState)]
            let idx = (freq(os) - 1) * 64
                + prevSuccess
                + ns2BSIndx[numStats(suffix(minContext)) - 1]
                + hiBitsFlag
                + 2 * hb2Flag[sym(os)]
                + ((runLength >> 26) & 0x20)
            let prob = binSumm[idx]
            if try decodeBit(prob, Ppmd7.binScale) == 0 {
                binSumm[idx] = (prob + (1 << Ppmd7.intBits) - ((prob + (1 << (Ppmd7.periodBits - 2))) >> Ppmd7.periodBits)) & 0xffff
                foundState = os
                let symbol = sym(os)
                updateBin()
                return symbol
            }
            let np = (prob - ((prob + (1 << (Ppmd7.periodBits - 2))) >> Ppmd7.periodBits)) & 0xffff
            binSumm[idx] = np
            initEsc = Ppmd7.expEscape[np >> 10]
            for k in 0..<256 { charMask[k] = 0xff }
            charMask[sym(os)] = 0
            prevSuccess = 0
        }
        while true {
            let numMasked = numStats(minContext)
            repeat {
                orderFall += 1
                let sfx = suffix(minContext)
                if sfx == 0 { return -1 }
                minContext = sfx
            } while numStats(minContext) == numMasked
            var hiCnt = 0
            var s = stats(minContext)
            var i = 0
            let num = numStats(minContext) - numMasked
            repeat {
                if charMask[sym(s)] != 0 { hiCnt += freq(s); ps[i] = s; i += 1 }
                s += 6
            } while i != num
            let (see, escFreq) = makeEscFreq(numMasked)
            let freqSum = escFreq + hiCnt
            let count = try threshold(freqSum)
            if count < hiCnt {
                var k = 0
                var acc = freq(ps[0])
                while acc <= count { k += 1; acc += freq(ps[k]) }
                let st = ps[k]
                try decode(acc - freq(st), freq(st))
                if seeShift[see] < Ppmd7.periodBits {
                    seeCount[see] = (seeCount[see] - 1) & 0xff
                    if seeCount[see] == 0 {
                        seeSumm[see] = (seeSumm[see] << 1) & 0xffff
                        seeCount[see] = (3 << seeShift[see]) & 0xff
                        seeShift[see] += 1
                    }
                }
                foundState = st
                let symbol = sym(st)
                update2()
                return symbol
            }
            if count >= freqSum { return -1 }
            try decode(hiCnt, freqSum - hiCnt)
            seeSumm[see] = (seeSumm[see] + freqSum) & 0xffff
            while i > 0 { i -= 1; charMask[sym(ps[i])] = 0 }
        }
    }
}
