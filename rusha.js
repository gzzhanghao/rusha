(function () {
    if (/*
 * Rusha, a JavaScript implementation of the Secure Hash Algorithm, SHA-1,
 * as defined in FIPS PUB 180-1, tuned for high performance with large inputs.
 * (http://github.com/srijs/rusha)
 *
 * Inspired by Paul Johnstons implementation (http://pajhome.org.uk/crypt/md5).
 *
 * Copyright (c) 2013 Sam Rijs (http://awesam.de).
 * Released under the terms of the MIT license as follows:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
        // If we'e running in Node.JS, export a module.
        typeof module !== 'undefined') {
        module.exports = Rusha;
    } else if (// If we're running in a DOM context, export
        // the Rusha object to toplevel.
        typeof window !== 'undefined') {
        window.Rusha = Rusha;
    } else if (typeof self !== 'undefined') {
        self.Rusha = Rusha;
    }
    var // Calculate the length of buffer that the sha1 routine uses
    // including the padding.
    padlen = function (len) {
        for (len += 9; len % 64 > 0; len += 1);
        return len;
    };
    var padZeroes = function (bin, len) {
        var h8 = new Uint8Array(bin.buffer);
        for (var i = len % 4; i < 4; i++)
            h8[len + i] = 0;
        for (var i = (len >> 2) + 1; i < bin.length; i++)
            bin[i] = 0;
    };
    var padData = function (bin, chunkLen, msgLen) {
        bin[chunkLen >> 2] |= 128 << 24 - (chunkLen % 4 << 3);
        bin[((chunkLen >> 2) + 2 & ~15) + 14] = msgLen >> 29;
        bin[((chunkLen >> 2) + 2 & ~15) + 15] = msgLen << 3;
    };
    var // Convert an ArrayBuffer into its hexadecimal string representation.
    hex = function (arrayBuffer) {
        var i, x, hex_tab = '0123456789abcdef', res = '', binarray = new Uint8Array(arrayBuffer);
        for (i = 0; i < binarray.length; i++) {
            x = binarray[i];
            res += hex_tab.charAt(x >> 4 & 15) + hex_tab.charAt(x >> 0 & 15);
        }
        return res;
    };
    var ceilHeapSize = function (v) {
        // The asm.js spec says:
        // The heap object's byteLength must be either
        // 2^n for n in [12, 24) or 2^24 * n for n ≥ 1.
        // Also, byteLengths smaller than 2^16 are deprecated.
        var p;
        if (// If v is smaller than 2^16, the smallest possible solution
            // is 2^16.
            v <= 65536)
            return 65536;
        if (// If v < 2^24, we round up to 2^n,
            // otherwise we round up to 2^24 * n.
            v < 16777216) {
            for (p = 65536; p < v; p = p << 1);
        } else {
            for (p = 16777216; p < v; p += 16777216);
        }
        return p;
    };
    var getRawDigest = function (heap, padMaxChunkLen) {
        var io = new Int32Array(heap, padMaxChunkLen + 320, 5);
        var out = new Int32Array(5);
        var arr = new DataView(out.buffer);
        arr.setInt32(0, io[0], false);
        arr.setInt32(4, io[1], false);
        arr.setInt32(8, io[2], false);
        arr.setInt32(12, io[3], false);
        arr.setInt32(16, io[4], false);
        return out;
    };
    function Rusha(chunkSize) {
        'use strict';
        // Private object structure.
        var self$2 = {};
        chunkSize = chunkSize || 64 * 1024;
        if (chunkSize % 64 > 0) {
            throw new Error('Chunk size must be a multiple of 128 bit');
        }
        self$2.offset = 0;
        self$2.maxChunkLen = chunkSize;
        self$2.padMaxChunkLen = padlen(chunkSize);
        // The size of the heap is the sum of:
        // 1. The padded input message size
        // 2. The extended space the algorithm needs (320 byte)
        // 3. The 160 bit state the algoritm uses
        self$2.heap = new ArrayBuffer(ceilHeapSize(self$2.padMaxChunkLen + 320 + 20));
        self$2.h32 = new Int32Array(self$2.heap);
        self$2.h8 = new Int8Array(self$2.heap);
        self$2.core = new Rusha._core({ Int32Array: Int32Array }, {}, self$2.heap);
        initState();
        function initState() {
            self$2.offset = 0;
            var io = new Int32Array(self$2.heap, self$2.padMaxChunkLen + 320, 5);
            io[0] = 1732584193;
            io[1] = -271733879;
            io[2] = -1732584194;
            io[3] = 271733878;
            io[4] = -1009589776;
        }
        function convBuf(buf, start, len, offset) {
            var om = offset % 4;
            var lm = (len + om) % 4;
            var j = len - lm;
            switch (om) {
            case 0:
                self$2.h8[offset] = buf[start + 3];
            case 1:
                self$2.h8[offset + 1 - (om << 1) | 0] = buf[start + 2];
            case 2:
                self$2.h8[offset + 2 - (om << 1) | 0] = buf[start + 1];
            case 3:
                self$2.h8[offset + 3 - (om << 1) | 0] = buf[start];
            }
            if (len < lm + om) {
                return;
            }
            for (var i = 4 - om; i < j; i = i + 4 | 0) {
                self$2.h32[offset + i >> 2 | 0] = buf[start + i] << 24 | buf[start + i + 1] << 16 | buf[start + i + 2] << 8 | buf[start + i + 3];
            }
            switch (lm) {
            case 3:
                self$2.h8[offset + j + 1 | 0] = buf[start + j + 2];
            case 2:
                self$2.h8[offset + j + 2 | 0] = buf[start + j + 1];
            case 1:
                self$2.h8[offset + j + 3 | 0] = buf[start + j];
            }
        }
        ;
        var // Calculate the hash digest as an array of 5 32bit integers.
        rawDigest = this.rawDigest = function (msg) {
            var msgLen = msg.byteLength;
            initState();
            msg = new Uint8Array(msg);
            var chunkLen = self$2.maxChunkLen;
            var chunkOffset = 0;
            for (; chunkOffset + chunkLen < msgLen; chunkOffset += chunkLen) {
                convBuf(msg, chunkOffset, chunkLen, 0);
                self$2.core.hash(chunkLen, self$2.padMaxChunkLen);
            }
            chunkLen = msgLen - chunkOffset;
            var padChunkLen = padlen(chunkLen);
            var view = new Int32Array(self$2.heap, 0, padChunkLen >> 2);
            convBuf(msg, chunkOffset, chunkLen, 0);
            padZeroes(view, chunkLen);
            padData(view, chunkLen, msgLen);
            self$2.core.hash(padChunkLen, self$2.padMaxChunkLen);
            return getRawDigest(self$2.heap, self$2.padMaxChunkLen);
        };
        // The digest and digestFrom* interface returns the hash digest
        // as a hex string.
        this.digest = function (msg) {
            return hex(rawDigest(msg).buffer);
        };
        var reset = this.reset = function () {
            initState();
        };
        this.update = function (chunk) {
            var chunkOffset = 0;
            var chunkLen = chunk.byteLength;
            var turnOffset = self$2.offset % self$2.maxChunkLen;
            self$2.offset += chunkLen;
            while (chunkOffset < chunkLen) {
                var inputLen = Math.min(chunkLen - chunkOffset, self$2.maxChunkLen - turnOffset);
                convBuf(chunk, chunkOffset, inputLen, turnOffset);
                turnOffset += inputLen;
                chunkOffset += inputLen;
                if (turnOffset === self$2.maxChunkLen) {
                    self$2.core.hash(self$2.maxChunkLen, self$2.padMaxChunkLen);
                    turnOffset = 0;
                }
            }
        };
        var rawFinalize = this.rawFinalize = function () {
            var msgLen = self$2.offset;
            var chunkLen = msgLen % self$2.maxChunkLen;
            var padChunkLen = padlen(chunkLen);
            var view = new Int32Array(self$2.heap, 0, padChunkLen >> 2);
            padZeroes(view, chunkLen);
            padData(view, chunkLen, msgLen);
            self$2.core.hash(padChunkLen, self$2.padMaxChunkLen);
            var result = getRawDigest(self$2.heap, self$2.padMaxChunkLen);
            initState();
            return result;
        };
        this.finalize = function () {
            return hex(rawFinalize().buffer);
        };
        this.getState = function () {
            return {
                offset: self$2.offset,
                maxChunkLen: self$2.maxChunkLen,
                padMaxChunkLen: self$2.padMaxChunkLen,
                heap: self$2.heap
            };
        };
        this.setState = function (state) {
            self$2.offset = state.offset;
            self$2.maxChunkLen = state.maxChunkLen;
            self$2.padMaxChunkLen = state.padMaxChunkLen;
            self$2.heap = state.heap;
            self$2.h32 = new Int32Array(self$2.heap);
            self$2.h8 = new Int8Array(self$2.heap);
            self$2.core = new Rusha._core({ Int32Array: Int32Array }, {}, self$2.heap);
        };
    }
    ;
    // The low-level RushCore module provides the heart of Rusha,
    // a high-speed sha1 implementation working on an Int32Array heap.
    // At first glance, the implementation seems complicated, however
    // with the SHA1 spec at hand, it is obvious this almost a textbook
    // implementation that has a few functions hand-inlined and a few loops
    // hand-unrolled.
    Rusha._core = function RushaCore(stdlib, foreign, heap) {
        'use asm';
        var H = new stdlib.Int32Array(heap);
        function hash(k, x) {
            // k in bytes
            k = k | 0;
            x = x | 0;
            var i = 0, j = 0, y0 = 0, z0 = 0, y1 = 0, z1 = 0, y2 = 0, z2 = 0, y3 = 0, z3 = 0, y4 = 0, z4 = 0, t0 = 0, t1 = 0;
            y0 = H[x + 320 >> 2] | 0;
            y1 = H[x + 324 >> 2] | 0;
            y2 = H[x + 328 >> 2] | 0;
            y3 = H[x + 332 >> 2] | 0;
            y4 = H[x + 336 >> 2] | 0;
            for (i = 0; (i | 0) < (k | 0); i = i + 64 | 0) {
                z0 = y0;
                z1 = y1;
                z2 = y2;
                z3 = y3;
                z4 = y4;
                for (j = 0; (j | 0) < 64; j = j + 4 | 0) {
                    t1 = H[i + j >> 2] | 0;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | ~y1 & y3) | 0) + ((t1 + y4 | 0) + 1518500249 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[k + j >> 2] = t1;
                }
                for (j = k + 64 | 0; (j | 0) < (k + 80 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | ~y1 & y3) | 0) + ((t1 + y4 | 0) + 1518500249 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 80 | 0; (j | 0) < (k + 160 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 ^ y2 ^ y3) | 0) + ((t1 + y4 | 0) + 1859775393 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 160 | 0; (j | 0) < (k + 240 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 & y2 | y1 & y3 | y2 & y3) | 0) + ((t1 + y4 | 0) - 1894007588 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                for (j = k + 240 | 0; (j | 0) < (k + 320 | 0); j = j + 4 | 0) {
                    t1 = (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) << 1 | (H[j - 12 >> 2] ^ H[j - 32 >> 2] ^ H[j - 56 >> 2] ^ H[j - 64 >> 2]) >>> 31;
                    t0 = ((y0 << 5 | y0 >>> 27) + (y1 ^ y2 ^ y3) | 0) + ((t1 + y4 | 0) - 899497514 | 0) | 0;
                    y4 = y3;
                    y3 = y2;
                    y2 = y1 << 30 | y1 >>> 2;
                    y1 = y0;
                    y0 = t0;
                    H[j >> 2] = t1;
                }
                y0 = y0 + z0 | 0;
                y1 = y1 + z1 | 0;
                y2 = y2 + z2 | 0;
                y3 = y3 + z3 | 0;
                y4 = y4 + z4 | 0;
            }
            H[x + 320 >> 2] = y0;
            H[x + 324 >> 2] = y1;
            H[x + 328 >> 2] = y2;
            H[x + 332 >> 2] = y3;
            H[x + 336 >> 2] = y4;
        }
        return { hash: hash };
    };
}());