// ─────────────────────────────────────────────────────────────
//  ATLAS — Pure-JS MMDB Reader
//  No dependencies. Works directly on Uint8Array in the browser.
//  Supports GeoLite2-ASN and GeoLite2-Country (IPv6 tree, 28-bit).
// ─────────────────────────────────────────────────────────────

(function (global) {
    'use strict';

    const META_MARKER = new Uint8Array([0xAB, 0xCD, 0xEF, 0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D]);

    // ── Data type IDs ──────────────────────────────────────────
    const T_POINTER  = 1;
    const T_STRING   = 2;
    const T_DOUBLE   = 3;
    const T_BYTES    = 4;
    const T_UINT16   = 5;
    const T_UINT32   = 6;
    const T_MAP      = 7;
    const T_INT32    = 8;
    const T_UINT64   = 9;
    const T_UINT128  = 10;
    const T_ARRAY    = 11;
    const T_BOOL     = 14;
    const T_FLOAT    = 15;

    // ── IPv4-in-IPv6 mapped prefix (::ffff:0:0/96 is NOT what MaxMind uses)
    // GeoLite2 IPv6 trees encode IPv4 addresses starting at a special node.
    // We walk down the tree 96 times for IPv4 to reach the IPv4 subtree root.

    function findMetaMarker(buf) {
        const len = buf.length - META_MARKER.length;
        for (let i = len; i >= 0; i--) {
            let found = true;
            for (let j = 0; j < META_MARKER.length; j++) {
                if (buf[i + j] !== META_MARKER[j]) { found = false; break; }
            }
            if (found) return i + META_MARKER.length;
        }
        return -1;
    }

    // ── Decode a data record at `offset` in the data section ──
    function decodeData(buf, dataStart, offset) {
        const abs = dataStart + offset;
        return decodeValue(buf, dataStart, abs);
    }

    function decodeValue(buf, dataStart, pos) {
        let ctrlByte = buf[pos++];
        let type = (ctrlByte >> 5) & 0x7;

        // Extended type
        if (type === 0) {
            type = buf[pos++] + 7;
        }

        // Payload size
        let size = ctrlByte & 0x1F;
        if (type === T_POINTER) {
            // Pointer — special encoding
            const ptrSize = (size >> 3) & 0x3;
            const ptrVal  = size & 0x7;
            let pointer;
            if (ptrSize === 0) {
                pointer = (ptrVal << 8) | buf[pos++];
            } else if (ptrSize === 1) {
                pointer = (ptrVal << 16) | (buf[pos++] << 8) | buf[pos++];
                pointer += 2048;
            } else if (ptrSize === 2) {
                pointer = (ptrVal << 24) | (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++];
                pointer += 526336;
            } else {
                pointer = (buf[pos++] * 16777216) + (buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++];
            }
            const [val] = decodeValue(buf, dataStart, dataStart + pointer);
            return [val, pos];
        }

        if (size === 29) {
            size = buf[pos++] + 29;
        } else if (size === 30) {
            size = ((buf[pos++] << 8) | buf[pos++]) + 285;
        } else if (size === 31) {
            size = ((buf[pos++] << 16) | (buf[pos++] << 8) | buf[pos++]) + 65821;
        }

        switch (type) {
            case T_MAP: {
                const map = {};
                for (let i = 0; i < size; i++) {
                    let key, val;
                    [key, pos] = decodeValue(buf, dataStart, pos);
                    [val, pos] = decodeValue(buf, dataStart, pos);
                    map[key] = val;
                }
                return [map, pos];
            }
            case T_ARRAY: {
                const arr = [];
                for (let i = 0; i < size; i++) {
                    let val;
                    [val, pos] = decodeValue(buf, dataStart, pos);
                    arr.push(val);
                }
                return [arr, pos];
            }
            case T_STRING: {
                const bytes = buf.subarray(pos, pos + size);
                const str = new TextDecoder().decode(bytes);
                return [str, pos + size];
            }
            case T_BYTES: {
                return [buf.slice(pos, pos + size), pos + size];
            }
            case T_UINT16:
            case T_UINT32: {
                let val = 0;
                for (let i = 0; i < size; i++) val = (val * 256) + buf[pos++];
                return [val, pos];
            }
            case T_UINT64:
            case T_UINT128: {
                // Return as hex string — we don't need these as numbers
                let hex = '';
                for (let i = 0; i < size; i++) hex += buf[pos++].toString(16).padStart(2, '0');
                return [hex, pos];
            }
            case T_INT32: {
                let val = 0;
                for (let i = 0; i < size; i++) val = (val << 8) | buf[pos++];
                // Sign-extend
                if (size === 4 && (val & 0x80000000)) val = val - 0x100000000;
                return [val, pos];
            }
            case T_DOUBLE: {
                const view = new DataView(buf.buffer, buf.byteOffset + pos, 8);
                return [view.getFloat64(0, false), pos + 8];
            }
            case T_FLOAT: {
                const view = new DataView(buf.buffer, buf.byteOffset + pos, 4);
                return [view.getFloat32(0, false), pos + 4];
            }
            case T_BOOL: {
                return [size !== 0, pos];
            }
            default:
                return [null, pos + size];
        }
    }

    // ── Parse IP string into array of bits (MSB first) ────────
    function ipToBits(ip) {
        if (ip.includes(':')) {
            // IPv6
            return expandIPv6(ip);
        } else {
            // IPv4
            const parts = ip.split('.').map(Number);
            const bits = [];
            for (const p of parts) {
                for (let i = 7; i >= 0; i--) bits.push((p >> i) & 1);
            }
            return bits; // 32 bits
        }
    }

    function expandIPv6(ip) {
        // Handle :: expansion
        let halves = ip.split('::');
        let left = halves[0] ? halves[0].split(':') : [];
        let right = halves[1] ? halves[1].split(':') : [];
        const missing = 8 - left.length - right.length;
        const full = [...left, ...Array(missing).fill('0'), ...right];
        const bits = [];
        for (const group of full) {
            const val = parseInt(group || '0', 16);
            for (let i = 15; i >= 0; i--) bits.push((val >> i) & 1);
        }
        return bits; // 128 bits
    }

    // ── Read a tree node ──────────────────────────────────────
    function readNode(buf, nodeCount, recordSize, nodeNum) {
        // recordSize is the full node width in bits (e.g. 28 means 14+14, but stored as 28*2/8 bytes)
        const bytesPerNode = Math.ceil(recordSize * 2 / 8);
        const base = nodeNum * bytesPerNode;

        if (recordSize === 24) {
            const left  = (buf[base]     << 16) | (buf[base + 1] << 8) | buf[base + 2];
            const right = (buf[base + 3] << 16) | (buf[base + 4] << 8) | buf[base + 5];
            return [left, right];
        } else if (recordSize === 28) {
            // 7 bytes per node: left=28 bits, right=28 bits
            const b0 = buf[base], b1 = buf[base+1], b2 = buf[base+2], b3 = buf[base+3], b4 = buf[base+4], b5 = buf[base+5], b6 = buf[base+6];
            const left  = ((b3 & 0xF0) << 20) | (b0 << 16) | (b1 << 8) | b2;
            const right = ((b3 & 0x0F) << 24) | (b4 << 16) | (b5 << 8) | b6;
            return [left, right];
        } else if (recordSize === 32) {
            const left  = (buf[base]     << 24) | (buf[base+1] << 16) | (buf[base+2] << 8) | buf[base+3];
            const right = (buf[base+4]   << 24) | (buf[base+5] << 16) | (buf[base+6] << 8) | buf[base+7];
            return [left >>> 0, right >>> 0];
        }
        return [0, 0];
    }

    // ── Main Reader class ──────────────────────────────────────
    function MMDBReader(uint8array) {
        this._buf = uint8array;
        this._parse();
    }

    MMDBReader.prototype._parse = function () {
        const buf = this._buf;

        // Find metadata
        const metaOffset = findMetaMarker(buf);
        if (metaOffset < 0) throw new Error('MMDB: metadata marker not found');

        const [meta] = decodeValue(buf, metaOffset, metaOffset);
        this._meta = meta;

        this._nodeCount  = meta.node_count;
        this._recordSize = meta.record_size;
        this._ipVersion  = meta.ip_version;

        const bytesPerNode   = Math.ceil(this._recordSize * 2 / 8);
        this._treeSize       = this._nodeCount * bytesPerNode;
        this._dataStart      = this._treeSize + 16; // 16-byte data section separator

        // For IPv4 lookups in an IPv6 tree, find the IPv4 subtree root.
        // Walk down 96 zero bits from node 0.
        this._ipv4Start = 0;
        if (this._ipVersion === 6) {
            let node = 0;
            for (let i = 0; i < 96; i++) {
                const [left] = readNode(buf, this._nodeCount, this._recordSize, node);
                node = left;
                if (node >= this._nodeCount) break;
            }
            this._ipv4Start = node;
        }
    };

    MMDBReader.prototype.get = function (ip) {
        const buf        = this._buf;
        const nodeCount  = this._nodeCount;
        const recordSize = this._recordSize;
        const dataStart  = this._dataStart;

        let bits;
        let startNode;

        if (ip.includes(':')) {
            // IPv6
            bits = ipToBits(ip);
            startNode = 0;
        } else {
            // IPv4
            bits = ipToBits(ip);
            startNode = this._ipVersion === 6 ? this._ipv4Start : 0;
        }

        let node = startNode;
        for (const bit of bits) {
            if (node >= nodeCount) break;
            const [left, right] = readNode(buf, nodeCount, recordSize, node);
            node = bit === 0 ? left : right;
        }

        // nodeCount = no data; nodeCount+1..= error/empty
        if (node === nodeCount) return null;
        if (node < nodeCount)   return null; // didn't reach a leaf

        // Data record offset
        const recordOffset = node - nodeCount - 16;
        if (recordOffset < 0) return null;

        try {
            const [val] = decodeValue(buf, dataStart, dataStart + recordOffset);
            return val;
        } catch (e) {
            return null;
        }
    };

    global.MMDBReader = MMDBReader;

}(typeof window !== 'undefined' ? window : this));
