"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    // The checks above watch RSS, which the OS may not grow for a lazily committed
    // allocation. These exploit-style checks inspect every Buffer.alloc request
    // instead: anything larger than the real entry data could need is refused and
    // recorded, so an allocation sized from the declared size fails fast and
    // deterministically on every platform.
    describe("allocation is bounded by the real entry data", () => {
        const LIMIT = 16 * 1024 * 1024;
        const content = Buffer.from("adm-zip ".repeat(512));
        const originalAlloc = Buffer.alloc;
        let oversized;

        beforeEach(() => {
            oversized = [];
            Buffer.alloc = function (size) {
                if (size > LIMIT) {
                    oversized.push(size);
                    throw new RangeError("refused Buffer.alloc(" + size + ") sized from the declared entry size");
                }
                return originalAlloc.apply(Buffer, arguments);
            };
        });

        afterEach(() => {
            Buffer.alloc = originalAlloc;
        });

        // a crafted entry that declares DECLARED uncompressed bytes but carries
        // `content` with a valid crc, so only the declared size is a lie
        function sizeBomb(method) {
            const payload = method === Utils.Constants.DEFLATED ? zlib.deflateRawSync(content) : content;
            const buf = craftBomb(DECLARED, method, payload);
            const crc = Utils.crc32(content);
            buf.writeUInt32LE(crc, Utils.Constants.LOCCRC);
            buf.writeUInt32LE(crc, Utils.Constants.LOCHDR + 1 + payload.length + Utils.Constants.CENCRC);
            return new Zip(buf);
        }

        [
            ["STORED", Utils.Constants.STORED],
            ["DEFLATED", Utils.Constants.DEFLATED]
        ].forEach(([label, method]) => {
            it(`getData() of a ${label} entry allocates from the real data, not the declared size`, () => {
                const entry = sizeBomb(method).getEntries()[0];
                expect(entry.header.size).to.equal(DECLARED);

                let data, error;
                try {
                    data = entry.getData();
                } catch (e) {
                    error = e;
                }
                expect(oversized, "Buffer.alloc requests sized from the declared size").to.eql([]);
                expect(error).to.equal(undefined);
                expect(data.equals(content)).to.equal(true);
            });

            it(`readAsText() and test() of a ${label} entry allocate from the real data, not the declared size`, () => {
                const zip = sizeBomb(method);

                let text, tested, error;
                try {
                    text = zip.readAsText("a");
                    tested = zip.test();
                } catch (e) {
                    error = e;
                }
                expect(oversized, "Buffer.alloc requests sized from the declared size").to.eql([]);
                expect(error).to.equal(undefined);
                expect(text).to.equal(content.toString("utf8"));
                expect(tested).to.equal(true);
            });

            it(`getDataAsync() of a ${label} entry allocates from the real data, not the declared size`, (done) => {
                const entry = sizeBomb(method).getEntries()[0];

                let error;
                try {
                    entry.getDataAsync(function (data, err) {
                        try {
                            expect(oversized, "Buffer.alloc requests sized from the declared size").to.eql([]);
                            expect(err).to.equal(undefined);
                            expect(data.equals(content)).to.equal(true);
                            done();
                        } catch (e) {
                            done(e);
                        }
                    });
                } catch (e) {
                    error = e;
                }
                if (error) {
                    expect(oversized, "Buffer.alloc requests sized from the declared size").to.eql([]);
                    done(error);
                }
            });
        });
    });
});
