const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Utils = require("../../util");

// adm-zip only hands maxOutputLength to zlib's synchronous API on Node >= 15
const syncCapAvailable = (+process.versions.node.split(".")[0] || 0) >= 15;
const MAX_OUTPUT_EXCEEDED = "Decompressed data exceeds the declared uncompressed size";

// builds an archive with a single DEFLATE entry whose declared uncompressed size
// (local + central header) is chosen by the caller, as an attacker would do
function deflatedZip(name, content, declaredSize) {
    const fileName = Buffer.from(name);
    const data = zlib.deflateRawSync(content);
    const crc = Utils.crc32(content);

    const loc = Buffer.alloc(Utils.Constants.LOCHDR);
    loc.writeUInt32LE(Utils.Constants.LOCSIG, 0);
    loc.writeUInt16LE(20, Utils.Constants.LOCVER);
    loc.writeUInt16LE(Utils.Constants.DEFLATED, Utils.Constants.LOCHOW);
    loc.writeUInt32LE(crc, Utils.Constants.LOCCRC);
    loc.writeUInt32LE(data.length, Utils.Constants.LOCSIZ);
    loc.writeUInt32LE(declaredSize, Utils.Constants.LOCLEN);
    loc.writeUInt16LE(fileName.length, Utils.Constants.LOCNAM);

    const cen = Buffer.alloc(Utils.Constants.CENHDR);
    cen.writeUInt32LE(Utils.Constants.CENSIG, 0);
    cen.writeUInt16LE(20, Utils.Constants.CENVEM);
    cen.writeUInt16LE(20, Utils.Constants.CENVER);
    cen.writeUInt16LE(Utils.Constants.DEFLATED, Utils.Constants.CENHOW);
    cen.writeUInt32LE(crc, Utils.Constants.CENCRC);
    cen.writeUInt32LE(data.length, Utils.Constants.CENSIZ);
    cen.writeUInt32LE(declaredSize, Utils.Constants.CENLEN);
    cen.writeUInt16LE(fileName.length, Utils.Constants.CENNAM);
    cen.writeUInt32LE(0, Utils.Constants.CENOFF);

    const end = Buffer.alloc(Utils.Constants.ENDHDR);
    end.writeUInt32LE(Utils.Constants.ENDSIG, 0);
    end.writeUInt16LE(1, Utils.Constants.ENDSUB);
    end.writeUInt16LE(1, Utils.Constants.ENDTOT);
    end.writeUInt32LE(cen.length + fileName.length, Utils.Constants.ENDSIZ);
    end.writeUInt32LE(loc.length + fileName.length + data.length, Utils.Constants.ENDOFF);

    return Buffer.concat([loc, fileName, data, cen, fileName, end]);
}

describe("method - inflater decompression bomb", () => {
    // 4 MB of a single repeated byte deflates to a few KB
    const bomb = Buffer.alloc(4 * 1024 * 1024, 0x61);
    const deflatedBomb = zlib.deflateRawSync(bomb);

    describe("inflater", () => {
        it("inflateAsync() stops an entry that declares size 0", (done) => {
            new Inflater(deflatedBomb, 0).inflateAsync(function (result, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                expect(result.length).to.equal(0);
                done();
            });
        });

        it("inflateAsync() caps output at the declared uncompressed size", (done) => {
            new Inflater(deflatedBomb, 1024).inflateAsync(function (result, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                expect(result.length).to.equal(0);
                done();
            });
        });

        it("inflate() and inflateAsync() still inflate data matching the declared size", (done) => {
            const content = Buffer.alloc(100 * 1024);
            for (let i = 0; i < content.length; i++) content[i] = (i * 7) & 0xff;
            const deflated = zlib.deflateRawSync(content);

            expect(new Inflater(deflated, content.length).inflate().equals(content)).to.equal(true);
            new Inflater(deflated, content.length).inflateAsync(function (result, err) {
                expect(err).to.equal(undefined);
                expect(result.equals(content)).to.equal(true);
                done();
            });
        });

        it("inflate() and inflateAsync() still inflate a genuinely empty entry", (done) => {
            const deflated = zlib.deflateRawSync(Buffer.alloc(0));

            expect(new Inflater(deflated, 0).inflate().length).to.equal(0);
            new Inflater(deflated, 0).inflateAsync(function (result, err) {
                expect(err).to.equal(undefined);
                expect(result.length).to.equal(0);
                done();
            });
        });
    });

    describe("zip entry", () => {
        it("getData() rejects an entry that declares size 0", () => {
            const zip = new Zip(deflatedZip("bomb.txt", bomb, 0));
            const entry = zip.getEntry("bomb.txt");
            expect(entry.header.size).to.equal(0);

            let error;
            try {
                entry.getData();
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an("error");
            if (syncCapAvailable) {
                // stopped by the output cap, not by a CRC mismatch after a full inflate
                expect(error).to.be.an.instanceof(RangeError);
                expect(error.code).to.equal("ERR_BUFFER_TOO_LARGE");
            }
        });

        it("getDataAsync() rejects an entry that declares size 0", (done) => {
            const zip = new Zip(deflatedZip("bomb.txt", bomb, 0));
            zip.getEntry("bomb.txt").getDataAsync(function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("readFileAsync() rejects an entry that declares a smaller size", (done) => {
            const zip = new Zip(deflatedZip("bomb.txt", bomb, 1024));
            zip.readFileAsync("bomb.txt", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("getData() and getDataAsync() still read entries with an honest size", (done) => {
            const content = Buffer.from("adm-zip ".repeat(4096));
            const zip = new Zip(deflatedZip("ok.txt", content, content.length));
            const entry = zip.getEntry("ok.txt");

            expect(entry.getData().equals(content)).to.equal(true);
            entry.getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(content)).to.equal(true);
                done();
            });
        });

        it("getData() and getDataAsync() still read a genuinely empty deflated entry", (done) => {
            const zip = new Zip(deflatedZip("empty.txt", Buffer.alloc(0), 0));
            const entry = zip.getEntry("empty.txt");

            expect(entry.getData().length).to.equal(0);
            entry.getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            });
        });
    });
});
