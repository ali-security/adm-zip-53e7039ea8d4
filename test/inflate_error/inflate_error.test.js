"use strict";

// GHSA-8238-w5pm-2374: inflateAsync() fed the compressed data to a zlib
// InflateRaw stream without an "error" listener. A malformed DEFLATE payload
// (Z_DATA_ERROR), a truncated stream, or output exceeding the declared size made
// the stream emit "error", which Node re-throws as an uncaught exception on a
// later tick: neither the caller's try/catch nor its callback ran and the whole
// process crashed. Stream failures are now reported through the callback.

const { expect } = require("chai");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const rimraf = require("rimraf");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Utils = require("../../util");

const MAX_OUTPUT_EXCEEDED = "Decompressed data exceeds the declared uncompressed size";
const CONTENT = Buffer.from("adm-zip ".repeat(8 * 1024));

// a raw DEFLATE block header with BTYPE=11 (reserved): zlib fails with
// "invalid block type" (Z_DATA_ERROR) on the first byte
const MALFORMED_DEFLATE = Buffer.alloc(64, 0xff);

// Builds a valid archive with adm-zip's own writer: one DEFLATE entry whose
// headers, CRC and offsets are all correct.
function validArchive(name) {
    const zip = new Zip();
    zip.addFile(name, CONTENT);
    const buf = zip.toBuffer();
    const entry = new Zip(buf).getEntry(name);
    expect(entry.header.method).to.equal(Utils.Constants.DEFLATED);
    return buf;
}

// The advisory's PoC: only the compressed data of the entry is corrupted, the
// ZIP structure around it stays intact.
function corruptedArchive(name) {
    const buf = validArchive(name);
    const compressed = new Zip(buf).getEntry(name).getCompressedData();
    const pos = buf.indexOf(compressed);
    expect(pos).to.be.above(0);
    buf.fill(0xff, pos, pos + compressed.length);
    return buf;
}

// Rewrites the declared uncompressed size of the single entry (local and
// central header) so the real data inflates past it.
function undersizedArchive(name, declaredSize) {
    const buf = validArchive(name);
    expect(buf.readUInt32LE(0)).to.equal(Utils.Constants.LOCSIG);
    buf.writeUInt32LE(declaredSize, Utils.Constants.LOCLEN);
    const endPos = buf.length - Utils.Constants.ENDHDR;
    expect(buf.readUInt32LE(endPos)).to.equal(Utils.Constants.ENDSIG);
    const cenPos = buf.readUInt32LE(endPos + Utils.Constants.ENDOFF);
    expect(buf.readUInt32LE(cenPos)).to.equal(Utils.Constants.CENSIG);
    buf.writeUInt32LE(declaredSize, cenPos + Utils.Constants.CENLEN);
    return buf;
}

describe("ADM-ZIP - async inflate stream errors (GHSA-8238-w5pm-2374)", () => {
    const destination = path.join(__dirname, "xxx");

    afterEach((done) => rimraf(destination, done));

    describe("inflater", () => {
        it("inflateAsync() reports a malformed DEFLATE stream to the callback", (done) => {
            new Inflater(MALFORMED_DEFLATE, CONTENT.length).inflateAsync(function (result, err) {
                expect(err).to.be.an("error");
                expect(err.code).to.equal("Z_DATA_ERROR");
                expect(result.length).to.equal(0);
                done();
            });
        });

        it("inflateAsync() reports a truncated DEFLATE stream to the callback", (done) => {
            const deflated = zlib.deflateRawSync(CONTENT);
            const truncated = deflated.slice(0, deflated.length >> 1);
            new Inflater(truncated, CONTENT.length).inflateAsync(function (result, err) {
                expect(err).to.be.an("error");
                expect(err.code).to.equal("Z_BUF_ERROR");
                expect(result.length).to.equal(0);
                done();
            });
        });

        it("inflate() still throws synchronously on a malformed DEFLATE stream", () => {
            expect(() => new Inflater(MALFORMED_DEFLATE, CONTENT.length).inflate()).to.throw();
        });
    });

    describe("malformed DEFLATE payload", () => {
        it("getDataAsync() reports the stream error instead of crashing", (done) => {
            const zip = new Zip(corruptedArchive("poc.txt"));
            zip.getEntry("poc.txt").getDataAsync(function (data, err) {
                expect(err).to.be.an("error");
                expect(err.code).to.equal("Z_DATA_ERROR");
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("readFileAsync() reports the stream error instead of crashing", (done) => {
            const zip = new Zip(corruptedArchive("poc.txt"));
            zip.readFileAsync("poc.txt", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.code).to.equal("Z_DATA_ERROR");
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("readAsTextAsync() reports the stream error instead of crashing", (done) => {
            const zip = new Zip(corruptedArchive("poc.txt"));
            zip.readAsTextAsync("poc.txt", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.code).to.equal("Z_DATA_ERROR");
                done();
            });
        });

        it("extractAllToAsync() rejects and writes nothing", () => {
            const zip = new Zip(corruptedArchive("poc.txt"));
            return zip.extractAllToAsync(destination, false).then(
                () => expect.fail("extractAllToAsync should reject a malformed DEFLATE entry"),
                (err) => {
                    expect(err).to.be.an("error");
                    expect(err.code).to.equal("Z_DATA_ERROR");
                    expect(fs.existsSync(path.join(destination, "poc.txt"))).to.equal(false);
                }
            );
        });

        it("getData() still throws synchronously", () => {
            const zip = new Zip(corruptedArchive("poc.txt"));
            expect(() => zip.getEntry("poc.txt").getData()).to.throw();
        });

        it("the host process survives the advisory's PoC", function () {
            this.timeout(20000);
            const script = [
                "var Zip = require(" + JSON.stringify(path.join(__dirname, "..", "..", "adm-zip")) + ");",
                "var zip = new Zip(Buffer.from(process.env.ADM_ZIP_POC, 'base64'));",
                "try {",
                "    zip.getEntry('poc.txt').getDataAsync(function (data, err) {",
                "        process.stdout.write(err ? 'callback-error:' + err.code : 'callback-ok');",
                "    });",
                "} catch (e) {",
                "    process.stdout.write('caught:' + e.message);",
                "}"
            ].join(" ");
            const env = Object.assign({}, process.env, { ADM_ZIP_POC: corruptedArchive("poc.txt").toString("base64") });
            const res = childProcess.spawnSync(process.execPath, ["-e", script], { env: env, encoding: "utf8", timeout: 15000 });

            expect(res.error).to.equal(undefined);
            expect(res.status, res.stderr).to.equal(0);
            expect(res.stdout).to.equal("callback-error:Z_DATA_ERROR");
        });
    });

    describe("output exceeding the declared size", () => {
        it("readAsTextAsync() reports the size error", (done) => {
            const zip = new Zip(undersizedArchive("big.txt", 1024));
            zip.readAsTextAsync("big.txt", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                done();
            });
        });

        it("extractAllToAsync() rejects and writes nothing", () => {
            const zip = new Zip(undersizedArchive("big.txt", 1024));
            return zip.extractAllToAsync(destination, false).then(
                () => expect.fail("extractAllToAsync should reject an entry larger than its declared size"),
                (err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.contain(MAX_OUTPUT_EXCEEDED);
                    expect(fs.existsSync(path.join(destination, "big.txt"))).to.equal(false);
                }
            );
        });
    });

    describe("valid archives", () => {
        it("getDataAsync() and readAsTextAsync() still read an intact DEFLATE entry", (done) => {
            const zip = new Zip(validArchive("ok.txt"));
            zip.getEntry("ok.txt").getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(CONTENT)).to.equal(true);
                zip.readAsTextAsync("ok.txt", function (text, err2) {
                    expect(err2).to.equal(undefined);
                    expect(text).to.equal(CONTENT.toString());
                    done();
                });
            });
        });

        it("extractAllToAsync() still extracts an intact DEFLATE entry", () => {
            const zip = new Zip(validArchive("ok.txt"));
            return zip.extractAllToAsync(destination, false).then(() => {
                expect(fs.readFileSync(path.join(destination, "ok.txt")).equals(CONTENT)).to.equal(true);
            });
        });
    });
});
