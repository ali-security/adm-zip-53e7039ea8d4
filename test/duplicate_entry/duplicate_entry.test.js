"use strict";

// GHSA-p634-w6r4-rjp2: a ZIP archive can declare the same entry name twice.
// adm-zip kept every entry in its entry list but only the last one in its
// name table, so getEntry(name) returned the last duplicate while
// extractAllTo() wrote the first one to disk. An application that validated an
// entry's bytes via getEntry() before extracting could approve one file while
// different content landed on disk. Such archives are now rejected on read.

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const DUPLICATE = /Duplicate entry name/;

// Overwrites every occurrence of `from` in `buf` with `to` (same length). For an
// entry name this renames the entry in both its local header and its central
// directory record, without touching the data or its CRC.
function renameEntry(buf, from, to) {
    const out = Buffer.from(buf);
    const needle = Buffer.isBuffer(from) ? from : Buffer.from(from);
    const replacement = Buffer.isBuffer(to) ? to : Buffer.from(to);
    assert.strictEqual(needle.length, replacement.length);
    let count = 0;
    let pos = out.indexOf(needle);
    while (pos !== -1) {
        replacement.copy(out, pos);
        count++;
        pos = out.indexOf(needle, pos + needle.length);
    }
    // exactly one local header and one central directory record carry the name
    assert.strictEqual(count, 2);
    return out;
}

// Builds the advisory's PoC: "a.txt" (FIRST) is renamed to "b.txt" so the archive
// holds two "b.txt" entries, FIRST then SECOND.
function makeDuplicateArchive() {
    const zip = new Zip({ noSort: true });
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    return renameEntry(zip.toBuffer(), "a.txt", "b.txt");
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    const destination = path.join(__dirname, "xxx");

    afterEach((done) => rimraf(destination, done));

    it("getEntry() rejects an archive that declares the same name twice", () => {
        const buf = makeDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntry("b.txt"), DUPLICATE);
        assert.throws(() => new Zip(buf).readFile("b.txt"), DUPLICATE);
    });

    it("getEntries() and eager loading reject the archive", () => {
        const buf = makeDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntries(), DUPLICATE);
        assert.throws(() => new Zip(buf, { readEntries: true }), DUPLICATE);
    });

    it("extractAllTo() rejects the archive and writes nothing", () => {
        const buf = makeDuplicateArchive();
        assert.throws(() => new Zip(buf).extractAllTo(destination, false), DUPLICATE);
        assert.throws(() => new Zip(buf).extractAllTo(destination, true), DUPLICATE);
        assert.strictEqual(fs.existsSync(path.join(destination, "b.txt")), false);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", () => {
        const buf = makeDuplicateArchive();
        return new Zip(buf).extractAllToAsync(destination, false).then(
            () => assert.fail("extractAllToAsync should reject an archive with duplicate entry names"),
            (err) => {
                assert.ok(DUPLICATE.test(err.message), err.message);
                assert.strictEqual(fs.existsSync(path.join(destination, "b.txt")), false);
            }
        );
    });

    it("a validate-then-extract flow cannot approve one file while writing another", () => {
        const zip = new Zip(makeDuplicateArchive());
        // the advisory's flow: inspect the entry via getEntry(), then extract everything
        assert.throws(() => {
            const approved = zip.getEntry("b.txt").getData().toString();
            zip.extractAllTo(destination, false);
            // only reached if the archive was accepted: what landed on disk must be what was approved
            assert.strictEqual(fs.readFileSync(path.join(destination, "b.txt")).toString(), approved);
        }, DUPLICATE);
    });

    it("names with different bytes that decode to the same string are duplicates", () => {
        const zip = new Zip({ noSort: true });
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));
        // invalid UTF-8 lead bytes both decode to U+FFFD, i.e. the same entry name
        let buf = renameEntry(zip.toBuffer(), "a.txt", Buffer.from([0xff, 0x2e, 0x74, 0x78, 0x74]));
        buf = renameEntry(buf, "b.txt", Buffer.from([0xfe, 0x2e, 0x74, 0x78, 0x74]));
        assert.throws(() => new Zip(buf).getEntries(), DUPLICATE);
        assert.throws(() => new Zip(buf).getEntry("�.txt"), DUPLICATE);
    });

    it("accepts distinct names, including names of Object.prototype members", () => {
        const names = ["__proto__", "a.txt", "constructor", "hasOwnProperty", "toString", "valueOf"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, Buffer.from("content of " + name)));
        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort(),
            names.slice().sort()
        );
        names.forEach((name) => assert.strictEqual(reopened.readFile(name).toString(), "content of " + name));
    });

    it("accepts an archive whose entries have distinct names", () => {
        const zip = new Zip({ noSort: true });
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));
        const reopened = new Zip(zip.toBuffer());
        assert.strictEqual(reopened.readFile("a.txt").toString(), "FIRST");
        assert.strictEqual(reopened.readFile("b.txt").toString(), "SECOND");
        reopened.extractAllTo(destination, false);
        assert.strictEqual(fs.readFileSync(path.join(destination, "a.txt")).toString(), "FIRST");
        assert.strictEqual(fs.readFileSync(path.join(destination, "b.txt")).toString(), "SECOND");
    });
});
