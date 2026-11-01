"use strict";

// CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9): extraction followed symbolic links that
// already existed inside the extraction target. sanitize() only checks the
// textual entry path against the root, while writeFileTo()/makeDir() open and
// create paths with calls that follow symlinks. Anyone able to plant a symlink in
// a shared or reused extraction directory could therefore make extractAllTo(),
// extractAllToAsync() or extractEntryTo() write (and chmod) files anywhere the
// extracting process can write - no traversal sequence needed in the archive.
// Every path component below the extraction root is now lstat'ed and a symlink
// rejects the write.

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");
const Utils = require("../../util");

const IN_THE_WAY = /There is a file in the way/;

describe("ADM-ZIP - symlinks inside the extraction target (CVE-2026-76845)", () => {
    const work = path.join(__dirname, "xxx");
    const destination = path.join(work, "dest");
    const outside = path.join(work, "outside");
    let links = [];

    // Directory links are created as junctions: on Windows a junction needs no
    // special privilege, elsewhere the type argument is ignored. File symlinks may
    // need a privilege on Windows; when it is missing the test is skipped.
    function makeLink(ctx, target, linkPath, type) {
        try {
            fs.symlinkSync(target, linkPath, type);
        } catch (e) {
            if (process.platform === "win32" && e.code === "EPERM") ctx.skip();
            throw e;
        }
        links.push(linkPath);
    }

    function removeLink(linkPath) {
        try {
            fs.unlinkSync(linkPath);
        } catch (e) {
            try {
                fs.rmdirSync(linkPath);
            } catch (e2) {
                // already gone
            }
        }
    }

    // destination/link -> outside
    function linkDirectory(ctx) {
        const linkPath = path.join(destination, "link");
        makeLink(ctx, outside, linkPath, "junction");
        return linkPath;
    }

    // destination/<name> -> outside/<targetName>
    function linkFile(ctx, name, targetName) {
        const linkPath = path.join(destination, name);
        makeLink(ctx, path.join(outside, targetName), linkPath, "file");
        return linkPath;
    }

    function archive(entries) {
        const zip = new Zip();
        entries.forEach((entry) => {
            if (entry.slice(-1) === "/") zip.addFile(entry, null);
            else zip.addFile(entry, Buffer.from("PWNED"));
        });
        return zip.toBuffer();
    }

    function read(file) {
        return fs.readFileSync(file).toString();
    }

    beforeEach(() => {
        links = [];
        rimraf.sync(work);
        fs.mkdirSync(destination, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    afterEach((done) => {
        // drop the links first so cleanup can never reach through them
        links.forEach(removeLink);
        rimraf(work, done);
    });

    describe("extractAllTo()", () => {
        it("does not write a file through a symlinked directory", function () {
            linkDirectory(this);
            const buf = archive(["link/pwned.txt"]);

            assert.throws(() => new Zip(buf).extractAllTo(destination, true), IN_THE_WAY);
            assert.throws(() => new Zip(buf).extractAllTo(destination, false), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("does not write a file through a symlinked directory nested below real ones", function () {
            fs.mkdirSync(path.join(destination, "a", "b"), { recursive: true });
            makeLink(this, outside, path.join(destination, "a", "b", "link"), "junction");
            const buf = archive(["a/b/link/deeper/pwned.txt"]);

            assert.throws(() => new Zip(buf).extractAllTo(destination, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "deeper")), false);
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDirectory(this);
            const buf = archive(["link/sub/"]);

            assert.throws(() => new Zip(buf).extractAllTo(destination, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "sub")), false);
        });

        it("does not overwrite the target of a symlinked file", function () {
            fs.writeFileSync(path.join(outside, "victim.txt"), "ORIGINAL");
            linkFile(this, "victim.txt", "victim.txt");
            const buf = archive(["victim.txt"]);

            assert.throws(() => new Zip(buf).extractAllTo(destination, true), IN_THE_WAY);
            assert.strictEqual(read(path.join(outside, "victim.txt")), "ORIGINAL");
        });

        it("does not create a file through a dangling symlink, even without overwrite", function () {
            linkFile(this, "victim.txt", "created.txt");
            const buf = archive(["victim.txt"]);

            assert.throws(() => new Zip(buf).extractAllTo(destination, false), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "created.txt")), false);
        });
    });

    describe("extractEntryTo()", () => {
        it("does not write a single file through a symlinked directory", function () {
            linkDirectory(this);
            const zip = new Zip(archive(["link/pwned.txt"]));

            assert.throws(() => zip.extractEntryTo("link/pwned.txt", destination, true, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("does not write the children of a directory entry through a symlinked directory", function () {
            linkDirectory(this);
            const zip = new Zip(archive(["link/", "link/pwned.txt"]));

            assert.throws(() => zip.extractEntryTo("link/", destination, true, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("does not write through a symlinked directory named by outFileName", function () {
            linkDirectory(this);
            const zip = new Zip(archive(["a.txt"]));

            assert.throws(() => zip.extractEntryTo("a.txt", destination, false, true, false, "link/pwned.txt"), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("does not overwrite the target of a symlinked file when the entry path is flattened", function () {
            fs.writeFileSync(path.join(outside, "victim.txt"), "ORIGINAL");
            linkFile(this, "victim.txt", "victim.txt");
            const zip = new Zip(archive(["dir/victim.txt"]));

            assert.throws(() => zip.extractEntryTo("dir/victim.txt", destination, false, true), IN_THE_WAY);
            assert.strictEqual(read(path.join(outside, "victim.txt")), "ORIGINAL");
        });
    });

    describe("extractAllToAsync()", () => {
        it("does not write a file through a symlinked directory", function () {
            linkDirectory(this);
            return new Zip(archive(["link/pwned.txt"])).extractAllToAsync(destination, true).then(
                () => assert.fail("extractAllToAsync should refuse to write through a symlink"),
                (err) => {
                    assert.ok(IN_THE_WAY.test(err.message), err.message);
                    assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
                }
            );
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDirectory(this);
            return new Zip(archive(["link/sub/"])).extractAllToAsync(destination, true).then(
                () => assert.fail("extractAllToAsync should refuse to create a folder through a symlink"),
                (err) => {
                    assert.ok(/Unable to create folder/.test(err.message), err.message);
                    assert.strictEqual(fs.existsSync(path.join(outside, "sub")), false);
                }
            );
        });

        it("does not overwrite the target of a symlinked file", function () {
            fs.writeFileSync(path.join(outside, "victim.txt"), "ORIGINAL");
            linkFile(this, "victim.txt", "victim.txt");
            return new Zip(archive(["victim.txt"])).extractAllToAsync(destination, true).then(
                () => assert.fail("extractAllToAsync should refuse to write through a symlink"),
                (err) => {
                    assert.ok(IN_THE_WAY.test(err.message), err.message);
                    assert.strictEqual(read(path.join(outside, "victim.txt")), "ORIGINAL");
                }
            );
        });
    });

    describe("legitimate extraction", () => {
        it("still extracts into existing real directories and overwrites real files", () => {
            fs.mkdirSync(path.join(destination, "a", "b"), { recursive: true });
            fs.writeFileSync(path.join(destination, "a", "b", "c.txt"), "OLD");
            const buf = archive(["a/", "a/b/", "a/b/c.txt", "d/", "e.txt"]);

            new Zip(buf).extractAllTo(destination, true);
            assert.strictEqual(read(path.join(destination, "a", "b", "c.txt")), "PWNED");
            assert.strictEqual(read(path.join(destination, "e.txt")), "PWNED");
            assert.ok(fs.statSync(path.join(destination, "d")).isDirectory());

            const zip = new Zip(buf);
            zip.extractEntryTo("a/", destination, true, true);
            zip.extractEntryTo("e.txt", destination, false, true, false, "f.txt");
            assert.strictEqual(read(path.join(destination, "f.txt")), "PWNED");

            return new Zip(buf).extractAllToAsync(destination, true).then(() => {
                assert.strictEqual(read(path.join(destination, "a", "b", "c.txt")), "PWNED");
            });
        });

        it("still extracts when the extraction root itself is reached through a symlink", function () {
            const root = path.join(work, "root-link");
            makeLink(this, destination, root, "junction");
            const buf = archive(["a/", "a/b/c.txt", "e.txt"]);

            new Zip(buf).extractAllTo(root, true);
            assert.strictEqual(read(path.join(destination, "a", "b", "c.txt")), "PWNED");
            assert.strictEqual(read(path.join(destination, "e.txt")), "PWNED");

            new Zip(buf).extractEntryTo("a/b/c.txt", root, false, true);
            assert.strictEqual(read(path.join(destination, "c.txt")), "PWNED");

            return new Zip(buf).extractAllToAsync(path.join(root, "async"), true).then(() => {
                assert.strictEqual(read(path.join(destination, "async", "a", "b", "c.txt")), "PWNED");
            });
        });
    });

    describe("Utils#assertPathSafe()", () => {
        it("rejects a symlinked component below the root and accepts everything else", function () {
            const link = linkDirectory(this);
            const utils = new Utils();

            assert.throws(() => utils.assertPathSafe(destination, link), IN_THE_WAY);
            assert.throws(() => utils.assertPathSafe(destination, path.join(link, "x", "y.txt")), IN_THE_WAY);

            // the root itself, paths that do not exist yet and paths outside the root are left alone
            utils.assertPathSafe(destination, destination);
            utils.assertPathSafe(destination, path.join(destination, "missing", "file.txt"));
            utils.assertPathSafe(destination, path.join(outside, "file.txt"));
            // a root reached through a symlink is the caller's choice
            utils.assertPathSafe(link, path.join(link, "file.txt"));
        });

        it("is a no-op for a custom fs without lstatSync", function () {
            linkDirectory(this);
            const customFs = Object.assign({}, fs);
            delete customFs.lstatSync;
            const utils = new Utils({ fs: customFs });

            utils.assertPathSafe(destination, path.join(destination, "link", "file.txt"));
        });
    });
});
