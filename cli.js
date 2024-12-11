#!/usr/bin/env node
function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes'

    const k = 1024
    const dm = decimals < 0 ? 0 : decimals
    const sizes = ['Bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']

    const i = Math.floor(Math.log(bytes) / Math.log(k))

    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`
}
(async () => {
    const fs = require('fs');
    const path = require('path');
    const { Server, Client, Tracker, HelperFunctions: { hash, hashFile }, messages, partSize } = require('./index.js');
    if (process.argv[2] == 'download') {
        const fileHash = process.argv[3];
        if (!fileHash) {
            console.error('Missing file hash.');
            console.log('Usage: node cli.js download file_hash [file_path]');
            process.exit(1);
        }
        const tracker = new Tracker('https://dfn-tracker.westhedev.xyz');
        const peers = (await tracker.findPeers([fileHash]))[fileHash];
        if (!peers[0]) {
            throw new Error('No peers found for this file.');
        }
        // Ideally we would have connections to multiple peers or at least use a random one
        console.log(`Found peer: ${peers[0]}`);
        const client = new Client(`https://${peers[0]}`);
        const meta = await client.getFileMetadata(fileHash);
        console.log(`File info: name: ${meta.name}, size: ${formatBytes(meta.size)}, parts: ${meta.parts}`);
        const out = fs.createWriteStream(process.argv[4] || meta.name);
        process.stdout.write(`\r\x1b[KDownloading file...`);
        var running = 0;
        var write_index = 0;
        const start = Date.now();
        for (let i = 0; i < meta.parts; i++) {
            running++;
            const ii = Number(i); // recast
            setTimeout(async () => {
                const d = await client.getFilePart(fileHash, i);
                if ((await hash(d)) != meta.part_hashes[i]) {
                    throw new Error('Hash mismatch!');
                }
                while (write_index != ii) await new Promise(r => setTimeout(r, 10));
                out.write(d);
                process.stdout.write(`\r\x1b[KDownloaded part ${write_index + 1}/${meta.parts} (${(((write_index + 1) / meta.parts) * 100).toFixed(2)}%) (${formatBytes(((write_index + 1) * partSize) / ((Date.now() - start) / 1000))}/s)...`);
                write_index++;
                running--;
            }, 0);
            while (running >= 5) await new Promise(r => setTimeout(r, 10)); // Limit to 5 concurrent requests to the peer
        }
        while (running > 0) await new Promise(r => setTimeout(r, 10));
        out.close();
        process.stdout.write(`\r\x1b[KDownload complete in ${((Date.now() - start) / 1000).toFixed(0)}s (${formatBytes(((write_index + 1) * partSize) / ((Date.now() - start) / 1000))}/s)\n`);
    } else if (process.argv[2] == 'serve') {
        var files = process.argv.slice(3).map((f) => path.resolve(f));
        if (fs.statSync(files[0]).isDirectory()) {
            files = fs.readdirSync(files[0]).map((f) => {
                const file = path.join(files[0], f);
                if (fs.statSync(file).isFile()) {
                    return file;
                }
            }).filter((f) => f); // remove empty strings
        }
        const fileObjects = {};
        for (const file of files) {
            if (!fs.existsSync(file)) {
                console.error(`File "${file}" does not exist.`);
                process.exit(1);
            }
            const fileSize = fs.statSync(file).size;
            const fileHash = await hashFile(file, (progress) => {
                process.stdout.write(`\r\x1b[KHashing file "${file}"... ${progress}%`);
            });
            fileObjects[fileHash.hash] = {
                name: path.basename(file),
                path: file,
                size: fs.statSync(file).size,
                hash: fileHash.hash,
                progress: fileHash.parts.map((p) => 1), // an array of ether 1 or 0 for each part
                parts: Math.ceil(fileSize / partSize),
                part_hashes: fileHash.parts,
                fd: await fs.promises.open(file, 'r')
            };
        }
        process.stdout.write(`\r\x1b[KStarting server...`);
        const server = new Server();
        server.on('file-meta-request', (fileHash, cb, error) => {
            if (!fileObjects.hasOwnProperty(fileHash)) {
                error(messages.UNKNOWN_FILE);
                return;
            }
            cb({
                name: fileObjects[fileHash].name,
                size: fileObjects[fileHash].size,
                hash: fileHash,
                parts: fileObjects[fileHash].parts,
                part_hashes: fileObjects[fileHash].part_hashes,
                encrypted: false
            });
        });
        server.on('file-progress-request', (fileHash, cb, error) => {
            if (!fileObjects.hasOwnProperty(fileHash)) {
                error(messages.UNKNOWN_FILE);
                return;
            }
            cb(fileObjects[fileHash].progress);
        });
        server.on('file-part-request', async (fileHash, partIndex, cb, error) => {
            if (!fileObjects.hasOwnProperty(fileHash)) {
                error(messages.UNKNOWN_FILE);
                return;
            }
            const offset = partIndex * partSize;
            var readSize = partSize;
            if ((offset + partSize) > fileObjects[fileHash].size) readSize = fileObjects[fileHash].size - offset;
            const buffer = Buffer.alloc(readSize);
            await fileObjects[fileHash].fd.read(buffer, 0, readSize, offset);
            cb(buffer);
        });
        await server.start();
        const tracker = new Tracker("https://dfn-tracker.westhedev.xyz", server.hostname);
        await tracker.announceFiles(Object.keys(fileObjects));
        for (const fileHash of Object.keys(fileObjects)) {
            console.log(`\r\x1b[KServing file "${fileObjects[fileHash].path}" hash: ${fileHash}`);
        }
    } else {
        console.error('Unknown command: ' + process.argv[2]);
        console.log('Usage: node cli.js command arguments ...');
        console.log('Commands:');
        console.log('\tdownload file_hash [file_path]');
        console.log('\tserve files (or directory) ...');
        process.exit(1);
    }
})();