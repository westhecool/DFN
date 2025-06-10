#!/usr/bin/env node
import DFN from './index.js';
import pathlib from 'path';
import Table from 'cli-table3';
import fs from 'fs';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

const otherCommands = ['sync', 'create', 'tracker-server'];
const args = yargs(hideBin(process.argv))
    .usage('Usage: $0 command arguments ... or $0 download_list_path [download_path]')
    .command('download download_list_path [download_path]', 'Download file without serving it back to the network (recommended for small files)', (yargs) => {
        yargs.positional('download_list_path', {
            type: 'string',
            description: 'Path to download list file. Can also be a quick share link',
            demandOption: true
        })
        yargs.positional('download_path', {
            type: 'string',
            description: 'Path to download to',
            default: '.',
            demandOption: false
        })
    })
    .command('sync download_list_path [download_path]', 'Download (if not already complete) and serve files back to the network', (yargs) => {
        yargs.positional('download_list_path', {
            type: 'string',
            description: 'Path to download list file. Can also be a quick share link',
            demandOption: true
        })
        yargs.positional('download_path', {
            type: 'string',
            description: 'Path to download to',
            default: '.',
            demandOption: false
        })
    })
    .command('create path [download_list_path]', 'Create a new download list', (yargs) => {
        yargs.positional('path', {
            type: 'string',
            description: 'Path to file/folder to be downloaded',
            demandOption: true
        })
            .positional('download_list_path', {
                type: 'string',
                description: 'Path to download list file to be created',
                default: null,
                demandOption: false
            })
    })
    .command('tracker-server', 'Start a tracker server', (yargs) => {
        yargs.option('port', {
            type: 'number',
            description: 'Port to listen on',
            default: 3000,
            demandOption: false
        })
            .option('host', {
                type: 'string',
                description: 'Host to listen on',
                default: '0.0.0.0',
                demandOption: false
            })
            .option('tunnel', {
                type: 'boolean',
                description: 'Serve the tracker over a tunnel (not recommended as the hostnames change often)',
                default: false,
                demandOption: false
            })
            .alias('H', 'host')
            .alias('p', 'port')
            .alias('t', 'tunnel')
    })
    .alias('h', 'help')
const argv = args.parse();

let list;
let listbuf;
let listhash;
let peer;
let status = {};
let outpath = '.';
let endReport = '';
let lastStatus = null;
async function printStatus() {
    let speed = 0;
    const t = new Table({
        head: ['Path', 'Downloaded', 'Speed', 'Time Left']
    });

    for (const path of await peer.getFiles(false)) {
        const status = parseProgress(await peer.getFileProgress(path));
        if ((status.speed < Infinity && status.speed > 0) && !status.done) {
            speed += status.speed;
            t.push([
                status.pathNice,
                status.receivedF + '/' + status.totalF,
                status.speedF,
                Math.round(status.timeLeft) + 's',
                // JSON.stringify(status.partsHave) (fun for debugging)
            ]);
        }
    }
    const s = `Active transfers: Downloaded: ${(await peer.getFiles(true)).length}/${(await peer.getFiles()).length} files. Connected to ${Object.keys(peer.clients).length} peers. Total speed: ${formatBytes(speed)}/s\n` + t.toString();
    const h = await DFN.functions.hash(s);
    if (h == lastStatus) return;
    lastStatus = h;
    console.clear();
    console.log(s.trimEnd());
}

function parseProgress(progress) {
    progress.speedF = (progress.speed < Infinity && progress.speed >= 0) ? formatBytes(progress.speed) + '/s' : '-';
    progress.totalF = formatBytes(progress.total);
    progress.receivedF = formatBytes(progress.received);
    progress.neededF = formatBytes(progress.needed);
    progress.pathNice = progress.path.replace(outpath, '').substring(1).replace(/\\/g, '/');
    return progress;
}

async function main(listpath, seed = false) {
    console.clear();
    if (listpath.startsWith('qsl:')) {
        const serverAdd = listpath.split(':')[1];
        const hash = listpath.split(':')[2];
        const client = new DFN.Client('wss://' + serverAdd);
        await client.connect();
        listbuf = Buffer.concat([Buffer.from('DFNDLF'), DFN.binmap.serialize(await client.requestFileDownloadList(hash))]); // inefficient
    } else {
        listbuf = await fs.promises.readFile(listpath);
    }
    list = await DFN.decodeDownloadList(listbuf);
    listhash = await DFN.functions.hash(listbuf);
    console.log(`Downloading "${list.name}" (${formatBytes(list.size)}) to "${outpath}" Created: ${(new Date(list.created)).toLocaleString()}...`);
    peer = new DFN.Peer({ enableSeeding: seed });
    peer.server.on('file-download-list-request', (hash, cb, error) => {
        if (hash == listhash) {
            cb(list);
        } else {
            error(DFN.MESSAGES.ERR_UNKNOWN_FILE_DOWNLOAD_LIST);
        }
    });
    peer.events.on('download-complete', (p) => {
        endReport += `Downloaded ${p.path} (${p.totalF}) in ${Math.round(p.time)}s (${p.speedF})\n`;
        delete status[p.path];
    });
    console.log('Starting up...');
    await peer.start();
    await peer.add(list.content, outpath, (progress) => {
        process.stdout.write(`\rChecking downloaded file progress: ${progress.toFixed(2)}%`);
    });
    const alreadyDownloaded = await peer.getFiles(true);
    for (const file of alreadyDownloaded) {
        endReport += `File ${file} (${formatBytes(peer.files[file].info.size)}) was already downloaded\n`;
    }
    process.stdout.write('\n');
    if (await peer.allFilesComplete()) {
        console.log('All files were already downloaded!');
        if (!seed) {
            await peer.stop();
            process.exit(0);
            return;
        }
    } else {
        const interval = setInterval(printStatus, 1000);
        while (!await peer.allFilesComplete()) await new Promise((resolve) => setTimeout(resolve, 1000));
        clearInterval(interval);
        await new Promise((resolve) => setTimeout(resolve, 1500)); // wait for last status update
        console.clear();
        console.log('All downloads complete:');
        console.log(endReport.trimEnd());
    }
    if (seed) {
        console.log('Contining to seed... (CTRL+C to stop) Waiting quick share link...');
        console.log(`Quick share link: qsl:${await peer.cloudflared.waitForHostname()}:${listhash}`);
    } else {
        await peer.stop();
    }
}

if (argv._[0] == 'sync') {
    const listpath = argv.download_list_path.startsWith('qsl:') ? argv.download_list_path : pathlib.resolve(argv.download_list_path);
    outpath = pathlib.resolve(argv.download_path || '.');
    await main(listpath, true);
} else if (argv._.length > 0 && !otherCommands.includes(argv._[0])) {
    let listpath = argv._[0] == 'download' ? argv.download_list_path : argv._[0]
    listpath = listpath.startsWith('qsl:') ? listpath : pathlib.resolve(listpath);
    outpath = pathlib.resolve(argv._[0] == 'download' ? argv.download_path : (argv._[1] || '.'));
    await main(listpath, false);
} else if (argv._[0] == 'create') {
    const path = pathlib.resolve(argv.path);
    const listpath = pathlib.resolve(argv.download_list_path || path + '.dfn');
    console.log(`Creating download list from "${path}". Please wait... (this will take a while for large collections of files)`);
    const buf = await DFN.generateDownloadList(path, { logProgress: true });
    await fs.promises.writeFile(listpath, buf);
    console.log(`Done. Download list saved at "${listpath}"`);
} else if (argv._[0] == 'tracker-server') {
    const server = new DFN.TrackerServer();
    await server.listen({ port: argv.port, host: argv.host });
    console.log(`Listening on: ws://127.0.0.1:${server.address.port} (ws://${server.address.address}:${server.address.port})`);
    if (argv.tunnel) {
        console.log('Requesting a tunnel, please wait...');
        const CF = new DFN.Cloudflared();
        await CF.run({ url: `http://127.0.0.1:${server.address.port}` });
        console.log(`Listening through tunnel on: wss://${await CF.waitForHostname()}`);
    }
} else {
    args.showHelp();
    process.exit(1);
}