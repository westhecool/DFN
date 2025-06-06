# DFN (DistributedFileNetwork)

A simple distributed file network over http/ws using cloudflare tunnels that is
- peer to peer
- end to end encrypted
- anonymous*
- fast
- can run a browser (downloading only)

\* seeding is almost completely anonymous but there are possible ways your ip address could be exposed when downloading

## todo before first release

- [ ] Bug tests
- [ ] Write documentation

## CLI

Installing:
```sh
npm i -g https://github.com/westhecool/DFN.git # will change when first release is published
```

Usage:
```
Usage: dfn command arguments ... or dfn download_list_path [download_path]

Commands:
  dfn download download_list_path [download_path]   Download file without serving it back to the network (recommended for small files)
  dfn sync download_list_path [download_path]       Download (if not already complete) and serve files back to the network
  dfn create path [download_list_path]              Create a new download list
  dfn tracker-server                                Start a tracker server

Options:
      --version  Show version number                [boolean]
  -h, --help     Show help                          [boolean]
```

Example usage:
```sh
# Add a whole folder to a download list
dfn create myfolder # will create myfolder.dfn

# Create a single file download list
dfn create myfile.mp4 # will create myfile.mp4.dfn

# Download only
dfn download mylist.dfn # download to the current directory
# or
dfn mylist.dfn # download to the current directory

# Download and Seed
dfn sync mylist.dfn # if the files are in the current directory
# else
dfn sync mylist.dfn "path/to/the/folder/containing/'myfolder'/or/'myfile.mp4'"
```