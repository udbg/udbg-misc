
This repo contains miscellaneous script which can make udbg more powerful

## Install

Requirements: git, [udbg 0.2.1](https://github.com/udbg/udbg/releases)

1. Merge the following configuration to your `udbg-config.lua`
    ```lua
    plugins = {
        {git = 'https://github.com/udbg/udbg-misc'},
    }
    ```
2. Start udbg, execute the `.plugin-update` command
3. Restart udbg

## Command

`udbg/command/`
- `vmpimpfix` A tool which can parse the import list obfuscated by VMP, inspired by https://github.com/mike1k/VMPImportFixer