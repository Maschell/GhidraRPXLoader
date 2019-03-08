# Ghidra RPX/RPL loader

This is a (WIP) simple extension to open .rpx and .rpl files with Ghidra.

# Usage

Install the extension using the `Install Extensions` option inside Ghidra or extract the .zip manually into `[GHIDRA_ROOT]\Ghidra\Extensions`. Make sure to restart the program after installing.

Once the extension is installed, you can import a .rpx/.rpl file via `File->Import File...`.

# Building

```
cd /path/to/extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra 
gradle 
```

Output goes into `dist`

# Credits

Based on https://github.com/Relys/rpl2elf