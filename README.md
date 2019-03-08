# Ghidra RPX/RPL loader

This is a (WIP) simple extension to open .rpx and .rpl files with Ghidra.

# Usage

Install the extension by using the `Install Extensions` option inside Ghidra or extracting the .zip manually into `[GHIDRA_ROOT]\Ghidra\Extensions`. Make sure to restart the program after installing.

Once the extension is installed, you import a .rpx/.rpl via `File->Import...`.

# Building

```
cd /path/to/extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra 
gradle extensionDistZip #Substitute extension name
```

Output goes into `build/distributions/`

# Credits

Based on https://github.com/Relys/rpl2elf