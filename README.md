# Ghidra RPX/RPL loader

This is a (WIP) simple extension to open .rpx and .rpl files with Ghidra.

# Dependencies

This loader uses the Gekko/Broadway processor definitions for Ghidra if found - it is recommended that this should be installed prior to using the loader.

https://github.com/aldelaro5/ghidra-gekko-broadway-lang

The loader will fallback to the default PowerPC processor if the Gekko/Broadway language is not found, but do not expect good results if the program uses any paired single instructions.

## Building
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 17 installation.
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (``File -> Install Extensions...``).

## Usage 
- Choose the `Gekko/Broadway/Espresso` language if asked

# Eclipse

To be able open this module in eclipse, you need to create a new Ghidra Module and copy the `.classpath`, `.project` and `.settings` to the root of this repository.

# Credits

- Based on https://github.com/Relys/rpl2elf
- https://github.com/Cuyler36/Ghidra-GameCube-Loader