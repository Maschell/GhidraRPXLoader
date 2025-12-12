# Ghidra RPX/RPL loader

This is a simple extension to open .rpx and .rpl files with `Ghidra 11.0+`.

The loader includes the Gekko/Broadway/Espresso processor definitions that are based on the [Ghidra-GameCube-Loader](https://github.com/Cuyler36/Ghidra-GameCube-Loader).

In case the Espresso language is not found, the loader will switch to the default PowerPC processor. However, it is not advisable to expect satisfactory results if the program uses paired single instructions.

Imports in official .rpl/.rpx files may display as "func_xyz" instead of the function's actual name. This issue can be resolved by running the `fix_primary_imports.java` script, which is included with this loader.

## Building

- Ensure you have ``JAVA_HOME`` set to the path of your JDK 21 installation.
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
- Run the `fix_primary_imports.java` script if imports are not displayed properly

# Credits

- Based on https://github.com/Relys/rpl2elf
- Based on https://github.com/Cuyler36/Ghidra-GameCube-Loader