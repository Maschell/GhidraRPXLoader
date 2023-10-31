// Sets all imported references to primary
//@author GaryOderNichts
//@category wiiu
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class fix_primary_imports extends GhidraScript {

    public void run() throws Exception {
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator it = refManager.getReferenceIterator​(currentProgram.getMinAddress());

        while (it.hasNext()) {
            Reference ref = it.next();

            if (ref.getSource() == SourceType.IMPORTED) {
                println("Setting primary reference for " + ref.getFromAddress().toString());
                refManager.setPrimary(ref, true);
            }
        }
    }

}
