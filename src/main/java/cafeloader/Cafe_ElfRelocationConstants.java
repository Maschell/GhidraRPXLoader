package cafeloader;

public class Cafe_ElfRelocationConstants {
	public static final int R_PPC_NONE = 0;
	public static final int R_PPC_ADDR32 = 1;
	public static final int R_PPC_ADDR16_LO = 4;
	public static final int R_PPC_ADDR16_HI = 5;
	public static final int R_PPC_ADDR16_HA = 6;
	public static final int R_PPC_REL24 = 10;
	public static final int R_PPC_REL14 = 11;
	public static final int R_PPC_DTPMOD32 = 68;
	public static final int R_PPC_DTPREL32 = 78;
	public static final int R_PPC_EMB_SDA21 = 109;
	public static final int R_PPC_EMB_RELSDA = 116;
	public static final int R_PPC_DIAB_SDA21_LO = 180;
	public static final int R_PPC_DIAB_SDA21_HI = 181;
	public static final int R_PPC_DIAB_SDA21_HA = 182;
	public static final int R_PPC_DIAB_RELSDA_LO = 183;
	public static final int R_PPC_DIAB_RELSDA_HI = 184;
	public static final int R_PPC_DIAB_RELSDA_HA = 185;
	public static final int R_PPC_GHS_REL16_HA = 251;
	public static final int R_PPC_GHS_REL16_HI = 252;
	public static final int R_PPC_GHS_REL16_LO = 253;

	// Masks for manipulating Power PC relocation targets
	public static final int PPC_WORD32 = 0xFFFFFFFF;
	public static final int PPC_WORD30 = 0xFFFFFFFC;
	public static final int PPC_LOW24 = 0x03FFFFFC;
	public static final int PPC_LOW14 = 0x0020FFFC;
	public static final int PPC_HALF16 = 0xFFFF;

	private Cafe_ElfRelocationConstants() {
		// no construct
	}
}
