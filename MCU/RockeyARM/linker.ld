MEMORY {
	ROM (RX)  : ORIGIN = 0, LENGTH = 0x10000
	RAM (RW)  : ORIGIN = 0x68000000, LENGTH = 0x0400
	ZOD (RW)  : ORIGIN = 0x68000BF0, LENGTH = 0x0010
	BSP (RWX) : ORIGIN = 0x68001400, LENGTH = 0x0014
}

SECTIONS {
	.text : {
		KEEP(*(.world.start));
		*(.text .text.*);
		/* *(.rodata.CSWTCH .rodata.CSWTCH.*); */

		. = ALIGN(8); PROVIDE(__rodata_begin = .);
		*(.rodata .rodata.*);
		. = ALIGN(8); PROVIDE(__rodata_end = .);
	} > ROM

	.data : {
		. = ALIGN(8); PROVIDE(__data_begin = .);
        *(.data .data.*);
        . = ALIGN(8); PROVIDE(__data_end = .);
	} > RAM

	.bss (NOLOAD) : {
        . = ALIGN(8); PROVIDE(__bss_begin = .);
        *(.bss .bss.*);
        . = ALIGN(8); PROVIDE(__bss_end = .);
	} > ZOD

	g_FEI (NOLOAD) : {
		*(.ARM.__AT_0x68001400);
	} > BSP
}

ASSERT((_world_start == 0x40), "_world_start != 0x40");
ASSERT((__rodata_begin == __rodata_end), "__rodata_begin != __rodata_end");

ASSERT((__data_begin == __data_end), "__data_begin != __data_end");
ASSERT((__bss_end - __bss_begin <= 0x10), "__bss_end - __bss_begin > 0x10");
