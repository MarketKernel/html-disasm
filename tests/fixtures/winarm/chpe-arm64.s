// The native half of an ARM64X image needs a load configuration of its own; it points at nothing.
        .section .00cfg,"dr"
        .globl _load_config_used
        .p2align 3, 0
_load_config_used:
        .word 0x140
        .fill 0x13c, 1, 0
