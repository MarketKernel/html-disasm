// What MSVC's runtime gives an ARM64EC image and lld-link expects to find: the load configuration,
// pointing at the CHPE metadata, and the slots the loader fills with its x64-emulation helpers.
// The linker fills in the code map and the other tables the metadata names.
        .section .00cfg,"dr"
        .globl _load_config_used
        .p2align 3, 0
_load_config_used:
        .word 0x140                     // Size
        .fill 0x54, 1, 0
        .xword __security_cookie        // +0x58
        .fill 0x10, 1, 0
        .xword __guard_check_icall_fptr // +0x70
        .xword __guard_dispatch_icall_fptr
        .xword __guard_fids_table
        .xword __guard_fids_count
        .xword __guard_flags
        .xword 0
        .xword __guard_iat_table
        .xword __guard_iat_count
        .xword __guard_longjmp_table
        .xword __guard_longjmp_count
        .xword 0                        // +0xc0 DynamicValueRelocTable
        .xword __chpe_metadata          // +0xc8 CHPEMetadataPointer
        .fill 0x70, 1, 0

__guard_check_icall_fptr:
        .xword 0
__guard_dispatch_icall_fptr:
        .xword 0
        .irp name, dispatch_call_no_redirect, dispatch_ret, check_call, check_icall, get_x64_information, set_x64_information, check_icall_cfg, dispatch_fptr, helper3, helper4, helper5, helper6, helper7, helper8
        .globl __os_arm64x_\name
__os_arm64x_\name:
        .xword 0
        .endr
        .globl __os_arm64x_dispatch_icall
        .set __os_arm64x_dispatch_icall, __os_arm64x_check_icall

        .data
        .globl __chpe_metadata
        .p2align 3, 0
__chpe_metadata:
        .word 2                         // Version
        .rva __hybrid_code_map
        .word __hybrid_code_map_count
        .rva __x64_code_ranges_to_entry_points
        .rva __arm64x_redirection_metadata
        .rva __os_arm64x_dispatch_call_no_redirect
        .rva __os_arm64x_dispatch_ret
        .rva __os_arm64x_check_call
        .rva __os_arm64x_check_icall
        .rva __os_arm64x_check_icall_cfg
        .rva __arm64x_native_entrypoint
        .rva __hybrid_auxiliary_iat
        .word __x64_code_ranges_to_entry_points_count
        .word __arm64x_redirection_metadata_count
        .rva __os_arm64x_get_x64_information
        .rva __os_arm64x_set_x64_information
        .rva __arm64x_extra_rfe_table
        .word __arm64x_extra_rfe_table_size
        .rva __os_arm64x_dispatch_fptr
        .rva __hybrid_auxiliary_iat_copy
        .rva __hybrid_auxiliary_delayload_iat
        .rva __hybrid_auxiliary_delayload_iat_copy
        .word __hybrid_image_info_bitfield
        .rva __os_arm64x_helper3
        .rva __os_arm64x_helper4
        .rva __os_arm64x_helper5
        .rva __os_arm64x_helper6
        .rva __os_arm64x_helper7
        .rva __os_arm64x_helper8

__security_cookie:
        .xword 0
