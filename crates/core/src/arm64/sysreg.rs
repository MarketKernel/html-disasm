//! Names of the system registers a user-space program on macOS reads or
//! writes with mrs/msr. Anything else prints in the generic form LLVM uses,
//! S<op0>_<op1>_C<n>_C<m>_<op2>.

use super::types::Text;
use crate::sfmt;

fn known(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> Option<&'static str> {
    Some(match (op0, op1, crn, crm, op2) {
        (3, 3, 4, 2, 0) => "NZCV",
        (3, 3, 4, 2, 1) => "DAIF",
        (3, 3, 4, 2, 2) => "SVCR",
        (3, 3, 4, 2, 5) => "DIT",
        (3, 3, 4, 2, 6) => "SSBS",
        (3, 3, 4, 2, 7) => "TCO",
        (3, 3, 4, 4, 0) => "FPCR",
        (3, 3, 4, 4, 1) => "FPSR",
        (3, 3, 4, 4, 2) => "FPMR",
        (3, 3, 2, 5, 1) => "GCSPR_EL0",
        (3, 3, 13, 0, 2) => "TPIDR_EL0",
        (3, 3, 13, 0, 3) => "TPIDRRO_EL0",
        (3, 3, 13, 0, 5) => "TPIDR2_EL0",
        (3, 3, 14, 0, 0) => "CNTFRQ_EL0",
        (3, 3, 14, 0, 1) => "CNTPCT_EL0",
        (3, 3, 14, 0, 2) => "CNTVCT_EL0",
        (3, 3, 14, 0, 5) => "CNTPCTSS_EL0",
        (3, 3, 14, 0, 6) => "CNTVCTSS_EL0",
        (3, 3, 0, 0, 1) => "CTR_EL0",
        (3, 3, 0, 0, 7) => "DCZID_EL0",
        (3, 3, 2, 4, 0) => "RNDR",
        (3, 3, 2, 4, 1) => "RNDRRS",
        (3, 0, 0, 0, 0) => "MIDR_EL1",
        (3, 0, 0, 0, 5) => "MPIDR_EL1",
        (3, 0, 0, 0, 6) => "REVIDR_EL1",
        (3, 0, 0, 4, 0) => "ID_AA64PFR0_EL1",
        (3, 0, 0, 4, 1) => "ID_AA64PFR1_EL1",
        (3, 0, 0, 6, 0) => "ID_AA64ISAR0_EL1",
        (3, 0, 0, 6, 1) => "ID_AA64ISAR1_EL1",
        (3, 0, 0, 6, 2) => "ID_AA64ISAR2_EL1",
        (3, 0, 0, 7, 0) => "ID_AA64MMFR0_EL1",
        (3, 0, 4, 2, 0) => "SPSel",
        (3, 0, 4, 2, 2) => "CurrentEL",
        (3, 0, 4, 2, 3) => "PAN",
        (3, 0, 4, 2, 4) => "UAO",
        (3, 0, 13, 0, 4) => "TPIDR_EL1",
        _ => return None,
    })
}

pub fn sysreg_name(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> Text {
    match known(op0, op1, crn, crm, op2) {
        Some(name) => Text::from(name),
        None => sfmt!(Text, "S{}_{}_C{}_C{}_{}", op0, op1, crn, crm, op2),
    }
}
