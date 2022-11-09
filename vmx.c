/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2009-2019 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#include "vmx.h"

bool  in_smm = 0;
VMCS_CACHE *vm;


// extern VMCS_Mapping vmcs_map;
bool isMemTypeValidMTRR(unsigned memtype)
{
  switch(memtype) {
  case BX_MEMTYPE_UC:
  case BX_MEMTYPE_WC:
  case BX_MEMTYPE_WT:
  case BX_MEMTYPE_WP:
  case BX_MEMTYPE_WB:
    return true;
  default:
    return false;
  }
}

#if BX_CPU_LEVEL >= 6
bool isMemTypeValidPAT(unsigned memtype)
{
  return (memtype == 0x07) /* UC- */ || isMemTypeValidMTRR(memtype);
}

bool isValidMSR_PAT(uint64_t pat_val)
{
  // use packed register as 64-bit value with convinient accessors
  for (unsigned i=0; i<8; i++)
    if (! isMemTypeValidPAT((pat_val >> i*8) & 0xff)) return false;

  return true;
}
#endif

#if BX_SUPPORT_CET
const uint64_t BX_CET_SHADOW_STACK_ENABLED                   = (1 << 0);
const uint64_t BX_CET_SHADOW_STACK_WRITE_ENABLED             = (1 << 1);
const uint64_t BX_CET_ENDBRANCH_ENABLED                      = (1 << 2);
const uint64_t BX_CET_LEGACY_INDIRECT_BRANCH_TREATMENT       = (1 << 3);
const uint64_t BX_CET_ENABLE_NO_TRACK_INDIRECT_BRANCH_PREFIX = (1 << 4);
const uint64_t BX_CET_SUPPRESS_DIS                           = (1 << 5);
const uint64_t BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING      = (1 << 10);
const uint64_t BX_CET_WAIT_FOR_ENBRANCH                      = (1 << 11);

bool is_invalid_cet_control(bx_address val)
{
  if ((val & (BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING | BX_CET_WAIT_FOR_ENBRANCH)) == 
             (BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING | BX_CET_WAIT_FOR_ENBRANCH)) return true;

  if (val & 0x3c0) return true; // reserved bits check
  return false;
}
#endif


const char *segname[] = { "es", "cs", "ss", "ds", "fs", "gs" };
struct BxExceptionInfo exceptions_info[] = {
  /* DE */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 0 },
  /* DB */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 02 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // NMI
  /* BP */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
  /* OF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_TRAP,  0 },
  /* BR */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* UD */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* NM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* DF */ { BX_ET_DOUBLE_FAULT, BX_EXCEPTION_CLASS_FAULT, 1 },
             // coprocessor segment overrun (286,386 only)
  /* 09 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* TS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* NP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* SS */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* GP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* PF */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 1 },
  /* 15 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // reserved
  /* MF */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* AC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 1 },
  /* MC */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_ABORT, 0 },
  /* XM */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* VE */ { BX_ET_PAGE_FAULT,   BX_EXCEPTION_CLASS_FAULT, 0 },
  /* CP */ { BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1 },
  /* 22 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 23 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 24 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 25 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 26 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 27 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 28 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 29 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 },
  /* 30 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }, // FIXME: SVM #SF
  /* 31 */ { BX_ET_BENIGN,       BX_EXCEPTION_CLASS_FAULT, 0 }
};

////////////////////////////////////////////////////////////
// VMEXIT reasons for BX prints
////////////////////////////////////////////////////////////

// static const char *VMX_vmexit_reason_name[] =
// {
//   /*  0 */  "Exception or NMI",
//   /*  1 */  "External Interrupt",
//   /*  2 */  "Triple Fault",
//   /*  3 */  "INIT",
//   /*  4 */  "SIPI",
//   /*  5 */  "I/O SMI (SMM Vmexit)",
//   /*  6 */  "SMI (SMM Vmexit)",
//   /*  7 */  "Interrupt Window Exiting",
//   /*  8 */  "NMI Window Exiting",
//   /*  9 */  "Task Switch",
//   /* 10 */  "CPUID",
//   /* 11 */  "GETSEC",
//   /* 12 */  "HLT",
//   /* 13 */  "INVD",
//   /* 14 */  "INVLPG",
//   /* 15 */  "RDPMC",
//   /* 16 */  "RDTSC",
//   /* 17 */  "RSM",
//   /* 18 */  "VMCALL",
//   /* 19 */  "VMCLEAR",
//   /* 20 */  "VMLAUNCH",
//   /* 21 */  "VMPTRLD",
//   /* 22 */  "VMPTRST",
//   /* 23 */  "VMREAD",
//   /* 24 */  "VMRESUME",
//   /* 25 */  "VMWRITE",
//   /* 26 */  "VMXOFF",
//   /* 27 */  "VMXON",
//   /* 28 */  "CR Access",
//   /* 29 */  "DR Access",
//   /* 30 */  "I/O Instruction",
//   /* 31 */  "RDMSR",
//   /* 32 */  "WRMSR",
//   /* 33 */  "VMEntry failure due to invalid guest state",
//   /* 34 */  "VMEntry failure due to MSR loading",
//   /* 35 */  "Reserved35",
//   /* 36 */  "MWAIT",
//   /* 37 */  "MTF (Monitor Trap Flag)",
//   /* 38 */  "Reserved38",
//   /* 39 */  "MONITOR",
//   /* 40 */  "PAUSE",
//   /* 41 */  "VMEntry failure due to machine check",
//   /* 42 */  "Reserved42",
//   /* 43 */  "TPR Below Threshold",
//   /* 44 */  "APIC Access",
//   /* 45 */  "Virtualized EOI",
//   /* 46 */  "GDTR/IDTR Access",
//   /* 47 */  "LDTR/TR Access",
//   /* 48 */  "EPT Violation",
//   /* 49 */  "EPT Misconfiguration",
//   /* 50 */  "INVEPT",
//   /* 51 */  "RDTSCP",
//   /* 52 */  "VMX preemption timer expired",
//   /* 53 */  "INVVPID",
//   /* 54 */  "WBINVD",
//   /* 55 */  "XSETBV",
//   /* 56 */  "APIC Write Trap",
//   /* 57 */  "RDRAND",
//   /* 58 */  "INVPCID",
//   /* 59 */  "VMFUNC",
//   /* 60 */  "ENCLS",
//   /* 61 */  "RDSEED",
//   /* 62 */  "PML Log Full",
//   /* 63 */  "XSAVES",
//   /* 64 */  "XRSTORS",
//   /* 65 */  "Reserved65",
//   /* 66 */  "Sub-Page Protection",
//   /* 67 */  "UMWAIT",
//   /* 68 */  "TPAUSE",
//   /* 69 */  "Reserved69",
//   /* 70 */  "Reserved70",
//   /* 71 */  "Reserved71",
//   /* 72 */  "ENQCMD PASID Translation",
//   /* 73 */  "ENQCMDS PASID Translation",
// };

#define VMENTRY_INJECTING_EVENT(vmentry_interr_info) (vmentry_interr_info & 0x80000000)

#define VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PINBASED_CTRLS_LO : VMX_MSR_VMX_PINBASED_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PINBASED_CTRLS_HI : VMX_MSR_VMX_PINBASED_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_LO : VMX_MSR_VMX_PROCBASED_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_HI : VMX_MSR_VMX_PROCBASED_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_LO : VMX_MSR_VMX_VMEXIT_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_HI : VMX_MSR_VMX_VMEXIT_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_LO : VMX_MSR_VMX_VMENTRY_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_HI : VMX_MSR_VMX_VMENTRY_CTRLS_HI)

#define BX_ERROR(...) { ; }
#define BX_DEBUG(...) { ; }

#define BX_CONST64(x)  (x)

#if BX_SUPPORT_X86_64
static inline bool IsCanonical(bx_address offset)
{
  return ((uint64_t)((((int64_t)(offset)) >> (BX_LIN_ADDRESS_WIDTH-1)) + 1) < 2);
}
#endif

static inline bool IsValidPhyAddr(bx_phy_address addr)
{
  return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

static inline bool IsValidPageAlignedPhyAddr(bx_phy_address addr)
{
  return ((addr & (BX_PHY_ADDRESS_RESERVED_BITS | 0xfff)) == 0);
}


#if BX_SUPPORT_VMX >= 2
bool is_eptptr_valid(uint64_t eptptr)
{
  // [2:0] EPT paging-structure memory type
  //       0 = Uncacheable (UC)
  //       6 = Write-back (WB)
  uint32_t memtype = eptptr & 7;
  if (memtype != BX_MEMTYPE_UC && memtype != BX_MEMTYPE_WB) return 0;

  // [5:3] This value is 1 less than the EPT page-walk length
  uint32_t walk_length = (eptptr >> 3) & 7;
  if (walk_length != 3) return 0;

  // [6]   EPT A/D Enable
  if (! (VMX_MSR_VMX_EPT_VPID_CAP & 1<<21)) {
    if (eptptr & 0x40) {
      BX_ERROR("is_eptptr_valid: EPTPTR A/D enabled when not supported by CPU\n");
      return 0;
    }
  }

  // [7]   CET: Enable supervisor shadow stack control
#if BX_SUPPORT_CET
  if (! (VMX_MSR_VMX_BASIC & (uint64_t)1<<56)) {
    if (eptptr & 0x80) {
      BX_ERROR("is_eptptr_valid: EPTPTR CET supervisor shadow stack control bit enabled when not supported by CPU\n");
      return 0;
    }
  }
#endif

#define BX_EPTPTR_RESERVED_BITS 0xf00 /* bits 11:8 are reserved */
  if (eptptr & BX_EPTPTR_RESERVED_BITS) {
    BX_ERROR("is_eptptr_valid: EPTPTR reserved bits set\n");
    return 0;
  }

  if (! IsValidPhyAddr(eptptr)) return 0;
  return 1;
}
#endif

enum VMX_error_code VMenterLoadCheckVmControls(void)
{

  //
  // Load VM-execution control fields to VMCS Cache
  //

  vm->vmexec_ctrls1 = vmread(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS);
  vm->vmexec_ctrls2 = vmread(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS);
  if (VMEXIT(VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS))
    vm->vmexec_ctrls3 = vmread(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS);
  else
    vm->vmexec_ctrls3 = 0;
  vm->vm_exceptions_bitmap = vmread(VMCS_32BIT_CONTROL_EXECUTION_BITMAP);
  vm->vm_pf_mask = vmread(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MASK);
  vm->vm_pf_match = vmread(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MATCH);
  vm->vm_cr0_mask = vmread(VMCS_CONTROL_CR0_GUEST_HOST_MASK);
  vm->vm_cr4_mask = vmread(VMCS_CONTROL_CR4_GUEST_HOST_MASK);
  vm->vm_cr0_read_shadow = vmread(VMCS_CONTROL_CR0_READ_SHADOW);
  vm->vm_cr4_read_shadow = vmread(VMCS_CONTROL_CR4_READ_SHADOW);

  vm->vm_cr3_target_cnt = vmread(VMCS_32BIT_CONTROL_CR3_TARGET_COUNT);
  for (int n=0; n<VMX_CR3_TARGET_MAX_CNT; n++)
    vm->vm_cr3_target_value[n] = vmread(VMCS_CR3_TARGET0 + 2*n);

  //
  // Check VM-execution control fields
  //

  if (~vm->vmexec_ctrls1 & VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed 0-settings\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
  if (vm->vmexec_ctrls1 & ~VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed 1-settings [0x%08x]\n", vm->vmexec_ctrls1 & ~VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (~vm->vmexec_ctrls2 & VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed 0-settings\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
  if (vm->vmexec_ctrls2 & ~VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed 1-settings [0x%08x]\n", vm->vmexec_ctrls2 & ~VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (~vm->vmexec_ctrls3 & VMX_MSR_VMX_PROCBASED_CTRLS2_LO) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX secondary proc-based controls allowed 0-settings\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
  if (vm->vmexec_ctrls3 & ~VMX_MSR_VMX_PROCBASED_CTRLS2_HI) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX secondary controls allowed 1-settings [0x%08x]\n", vm->vmexec_ctrls3 & ~VMX_MSR_VMX_PROCBASED_CTRLS2_HI);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (vm->vm_cr3_target_cnt > ((VMX_MSR_MISC >> 16)&0xf)) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: too may CR3 targets %d\n", vm->vm_cr3_target_cnt);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_IO_BITMAPS) {
     vm->io_bitmap_addr[0] = vmread(VMCS_64BIT_CONTROL_IO_BITMAP_A);
     vm->io_bitmap_addr[1] = vmread(VMCS_64BIT_CONTROL_IO_BITMAP_B);
     // I/O bitmaps control enabled
     for (int bitmap=0; bitmap < 2; bitmap++) {
       if (! IsValidPageAlignedPhyAddr(vm->io_bitmap_addr[bitmap])) {
         BX_ERROR("VMFAIL: VMCS EXEC CTRL: I/O bitmap %c phy addr malformed\n", 'A' + bitmap);
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
       }
     }
  }

  if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_MSR_BITMAPS) {
     // MSR bitmaps control enabled
     vm->msr_bitmap_addr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_MSR_BITMAPS);
     if (! IsValidPageAlignedPhyAddr(vm->msr_bitmap_addr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: MSR bitmap phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (! (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_NMI_EXITING)) {
     if (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: misconfigured virtual NMI control\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (! (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI)) {
     if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_NMI_WINDOW_EXITING) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: misconfigured virtual NMI control\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }
#if BX_SUPPORT_VMX >= 2
  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
     vm->vmread_bitmap_addr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR);
     if (! IsValidPageAlignedPhyAddr(vm->vmread_bitmap_addr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMREAD bitmap phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
     vm->vmwrite_bitmap_addr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR);
     if (! IsValidPageAlignedPhyAddr(vm->vmwrite_bitmap_addr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMWRITE bitmap phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_VIOLATION_EXCEPTION) {
     vm->ve_info_addr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR);
     if (! IsValidPageAlignedPhyAddr(vm->ve_info_addr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: broken #VE information address\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }
#endif

#if BX_SUPPORT_X86_64
  if (vm->vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_TPR_SHADOW) {
     vm->virtual_apic_page_addr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR);
     if (! IsValidPageAlignedPhyAddr(vm->virtual_apic_page_addr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: virtual apic phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

#if BX_SUPPORT_VMX >= 2
     if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY) {
       if (! PIN_VMEXIT(VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT)) {
         BX_ERROR("VMFAIL: VMCS EXEC CTRL: virtual interrupt delivery must be set together with external interrupt exiting\n");
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
       }

       for (int reg = 0; reg < 8; reg++) {
         vm->eoi_exit_bitmap[reg] = vmread(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
       }

       uint16_t guest_interrupt_status = vmread(VMCS_16BIT_GUEST_INTERRUPT_STATUS);
       vm->rvi = guest_interrupt_status & 0xff;
       vm->svi = guest_interrupt_status >> 8;
     }
     else
#endif
     {
       vm->vm_tpr_threshold = vmread(VMCS_32BIT_CONTROL_TPR_THRESHOLD);

       if (vm->vm_tpr_threshold & 0xfffffff0) {
         BX_ERROR("VMFAIL: VMCS EXEC CTRL: TPR threshold too big\n");
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
       }

       if (! (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES)) {
         uint8_t tpr_shadow = (VMX_Read_Virtual_APIC_VTPR() >> 4) & 0xf;
         if (vm->vm_tpr_threshold > tpr_shadow) {
           BX_ERROR("VMFAIL: VMCS EXEC CTRL: TPR threshold > TPR shadow\n");
           return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
         }
       }
     }
  }
#if BX_SUPPORT_VMX >= 2
  else { // TPR shadow is disabled
     if (vm->vmexec_ctrls3 & (VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE |
                              VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS |
                              VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY))
     {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: apic virtualization is enabled without TPR shadow\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }
#endif // BX_SUPPORT_VMX >= 2

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES) {
     vm->apic_access_page = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR);
     if (! IsValidPageAlignedPhyAddr(vm->apic_access_page)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: apic access page phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

#if BX_SUPPORT_VMX >= 2
     if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: virtualize X2APIC mode enabled together with APIC access virtualization\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
#endif
  }

#if BX_SUPPORT_VMX >= 2
  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) {
     vm->eptptr = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_EPTPTR);
     if (! is_eptptr_valid(vm->eptptr)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: invalid EPTPTR value\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }
  else {
     if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: unrestricted guest without EPT\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VPID_ENABLE) {
     vm->vpid = vmread(VMCS_16BIT_CONTROL_VPID);
     if (vm->vpid == 0) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: guest VPID == 0\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PAUSE_LOOP_VMEXIT) {
     vm->ple.pause_loop_exiting_gap = vmread(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_GAP);
     vm->ple.pause_loop_exiting_window = vmread(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_WINDOW);
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMFUNC_ENABLE)
    vm->vmfunc_ctrls = vmread(VMCS_64BIT_CONTROL_VMFUNC_CTRLS);
  else
    vm->vmfunc_ctrls = 0;

  if (vm->vmfunc_ctrls & ~VMX_VMFUNC_CTRL1_SUPPORTED_BITS) {
     BX_ERROR("VMFAIL: VMCS VM Functions control reserved bits set\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (vm->vmfunc_ctrls & VMX_VMFUNC_EPTP_SWITCHING_MASK) {
     if ((vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
       BX_ERROR("VMFAIL: VMFUNC EPTP-SWITCHING: EPT disabled\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

     vm->eptp_list_address = vmread(VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS);
     if (! IsValidPageAlignedPhyAddr(vm->eptp_list_address)) {
       BX_ERROR("VMFAIL: VMFUNC EPTP-SWITCHING: eptp list phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PML_ENABLE) {
    if ((vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: PML is enabled without EPT\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }

    vm->pml_address = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_PML_ADDRESS);
    if (! IsValidPageAlignedPhyAddr(vm->pml_address)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: PML base phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
    vm->pml_index = vmread(VMCS_16BIT_GUEST_PML_INDEX);
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_SUBPAGE_WR_PROTECT_CTRL) {
    if ((vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: SPP is enabled without EPT\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }

    vm->spptp = (bx_phy_address) vmread(VMCS_64BIT_CONTROL_SPPTP);
    if (! IsValidPageAlignedPhyAddr(vm->spptp)) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: SPP base phy addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_XSAVES_XRSTORS)
     vm->xss_exiting_bitmap = vmread(VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP);
  else
     vm->xss_exiting_bitmap = 0;
#endif

#endif // BX_SUPPORT_X86_64

  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_TSC_SCALING) {
     if ((vm->tsc_multiplier = vmread(VMCS_64BIT_CONTROL_TSC_MULTIPLIER)) == 0) {
       BX_ERROR("VMFAIL: VMCS EXEC CTRL: TSC multiplier should be non zero\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  //
  // Load VM-exit control fields to VMCS Cache
  //

  vm->vmexit_ctrls = vmread(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS);
  vm->vmexit_msr_store_cnt = vmread(VMCS_32BIT_CONTROL_VMEXIT_MSR_STORE_COUNT);
  vm->vmexit_msr_load_cnt = vmread(VMCS_32BIT_CONTROL_VMEXIT_MSR_LOAD_COUNT);

  //
  // Check VM-exit control fields
  //

  if (~vm->vmexit_ctrls & VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 0-settings\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
  if (vm->vmexit_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 1-settings [0x%08x]\n", vm->vmexit_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

#if BX_SUPPORT_VMX >= 2
  if ((~vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VMX_PREEMPTION_TIMER_VMEXIT) && (vm->vmexit_ctrls & VMX_VMEXIT_CTRL1_STORE_VMX_PREEMPTION_TIMER)) {
     BX_ERROR("VMFAIL: save_VMX_preemption_timer VMEXIT control is set but VMX_preemption_timer VMEXEC control is clear\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
#endif

  if (vm->vmexit_msr_store_cnt > 0) {
     vm->vmexit_msr_store_addr = vmread(VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR);
     if ((vm->vmexit_msr_store_addr & 0xf) != 0 || ! IsValidPhyAddr(vm->vmexit_msr_store_addr)) {
       BX_ERROR("VMFAIL: VMCS VMEXIT CTRL: msr store addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

     uint64_t last_byte = vm->vmexit_msr_store_addr + (vm->vmexit_msr_store_cnt * 16) - 1;
     if (! IsValidPhyAddr(last_byte)) {
       BX_ERROR("VMFAIL: VMCS VMEXIT CTRL: msr store addr too high\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmexit_msr_load_cnt > 0) {
     vm->vmexit_msr_load_addr = vmread(VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR);
     if ((vm->vmexit_msr_load_addr & 0xf) != 0 || ! IsValidPhyAddr(vm->vmexit_msr_load_addr)) {
       BX_ERROR("VMFAIL: VMCS VMEXIT CTRL: msr load addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

     uint64_t last_byte = (uint64_t) vm->vmexit_msr_load_addr + (vm->vmexit_msr_load_cnt * 16) - 1;
     if (! IsValidPhyAddr(last_byte)) {
       BX_ERROR("VMFAIL: VMCS VMEXIT CTRL: msr load addr too high\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  //
  // Load VM-entry control fields to VMCS Cache
  //

  vm->vmentry_ctrls = vmread(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS);
  vm->vmentry_msr_load_cnt = vmread(VMCS_32BIT_CONTROL_VMENTRY_MSR_LOAD_COUNT);

  //
  // Check VM-entry control fields
  //

  if (~vm->vmentry_ctrls & VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 0-settings\n");
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }
  if (vm->vmentry_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI) {
     BX_ERROR("VMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 1-settings [0x%08x]\n", vm->vmentry_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI);
     return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
  }

  if (vm->vmentry_ctrls & VMX_VMENTRY_CTRL1_DEACTIVATE_DUAL_MONITOR_TREATMENT) {
     if (! in_smm) {
       BX_ERROR("VMFAIL: VMENTRY from outside SMM with dual-monitor treatment enabled\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  if (vm->vmentry_msr_load_cnt > 0) {
     vm->vmentry_msr_load_addr = vmread(VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR);
     if ((vm->vmentry_msr_load_addr & 0xf) != 0 || ! IsValidPhyAddr(vm->vmentry_msr_load_addr)) {
       BX_ERROR("VMFAIL: VMCS VMENTRY CTRL: msr load addr malformed\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

     uint64_t last_byte = vm->vmentry_msr_load_addr + (vm->vmentry_msr_load_cnt * 16) - 1;
     if (! IsValidPhyAddr(last_byte)) {
       BX_ERROR("VMFAIL: VMCS VMENTRY CTRL: msr load addr too high\n");
       return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }
  }

  //
  // Check VM-entry event injection info
  //

  vm->vmentry_interr_info = vmread(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO);
  vm->vmentry_excep_err_code = vmread(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE);
  vm->vmentry_instr_length = vmread(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH);

  if (VMENTRY_INJECTING_EVENT(vm->vmentry_interr_info)) {

     /* the VMENTRY injecting event to the guest */
     unsigned vector = vm->vmentry_interr_info & 0xff;
     unsigned event_type = (vm->vmentry_interr_info >>  8) & 7;
     unsigned push_error = (vm->vmentry_interr_info >> 11) & 1;
     unsigned error_code = push_error ? vm->vmentry_excep_err_code : 0;

     unsigned push_error_reference = 0;
     if (event_type == BX_HARDWARE_EXCEPTION && vector < BX_CPU_HANDLED_EXCEPTIONS)
        push_error_reference = exceptions_info[vector].push_error;
#if BX_SUPPORT_CET
    //  if (! BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_CET)) {
      if (!(VMX_MSR_VMX_BASIC & (uint64_t)1<<56)) {
        if (vector == BX_CP_EXCEPTION) push_error_reference = false;
     }
#endif     

     if (vm->vmentry_interr_info & 0x7ffff000) {
        BX_ERROR("VMFAIL: VMENTRY broken interruption info field\n");
        return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

     switch (event_type) {
       case BX_EXTERNAL_INTERRUPT:
         break;

       case BX_NMI:
         if (vector != 2) {
           BX_ERROR("VMFAIL: VMENTRY bad injected event vector %d\n", vector);
           return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
         }
/*
         // injecting NMI
         if (vm->vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
           if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED) {
             BX_ERROR("VMFAIL: VMENTRY injected NMI vector when blocked by NMI in interruptibility state\n", vector);
             return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
           }
         }
*/
         break;

       case BX_HARDWARE_EXCEPTION:
         if (vector > 31) {
           BX_ERROR("VMFAIL: VMENTRY bad injected event vector %d\n", vector);
           return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
         }
         break;

       case BX_SOFTWARE_INTERRUPT:
       case BX_PRIVILEGED_SOFTWARE_INTERRUPT:
       case BX_SOFTWARE_EXCEPTION:
        //  if ((vm->vmentry_instr_length == 0 && !BX_SUPPORT_VMX_EXTENSION(BX_VMX_SW_INTERRUPT_INJECTION_ILEN_0)) || 
         if ((vm->vmentry_instr_length == 0 && !(VMX_MSR_MISC & 1<<30)) || 
              vm->vmentry_instr_length > 15)
         {
           BX_ERROR("VMFAIL: VMENTRY bad injected event instr length\n");
           return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
         }
         break;

       case 7: /* MTF */
        //  if (BX_SUPPORT_VMX_EXTENSION(BX_VMX_MONITOR_TRAP_FLAG)) {
           if (vector != 0) {
             BX_ERROR("VMFAIL: VMENTRY bad MTF injection with vector=%d\n", vector);
             return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
           }
        //  }
         break;

       default:
         BX_ERROR("VMFAIL: VMENTRY bad injected event type %d\n", event_type);
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
     }

#if BX_SUPPORT_VMX >= 2
     if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
       unsigned protected_mode_guest = (uint32_t) vmread(VMCS_GUEST_CR0) & BX_CR0_PE_MASK;
       if (! protected_mode_guest) push_error_reference = 0;
     }
#endif

    if (! (VMX_MSR_VMX_BASIC & (uint64_t)1<<56)) {
       // CET added new #CP exception with error code but legacy software assumed that this vector have no error code.
       // Therefore CET enabled processors do not check the error code anymore and able to deliver a hardware
       // exception with or without an error code, regardless of vector as indicated in VMX_MSR_VMX_BASIC[56]
       if (push_error != push_error_reference) {
         BX_ERROR("VMFAIL: VMENTRY injected event vector %d broken error code\n", vector);
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
       }
     }

     if (push_error) {
       if (error_code & 0xffff0000) {
         BX_ERROR("VMFAIL: VMENTRY bad error code 0x%08x for injected event %d\n", error_code, vector);
         return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
       }
     }
  }

  return VMXERR_NO_ERROR;
}

enum VMX_error_code VMenterLoadCheckHostState(void)
{
  VMCS_HOST_STATE *host_state = &vm->host_state;
  bool x86_64_host = false, x86_64_guest = false;

  //
  // VM Host State Checks Related to Address-Space Size
  //

  uint32_t vmexit_ctrls = vm->vmexit_ctrls;
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_HOST_ADDR_SPACE_SIZE) {
     x86_64_host = true;
  }
  uint32_t vmentry_ctrls = vm->vmentry_ctrls;
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
     x86_64_guest = true;
  }

#if BX_SUPPORT_X86_64
  if (__rdmsr1(MSR_EFER) & 1<<10) { // is_long_mode
     if (! x86_64_host) {
        BX_ERROR("VMFAIL: VMCS x86-64 host control invalid on VMENTRY\n");
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
  }
  else
#endif
  {
     if (x86_64_host || x86_64_guest) {
        BX_ERROR("VMFAIL: VMCS x86-64 guest(%d)/host(%d) controls invalid on VMENTRY\n", x86_64_guest, x86_64_host);
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
  }

  //
  // Load and Check VM Host State to VMCS Cache
  //

  host_state->cr0 = (bx_address) vmread(VMCS_HOST_CR0);
  if (~host_state->cr0 & VMX_MSR_CR0_FIXED0) {
     BX_ERROR("VMFAIL: VMCS host state invalid CR0 0x%08x\n", (uint32_t) host_state->cr0);
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (host_state->cr0 & ~VMX_MSR_CR0_FIXED1) {
     BX_ERROR("VMFAIL: VMCS host state invalid CR0 0x%08x\n", (uint32_t) host_state->cr0);
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->cr3 = (bx_address) vmread(VMCS_HOST_CR3);
#if BX_SUPPORT_X86_64
  if (! IsValidPhyAddr(host_state->cr3)) {
     BX_ERROR("VMFAIL: VMCS host state invalid CR3\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->cr4 = (bx_address) vmread(VMCS_HOST_CR4);
  if (~host_state->cr4 & VMX_MSR_CR4_FIXED0) {
     BX_ERROR("VMFAIL: VMCS host state invalid CR4 0x%x", host_state->cr4);
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (host_state->cr4 & ~VMX_MSR_CR4_FIXED1) {
     BX_ERROR("VMFAIL: VMCS host state invalid CR4 0x%x", host_state->cr4);
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  for(int n=0; n<6; n++) {
     host_state->segreg_selector[n] = vmread(VMCS_16BIT_HOST_ES_SELECTOR + 2*n);
     if (host_state->segreg_selector[n] & 7) {
        BX_ERROR("VMFAIL: VMCS host segreg %d TI/RPL != 0\n", n);
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
  }

  if (host_state->segreg_selector[BX_SEG_REG_CS] == 0) {
     BX_ERROR("VMFAIL: VMCS host CS selector 0\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (! x86_64_host && host_state->segreg_selector[BX_SEG_REG_SS] == 0) {
     BX_ERROR("VMFAIL: VMCS host SS selector 0\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->tr_selector = vmread(VMCS_16BIT_HOST_TR_SELECTOR);
  if (! host_state->tr_selector || (host_state->tr_selector & 7) != 0) {
     BX_ERROR("VMFAIL: VMCS invalid host TR selector\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->tr_base = (bx_address) vmread(VMCS_HOST_TR_BASE);
#if BX_SUPPORT_X86_64
  if (! IsCanonical(host_state->tr_base)) {
     BX_ERROR("VMFAIL: VMCS host TR BASE non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->fs_base = (bx_address) vmread(VMCS_HOST_FS_BASE);
  host_state->gs_base = (bx_address) vmread(VMCS_HOST_GS_BASE);
#if BX_SUPPORT_X86_64
  if (! IsCanonical(host_state->fs_base)) {
     BX_ERROR("VMFAIL: VMCS host FS BASE non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (! IsCanonical(host_state->gs_base)) {
     BX_ERROR("VMFAIL: VMCS host GS BASE non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->gdtr_base = (bx_address) vmread(VMCS_HOST_GDTR_BASE);
  host_state->idtr_base = (bx_address) vmread(VMCS_HOST_IDTR_BASE);
#if BX_SUPPORT_X86_64
  if (! IsCanonical(host_state->gdtr_base)) {
     BX_ERROR("VMFAIL: VMCS host GDTR BASE non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (! IsCanonical(host_state->idtr_base)) {
     BX_ERROR("VMFAIL: VMCS host IDTR BASE non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->sysenter_esp_msr = (bx_address) vmread(VMCS_HOST_IA32_SYSENTER_ESP_MSR);
  host_state->sysenter_eip_msr = (bx_address) vmread(VMCS_HOST_IA32_SYSENTER_EIP_MSR);
  host_state->sysenter_cs_msr = (uint16_t) vmread(VMCS_32BIT_HOST_IA32_SYSENTER_CS_MSR);

#if BX_SUPPORT_X86_64
  if (! IsCanonical(host_state->sysenter_esp_msr)) {
     BX_ERROR("VMFAIL: VMCS host SYSENTER_ESP_MSR non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (! IsCanonical(host_state->sysenter_eip_msr)) {
     BX_ERROR("VMFAIL: VMCS host SYSENTER_EIP_MSR non canonical\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

#if BX_SUPPORT_VMX >= 2
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_PAT_MSR) {
    host_state->pat_msr = vmread(VMCS_64BIT_HOST_IA32_PAT);
    if (! isValidMSR_PAT(host_state->pat_msr)) {
      BX_ERROR("VMFAIL: invalid Memory Type in host MSR_PAT\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

  host_state->rsp = (bx_address) vmread(VMCS_HOST_RSP);
  host_state->rip = (bx_address) vmread(VMCS_HOST_RIP);

#if BX_SUPPORT_CET
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_HOST_CET_STATE) {
    host_state->msr_ia32_s_cet = vmread(VMCS_HOST_IA32_S_CET);
    if (!IsCanonical(host_state->msr_ia32_s_cet) || (!x86_64_host && GET32H(host_state->msr_ia32_s_cet))) {
       BX_ERROR("VMFAIL: VMCS host IA32_S_CET/EB_LEG_BITMAP_BASE non canonical or invalid\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    if (is_invalid_cet_control(host_state->msr_ia32_s_cet)) {
       BX_ERROR("VMFAIL: VMCS host IA32_S_CET invalid\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    host_state->ssp = vmread(VMCS_HOST_SSP);
    if (!IsCanonical(host_state->ssp) || (!x86_64_host && GET32H(host_state->ssp))) {
       BX_ERROR("VMFAIL: VMCS host SSP non canonical or invalid\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
    if ((host_state->ssp & 0x3) != 0) {
       BX_ERROR("VMFAIL: VMCS host SSP[1:0] not zero\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    host_state->interrupt_ssp_table_address = vmread(VMCS_HOST_INTERRUPT_SSP_TABLE_ADDR);
    if (!IsCanonical(host_state->interrupt_ssp_table_address)) {
       BX_ERROR("VMFAIL: VMCS host INTERRUPT_SSP_TABLE_ADDR non canonical or invalid\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    if ((host_state->cr4 & BX_CR4_CET_MASK) && (host_state->cr0 & BX_CR0_WP_MASK) == 0) {
      BX_ERROR("FAIL: VMCS host CR4.CET=1 when CR0.WP=0\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

#define GET32H(val64) ((uint32_t)(((uint64_t)(val64)) >> 32))

#if BX_SUPPORT_PKEYS
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_HOST_PKRS) {
    host_state->pkrs = vmread(VMCS_64BIT_HOST_IA32_PKRS);
    if (GET32H(host_state->pkrs) != 0) {
      BX_ERROR("VMFAIL: invalid host IA32_PKRS value\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

#if BX_SUPPORT_X86_64

#if BX_SUPPORT_VMX >= 2
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_EFER_MSR) {
    host_state->efer_msr = vmread(VMCS_64BIT_HOST_IA32_EFER);
    if (host_state->efer_msr & ~__rdmsr1(MSR_EFER)) {
      BX_ERROR("VMFAIL: VMCS host EFER reserved bits set !\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
    bool lme = (host_state->efer_msr >>  8) & 0x1;
    bool lma = (host_state->efer_msr >> 10) & 0x1;
    if (lma != lme || lma != x86_64_host) {
      BX_ERROR("VMFAIL: VMCS host EFER (0x%08x) inconsistent value !\n", (uint32_t) host_state->efer_msr);
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

  if (x86_64_host) {
     if ((host_state->cr4 & BX_CR4_PAE_MASK) == 0) {
        BX_ERROR("VMFAIL: VMCS host CR4.PAE=0 with x86-64 host\n");
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
     if (! IsCanonical(host_state->rip)) {
        BX_ERROR("VMFAIL: VMCS host RIP non-canonical\n");
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
  }
  else {
     if (GET32H(host_state->rip) != 0) {
        BX_ERROR("VMFAIL: VMCS host RIP > 32 bit\n");
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
     if (host_state->cr4 & BX_CR4_PCIDE_MASK) {
        BX_ERROR("VMFAIL: VMCS host CR4.PCIDE set\n");
        return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
     }
  }
#endif

  return VMXERR_NO_ERROR;
}

bool IsLimitAccessRightsConsistent(uint32_t limit, uint32_t ar)
{
  bool g = (ar >> 15) & 1;

  // access rights reserved bits set
  if (ar & 0xfffe0f00) return 0;

  if (g) {
    // if any of the bits in limit[11:00] are '0 <=> G must be '0
    if ((limit & 0xfff) != 0xfff)
       return 0;
  }
  else {
    // if any of the bits in limit[31:20] are '1 <=> G must be '1
    if ((limit & 0xfff00000) != 0)
       return 0;
  }

  return 1;
}
static uint32_t rotate_r(uint32_t val_32)
{
  return (val_32 >> 8) | (val_32 << 24);
}

// AR.NULL is bit 16
static uint32_t vmx_unpack_ar_field(uint32_t ar_field, enum VMCS_Access_Rights_Format access_rights_format)
{
  switch (access_rights_format) {
  case VMCS_AR_ROTATE:
    ar_field = rotate_r(ar_field);
    break;
  case VMCS_AR_PACK:
    // zero out bit 16
    ar_field &= 0xfffeffff;
    // Null bit to be copied back from bit 11 to bit 16
    ar_field |= ((ar_field & 0x00000800) << 5);
    // zero out the bit 17 to bit 31
    ar_field &= 0x0001ffff;
    // bits 8 to 11 should be set to 0
    ar_field &= 0xfffff0ff;
    break;
  default:
    break;
  }

  return ar_field;
}
void parse_selector(uint16_t raw_selector, bx_selector_t *selector)
{
  selector->value = raw_selector;
  selector->index = raw_selector >> 3;
  selector->ti    = (raw_selector >> 2) & 0x01;
  selector->rpl   = raw_selector & 0x03;
}
bool set_segment_ar_data(bx_segment_reg_t *seg, bool valid,
            uint16_t raw_selector, bx_address base, uint32_t limit_scaled, uint16_t ar_data)
{
  parse_selector(raw_selector, &seg->selector);

  bx_descriptor_t *d = &seg->cache;

  d->p        = (ar_data >> 7) & 0x1;
  d->dpl      = (ar_data >> 5) & 0x3;
  d->segment  = (ar_data >> 4) & 0x1;
  d->type     = (ar_data & 0x0f);

  d->valid    = valid;

  if (d->segment || !valid) { /* data/code segment descriptors */
    d->u.segment.g     = (ar_data >> 15) & 0x1;
    d->u.segment.d_b   = (ar_data >> 14) & 0x1;
#if BX_SUPPORT_X86_64
    d->u.segment.l     = (ar_data >> 13) & 0x1;
#endif
    d->u.segment.avl   = (ar_data >> 12) & 0x1;

    d->u.segment.base  = base;
    d->u.segment.limit_scaled = limit_scaled;
  }
  else {
    switch(d->type) {
      case BX_SYS_SEGMENT_LDT:
      case BX_SYS_SEGMENT_AVAIL_286_TSS:
      case BX_SYS_SEGMENT_BUSY_286_TSS:
      case BX_SYS_SEGMENT_AVAIL_386_TSS:
      case BX_SYS_SEGMENT_BUSY_386_TSS:
        d->u.segment.avl   = (ar_data >> 12) & 0x1;
        d->u.segment.d_b   = (ar_data >> 14) & 0x1;
        d->u.segment.g     = (ar_data >> 15) & 0x1;
        d->u.segment.base  = base;
        d->u.segment.limit_scaled = limit_scaled;
        break;

      default:
        BX_ERROR("set_segment_ar_data(): case %d unsupported, valid=%d\n", (unsigned) d->type, d->valid);
    }
  }

  return d->valid;
}

const uint32_t EFlagsCFMask   = (1 <<  0);
const uint32_t EFlagsPFMask   = (1 <<  2);
const uint32_t EFlagsAFMask   = (1 <<  4);
const uint32_t EFlagsZFMask   = (1 <<  6);
const uint32_t EFlagsSFMask   = (1 <<  7);
const uint32_t EFlagsTFMask   = (1 <<  8);
const uint32_t EFlagsIFMask   = (1 <<  9);
const uint32_t EFlagsDFMask   = (1 << 10);
const uint32_t EFlagsOFMask   = (1 << 11);
const uint32_t EFlagsIOPLMask = (3 << 12);
const uint32_t EFlagsNTMask   = (1 << 14);
const uint32_t EFlagsRFMask   = (1 << 16);
const uint32_t EFlagsVMMask   = (1 << 17);
const uint32_t EFlagsACMask   = (1 << 18);
const uint32_t EFlagsVIFMask  = (1 << 19);
const uint32_t EFlagsVIPMask  = (1 << 20);
const uint32_t EFlagsIDMask   = (1 << 21);

uint32_t VMenterLoadCheckGuestState(uint32_t *qualification, uint64_t current_vmcsptr, uint64_t vmxonptr)
{
  int n;
  VMCS_GUEST_STATE guest;

  *qualification = VMENTER_ERR_NO_ERROR;

  //
  // Load and Check Guest State from VMCS
  //
  guest.rflags = vmread(VMCS_GUEST_RFLAGS);
  // RFLAGS reserved bits [63:22], bit 15, bit 5, bit 3 must be zero
  if (guest.rflags & BX_CONST64(0xFFFFFFFFFFC08028)) {
     BX_ERROR("VMENTER FAIL: RFLAGS reserved bits are set\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  // RFLAGS[1] must be always set
  if ((guest.rflags & 0x2) == 0) {
     BX_ERROR("VMENTER FAIL: RFLAGS[1] cleared\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  bool v8086_guest = false;
  if (guest.rflags & EFlagsVMMask)
     v8086_guest = true;

  bool x86_64_guest = false; // can't be 1 if X86_64 is not supported (checked before)
  uint32_t vmentry_ctrls = vm->vmentry_ctrls;
#if BX_SUPPORT_X86_64
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
     BX_DEBUG("VMENTER to x86-64 guest\n");
     x86_64_guest = true;
  }
#endif

  if (x86_64_guest && v8086_guest) {
     BX_ERROR("VMENTER FAIL: Enter to x86-64 guest with RFLAGS.VM\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  guest.cr0 = vmread(VMCS_GUEST_CR0);

#if BX_SUPPORT_VMX >= 2
  if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
     if (~guest.cr0 & (VMX_MSR_CR0_FIXED0 & ~(BX_CR0_PE_MASK | BX_CR0_PG_MASK))) {
        BX_ERROR("VMENTER FAIL: VMCS guest invalid CR0\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }

     bool pe = (guest.cr0 & BX_CR0_PE_MASK) != 0;
     bool pg = (guest.cr0 & BX_CR0_PG_MASK) != 0;
     if (pg && !pe) {
        BX_ERROR("VMENTER FAIL: VMCS unrestricted guest CR0.PG without CR0.PE\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
  }
  else
#endif
  {
     if (~guest.cr0 & VMX_MSR_CR0_FIXED0) {
        BX_ERROR("VMENTER FAIL: VMCS guest invalid CR0\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
  }

  if (guest.cr0 & ~VMX_MSR_CR0_FIXED1) {
     BX_ERROR("VMENTER FAIL: VMCS guest invalid CR0\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

#if BX_SUPPORT_VMX >= 2
  bool real_mode_guest = false;
  if (! (guest.cr0 & BX_CR0_PE_MASK))
     real_mode_guest = true;
#endif

  guest.cr3 = vmread(VMCS_GUEST_CR3);
#if BX_SUPPORT_X86_64
  if (! IsValidPhyAddr(guest.cr3)) {
     BX_ERROR("VMENTER FAIL: VMCS guest invalid CR3\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif

  guest.cr4 = vmread(VMCS_GUEST_CR4);
  if (~guest.cr4 & VMX_MSR_CR4_FIXED0) {
     BX_ERROR("VMENTER FAIL: VMCS guest invalid CR4\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (guest.cr4 & ~VMX_MSR_CR4_FIXED1) {
     BX_ERROR("VMENTER FAIL: VMCS guest invalid CR4\n");
     return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

#if BX_SUPPORT_X86_64
  if (x86_64_guest) {
     if ((guest.cr4 & BX_CR4_PAE_MASK) == 0) {
        BX_ERROR("VMENTER FAIL: VMCS guest CR4.PAE=0 in x86-64 mode\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
  }
  else {
     if (guest.cr4 & BX_CR4_PCIDE_MASK) {
        BX_ERROR("VMENTER FAIL: VMCS CR4.PCIDE set in 32-bit guest\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_DBG_CTRLS) {
     guest.dr7 = vmread(VMCS_GUEST_DR7);
     if (GET32H(guest.dr7)) {
        BX_ERROR("VMENTER FAIL: VMCS guest invalid DR7\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
  }
#endif

#if BX_SUPPORT_CET
  if ((guest.cr4 & BX_CR4_CET_MASK) && (guest.cr0 & BX_CR0_WP_MASK) == 0) {
    BX_ERROR("VMENTER FAIL: VMCS guest CR4.CET=1 when CR0.WP=0\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_GUEST_CET_STATE) {
    guest.msr_ia32_s_cet = vmread(VMCS_GUEST_IA32_S_CET);
    if (!IsCanonical(guest.msr_ia32_s_cet) || (!x86_64_guest && GET32H(guest.msr_ia32_s_cet))) {
       BX_ERROR("VMFAIL: VMCS guest IA32_S_CET/EB_LEG_BITMAP_BASE non canonical or invalid\n");
       return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    if (is_invalid_cet_control(guest.msr_ia32_s_cet)) {
       BX_ERROR("VMFAIL: VMCS guest IA32_S_CET invalid\n");
       return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    guest.ssp = vmread(VMCS_GUEST_SSP);
    if (!IsCanonical(guest.ssp) || (!x86_64_guest && GET32H(guest.ssp))) {
       BX_ERROR("VMFAIL: VMCS guest SSP non canonical or invalid\n");
       return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
    if ((guest.ssp & 0x3) != 0) {
       BX_ERROR("VMFAIL: VMCS guest SSP[1:0] not zero\n");
       return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    guest.interrupt_ssp_table_address = vmread(VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR);
    if (!IsCanonical(guest.interrupt_ssp_table_address)) {
       BX_ERROR("VMFAIL: VMCS guest INTERRUPT_SSP_TABLE_ADDR non canonical or invalid\n");
       return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

#if BX_SUPPORT_PKEYS
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_GUEST_PKRS) {
    guest.pkrs = vmread(VMCS_64BIT_GUEST_IA32_PKRS);
    if (GET32H(guest.pkrs) != 0) {
      BX_ERROR("VMFAIL: invalid guest IA32_PKRS value\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

  //
  // Load and Check Guest State from VMCS - Segment Registers
  //

  for (n=0; n<6; n++) {
     uint16_t selector = vmread(VMCS_16BIT_GUEST_ES_SELECTOR + 2*n);
     bx_address base = (bx_address) vmread(VMCS_GUEST_ES_BASE + 2*n);
     uint32_t limit = vmread(VMCS_32BIT_GUEST_ES_LIMIT + 2*n);
     uint32_t ar = vmread(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2*n);
     ar = vmx_unpack_ar_field(ar, VMCS_AR_PACK);

     bool invalid = (ar >> 16) & 1;

     set_segment_ar_data(&guest.sregs[n], !invalid,
                  (uint16_t) selector, base, limit, (uint16_t) ar);
  }
  for (n=0; n<6; n++) {
     uint16_t selector = vmread(VMCS_16BIT_GUEST_ES_SELECTOR + 2*n);
     bx_address base = (bx_address) vmread(VMCS_GUEST_ES_BASE + 2*n);
     uint32_t limit = vmread(VMCS_32BIT_GUEST_ES_LIMIT + 2*n);
     uint32_t ar = vmread(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2*n);
     ar = vmx_unpack_ar_field(ar, VMCS_AR_PACK);

     bool invalid = (ar >> 16) & 1;

     set_segment_ar_data(&guest.sregs[n], !invalid,
                  (uint16_t) selector, base, limit, (uint16_t) ar);
     if (v8086_guest) {
        // guest in V8086 mode
        if (base != ((bx_address)(selector << 4))) {
          BX_ERROR("VMENTER FAIL: VMCS v8086 guest bad %s.BASE\n", segname[n]);
          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
        if (limit != 0xffff) {
          BX_ERROR("VMENTER FAIL: VMCS v8086 guest %s.LIMIT != 0xFFFF\n", segname[n]);
          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
        // present, expand-up read/write accessed, segment, DPL=3
        if (ar != 0xF3) {
          BX_ERROR("VMENTER FAIL: VMCS v8086 guest %s.AR != 0xF3\n", segname[n]);
          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }

        continue; // go to next segment register
     }

#if BX_SUPPORT_X86_64
     if (n >= BX_SEG_REG_FS) {
        if (! IsCanonical(base)) {
          BX_ERROR("VMENTER FAIL: VMCS guest %s.BASE non canonical\n", segname[n]);
          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
     }
#endif

     if (n != BX_SEG_REG_CS && invalid)
        continue;
#define BX_SELECTOR_RPL_MASK (0xfffc)
#if BX_SUPPORT_X86_64
    //  if (n == BX_SEG_REG_SS && (selector & BX_SELECTOR_RPL_MASK) == 0) {
    //     // SS is allowed to be NULL selector if going to 64-bit guest
    //     if (x86_64_guest && guest.sregs[BX_SEG_REG_CS].cache.u.segment.l)
    //        continue;
    //  }

     if (n < BX_SEG_REG_FS) {
        if (GET32H(base) != 0) {
          BX_ERROR("VMENTER FAIL: VMCS guest %s.BASE > 32 bit\n", segname[n]);
          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
     }
#endif

     if (! guest.sregs[n].cache.segment) {
        BX_ERROR("VMENTER FAIL: VMCS guest %s not segment\n", segname[n]);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }

     if (! guest.sregs[n].cache.p) {
        BX_ERROR("VMENTER FAIL: VMCS guest %s not present\n", segname[n]);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }

     if (! IsLimitAccessRightsConsistent(limit, ar)) {
        BX_ERROR("VMENTER FAIL: VMCS guest %s.AR/LIMIT malformed\n", segname[n]);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }

     if (n == BX_SEG_REG_CS) {
        // CS checks
        switch (guest.sregs[BX_SEG_REG_CS].cache.type) {
          case BX_CODE_EXEC_ONLY_ACCESSED:
          case BX_CODE_EXEC_READ_ACCESSED:
             // non-conforming segment
             if (guest.sregs[BX_SEG_REG_CS].cache.dpl != guest.sregs[BX_SEG_REG_SS].cache.dpl) {
               BX_ERROR("VMENTER FAIL: VMCS guest non-conforming CS.DPL <> SS.DPL\n");
               return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
             }
             break;
          case BX_CODE_EXEC_ONLY_CONFORMING_ACCESSED:
          case BX_CODE_EXEC_READ_CONFORMING_ACCESSED:
             // conforming segment
             if (guest.sregs[BX_SEG_REG_CS].cache.dpl > guest.sregs[BX_SEG_REG_SS].cache.dpl) {
               BX_ERROR("VMENTER FAIL: VMCS guest non-conforming CS.DPL > SS.DPL\n");
               return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
             }
             break;
#if BX_SUPPORT_VMX >= 2
          case BX_DATA_READ_WRITE_ACCESSED:
             if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
               if (guest.sregs[BX_SEG_REG_CS].cache.dpl != 0) {
                 BX_ERROR("VMENTER FAIL: VMCS unrestricted guest CS.DPL != 0\n");
                 return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
               }
               break;
             }
             // fall through
#endif
          default:
             BX_ERROR("VMENTER FAIL: VMCS guest CS.TYPE\n");
             return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }

#if BX_SUPPORT_X86_64
        if (x86_64_guest) {
          if (guest.sregs[BX_SEG_REG_CS].cache.u.segment.d_b && guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
             BX_ERROR("VMENTER FAIL: VMCS x86_64 guest wrong CS.D_B/L\n");
             return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
          }
        }
#endif
     }
     else if (n == BX_SEG_REG_SS) {
        // SS checks
        switch (guest.sregs[BX_SEG_REG_SS].cache.type) {
          case BX_DATA_READ_WRITE_ACCESSED:
          case BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED:
             break;
          default:
             BX_ERROR("VMENTER FAIL: VMCS guest SS.TYPE\n");
             return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
     }
     else {
        // DS, ES, FS, GS
        if ((guest.sregs[n].cache.type & 0x1) == 0) {
           BX_ERROR("VMENTER FAIL: VMCS guest %s not ACCESSED\n", segname[n]);
           return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }

        if (guest.sregs[n].cache.type & 0x8) {
           if ((guest.sregs[n].cache.type & 0x2) == 0) {
              BX_ERROR("VMENTER FAIL: VMCS guest CODE segment %s not READABLE\n", segname[n]);
              return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
           }
        }

        if (! (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
           if (guest.sregs[n].cache.type <= 11) {
              // data segment or non-conforming code segment
              if (guest.sregs[n].selector.rpl > guest.sregs[n].cache.dpl) {
                BX_ERROR("VMENTER FAIL: VMCS guest non-conforming %s.RPL < %s.DPL\n", segname[n], segname[n]);
                return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
              }
           }
        }
     }
  }

  if (! v8086_guest) {
     if (! (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
        if (guest.sregs[BX_SEG_REG_SS].selector.rpl != guest.sregs[BX_SEG_REG_CS].selector.rpl) {
           BX_ERROR("VMENTER FAIL: VMCS guest CS.RPL != SS.RPL\n");
           return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
        if (guest.sregs[BX_SEG_REG_SS].selector.rpl != guest.sregs[BX_SEG_REG_SS].cache.dpl) {
           BX_ERROR("VMENTER FAIL: VMCS guest SS.RPL <> SS.DPL\n");
           return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
        }
     }
#if BX_SUPPORT_VMX >= 2
     else { // unrestricted guest
        if (real_mode_guest || guest.sregs[BX_SEG_REG_CS].cache.type == BX_DATA_READ_WRITE_ACCESSED) {
           if (guest.sregs[BX_SEG_REG_SS].cache.dpl != 0) {
             BX_ERROR("VMENTER FAIL: VMCS unrestricted guest SS.DPL != 0\n");
             return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
           }
        }
     }
#endif
  }

  //
  // Load and Check Guest State from VMCS - GDTR/IDTR
  //

  uint64_t gdtr_base = vmread(VMCS_GUEST_GDTR_BASE);
  uint32_t gdtr_limit = vmread(VMCS_32BIT_GUEST_GDTR_LIMIT);
  uint64_t idtr_base = vmread(VMCS_GUEST_IDTR_BASE);
  uint32_t idtr_limit = vmread(VMCS_32BIT_GUEST_IDTR_LIMIT);

#if BX_SUPPORT_X86_64
  if (! IsCanonical(gdtr_base) || ! IsCanonical(idtr_base)) {
    BX_ERROR("VMENTER FAIL: VMCS guest IDTR/IDTR.BASE non canonical\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif
  if (gdtr_limit > 0xffff || idtr_limit > 0xffff) {
     BX_ERROR("VMENTER FAIL: VMCS guest GDTR/IDTR limit > 0xFFFF\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  //
  // Load and Check Guest State from VMCS - LDTR
  //

  uint16_t ldtr_selector = vmread(VMCS_16BIT_GUEST_LDTR_SELECTOR);
  uint64_t ldtr_base = vmread(VMCS_GUEST_LDTR_BASE);
  uint32_t ldtr_limit = vmread(VMCS_32BIT_GUEST_LDTR_LIMIT);
  uint32_t ldtr_ar = vmread(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS);
  ldtr_ar = vmx_unpack_ar_field(ldtr_ar, VMCS_AR_PACK);
  bool ldtr_invalid = (ldtr_ar >> 16) & 1;
  if (set_segment_ar_data(&guest.ldtr, !ldtr_invalid, 
         (uint16_t) ldtr_selector, ldtr_base, ldtr_limit, (uint16_t)(ldtr_ar)))
  {
     // ldtr is valid
     if (guest.ldtr.selector.ti) {
        BX_ERROR("VMENTER FAIL: VMCS guest LDTR.TI set\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
     if (guest.ldtr.cache.type != BX_SYS_SEGMENT_LDT) {
        BX_ERROR("VMENTER FAIL: VMCS guest incorrect LDTR type (%d)\n", guest.ldtr.cache.type);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
     if (guest.ldtr.cache.segment) {
        BX_ERROR("VMENTER FAIL: VMCS guest LDTR is not system segment\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
     if (! guest.ldtr.cache.p) {
        BX_ERROR("VMENTER FAIL: VMCS guest LDTR not present\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
     if (! IsLimitAccessRightsConsistent(ldtr_limit, ldtr_ar)) {
        BX_ERROR("VMENTER FAIL: VMCS guest LDTR.AR/LIMIT malformed\n");
        // return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
#if BX_SUPPORT_X86_64
     if (! IsCanonical(ldtr_base)) {
        BX_ERROR("VMENTER FAIL: VMCS guest LDTR.BASE non canonical\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
     }
#endif
  }

  //
  // Load and Check Guest State from VMCS - TR
  //

  uint16_t tr_selector = vmread(VMCS_16BIT_GUEST_TR_SELECTOR);
  uint64_t tr_base = vmread(VMCS_GUEST_TR_BASE);
  uint32_t tr_limit = vmread(VMCS_32BIT_GUEST_TR_LIMIT);
  uint32_t tr_ar = vmread(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS);
  tr_ar = vmx_unpack_ar_field(tr_ar, VMCS_AR_PACK);
  bool tr_invalid = (tr_ar >> 16) & 1;

#if BX_SUPPORT_X86_64
  if (! IsCanonical(tr_base)) {
    BX_ERROR("VMENTER FAIL: VMCS guest TR.BASE non canonical\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif

  set_segment_ar_data(&guest.tr, !tr_invalid, 
      (uint16_t) tr_selector, tr_base, tr_limit, (uint16_t)(tr_ar));

  if (tr_invalid) {
     BX_ERROR("VMENTER FAIL: VMCS guest TR invalid\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (guest.tr.selector.ti) {
     BX_ERROR("VMENTER FAIL: VMCS guest TR.TI set\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (guest.tr.cache.segment) {
     BX_ERROR("VMENTER FAIL: VMCS guest TR is not system segment\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (! guest.tr.cache.p) {
     BX_ERROR("VMENTER FAIL: VMCS guest TR not present\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (! IsLimitAccessRightsConsistent(tr_limit, tr_ar)) {
     BX_ERROR("VMENTER FAIL: VMCS guest TR.AR/LIMIT malformed\n");
     return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  switch(guest.tr.cache.type) {
    case BX_SYS_SEGMENT_BUSY_386_TSS:
      break;
    case BX_SYS_SEGMENT_BUSY_286_TSS:
      if (! x86_64_guest) break;
      // fall through
    default:
      BX_ERROR("VMENTER FAIL: VMCS guest incorrect TR type\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  //
  // Load and Check Guest State from VMCS - MSRS
  //

  guest.ia32_debugctl_msr = vmread(VMCS_64BIT_GUEST_IA32_DEBUGCTL);
  guest.smbase = vmread(VMCS_32BIT_GUEST_SMBASE);

  guest.sysenter_esp_msr = vmread(VMCS_GUEST_IA32_SYSENTER_ESP_MSR);
  guest.sysenter_eip_msr = vmread(VMCS_GUEST_IA32_SYSENTER_EIP_MSR);
  guest.sysenter_cs_msr = vmread(VMCS_32BIT_GUEST_IA32_SYSENTER_CS_MSR);

#if BX_SUPPORT_X86_64
  if (! IsCanonical(guest.sysenter_esp_msr)) {
    BX_ERROR("VMENTER FAIL: VMCS guest SYSENTER_ESP_MSR non canonical\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (! IsCanonical(guest.sysenter_eip_msr)) {
    BX_ERROR("VMENTER FAIL: VMCS guest SYSENTER_EIP_MSR non canonical\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif

#if BX_SUPPORT_VMX >= 2
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_PAT_MSR) {
    guest.pat_msr = vmread(VMCS_64BIT_GUEST_IA32_PAT);
    if (! isValidMSR_PAT(guest.pat_msr)) {
      BX_ERROR("VMENTER FAIL: invalid Memory Type in guest MSR_PAT\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

  guest.rip = vmread(VMCS_GUEST_RIP);
  guest.rsp = vmread(VMCS_GUEST_RSP);

#if BX_SUPPORT_VMX >= 2 && BX_SUPPORT_X86_64
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_EFER_MSR) {
    guest.efer_msr = vmread(VMCS_64BIT_GUEST_IA32_EFER);
    if (guest.efer_msr & ~((uint64_t) __rdmsr1(MSR_EFER))) {
      BX_ERROR("VMENTER FAIL: VMCS guest EFER reserved bits set !\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
    bool lme = (guest.efer_msr >>  8) & 0x1;
    bool lma = (guest.efer_msr >> 10) & 0x1;
    if (lma != x86_64_guest) {
      BX_ERROR("VMENTER FAIL: VMCS guest EFER.LMA doesn't match x86_64_guest !\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
    if (lma != lme && (guest.cr0 & BX_CR0_PG_MASK) != 0) {
      BX_ERROR("VMENTER FAIL: VMCS guest EFER (0x%08x) inconsistent value !\n", (uint32_t) guest.efer_msr);
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  if (! x86_64_guest || !guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
    if (GET32H(guest.rip) != 0) {
       BX_ERROR("VMENTER FAIL: VMCS guest RIP > 32 bit\n");
       return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

  //
  // Load and Check Guest Non-Registers State from VMCS
  //

  vm->vmcs_linkptr = vmread(VMCS_64BIT_GUEST_LINK_POINTER);
  if (vm->vmcs_linkptr != BX_INVALID_VMCSPTR) {
    if (! IsValidPageAlignedPhyAddr(vm->vmcs_linkptr)) {
      *qualification = (uint64_t) VMENTER_ERR_GUEST_STATE_LINK_POINTER;
      BX_ERROR("VMFAIL: VMCS link pointer malformed\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    uint32_t revision = VMXReadRevisionID((bx_phy_address) vm->vmcs_linkptr);
    if (vm->vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
      if ((revision & BX_VMCS_SHADOW_BIT_MASK) == 0) {
        *qualification = (uint64_t) VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        BX_ERROR("VMFAIL: VMCS link pointer must indicate shadow VMCS revision ID = %x\n", revision);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
      revision &= ~BX_VMCS_SHADOW_BIT_MASK;
    }
    if (revision != VMXReadRevisionID((bx_phy_address) current_vmcsptr)) {
      *qualification = (uint64_t) VMENTER_ERR_GUEST_STATE_LINK_POINTER;
      BX_ERROR("VMFAIL: VMCS link pointer incorrect revision ID %x != %x\n", revision, VMXReadRevisionID((bx_phy_address) current_vmcsptr));
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    if (! in_smm || (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) != 0) {
      if (vm->vmcs_linkptr == current_vmcsptr) {
        *qualification = (uint64_t) VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        BX_ERROR("VMFAIL: VMCS link pointer equal to current VMCS pointer\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
    }
    else {
      if (vm->vmcs_linkptr == vmxonptr) {
        *qualification = (uint64_t) VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        BX_ERROR("VMFAIL: VMCS link pointer equal to VMXON pointer\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
    }
  }

  guest.tmpDR6 = (uint32_t) vmread(VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
  if (guest.tmpDR6 & BX_CONST64(0xFFFFFFFFFFFFAFF0)) {
    BX_ERROR("VMENTER FAIL: VMCS guest tmpDR6 reserved bits\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  guest.activity_state = vmread(VMCS_32BIT_GUEST_ACTIVITY_STATE);
  if (guest.activity_state > BX_VMX_LAST_ACTIVITY_STATE) {
    BX_ERROR("VMENTER FAIL: VMCS guest activity state %d\n", guest.activity_state);
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  if (guest.activity_state == BX_ACTIVITY_STATE_HLT) {
    if (guest.sregs[BX_SEG_REG_SS].cache.dpl != 0) {
      BX_ERROR("VMENTER FAIL: VMCS guest HLT state with SS.DPL=%d\n", guest.sregs[BX_SEG_REG_SS].cache.dpl);
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  guest.interruptibility_state = vmread(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE);
  if (guest.interruptibility_state & ~BX_VMX_INTERRUPTIBILITY_STATE_MASK) {
    BX_ERROR("VMENTER FAIL: VMCS guest interruptibility state broken\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  if (guest.interruptibility_state & 0x3) {
    if (guest.activity_state != BX_ACTIVITY_STATE_ACTIVE) {
      BX_ERROR("VMENTER FAIL: VMCS guest interruptibility state broken when entering non active CPU state %d\n", guest.activity_state);
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  if ((guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) &&
      (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS))
  {
    BX_ERROR("VMENTER FAIL: VMCS guest interruptibility state broken\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  if ((guest.rflags & EFlagsIFMask) == 0) {
    if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) {
      BX_ERROR("VMENTER FAIL: VMCS guest interrupts can't be blocked by STI when EFLAGS.IF = 0\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  if (VMENTRY_INJECTING_EVENT(vm->vmentry_interr_info)) {
    unsigned event_type = (vm->vmentry_interr_info >> 8) & 7;
    unsigned vector = vm->vmentry_interr_info & 0xff;
    if (event_type == BX_EXTERNAL_INTERRUPT) {
      if ((guest.interruptibility_state & 0x3) != 0 || (guest.rflags & EFlagsIFMask) == 0) {
        BX_ERROR("VMENTER FAIL: VMCS guest interrupts blocked when injecting external interrupt\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
    }
    if (event_type == BX_NMI) {
      if ((guest.interruptibility_state & 0x3) != 0) {
        BX_ERROR("VMENTER FAIL: VMCS guest interrupts blocked when injecting NMI\n");
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
    }
    if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
      BX_ERROR("VMENTER FAIL: No guest interruptions are allowed when entering Wait-For-Sipi state\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
    if (guest.activity_state == BX_ACTIVITY_STATE_SHUTDOWN && event_type != BX_NMI && vector != BX_MC_EXCEPTION) {
      BX_ERROR("VMENTER FAIL: Only NMI or #MC guest interruption is allowed when entering shutdown state\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) {
    if (! (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED)) {
      BX_ERROR("VMENTER FAIL: VMCS SMM guest should block SMI\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
      BX_ERROR("VMENTER FAIL: The activity state must not indicate the wait-for-SIPI state if entering to SMM guest\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

  if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED) {
    if (! in_smm) {
      BX_ERROR("VMENTER FAIL: VMCS SMI blocked when not in SMM mode\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }

// Checks on Guest Page-Directory-Pointer-Table Entries (not impremented yet)

  return VMXERR_NO_ERROR;
}

uint32_t VMX_Read_Virtual_APIC_VTPR(void){
    uintptr_t vtpr_ptr = vmread(0x2012) + 0x80;
    uint32_t *vtpr = (uint32_t *)vtpr_ptr;
    return vtpr[0];
} 
uint32_t VMXReadRevisionID(bx_phy_address pAddr){
    uintptr_t vmcs_ptr = pAddr;
    uint32_t *vmcs = (uint32_t *)vmcs_ptr;
    return vmcs[0];
} 