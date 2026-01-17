#include "Arch/ARM32/Arm32CapstoneHelper.h"
#include "Arch/ARM32/Arm32CapstoneAux.h"

Arm32CapstoneHelper::Arm32CapstoneHelper()
{
	setArch(CS_ARCH_ARM);
	setMode(CS_MODE_ARM);
}

bool Arm32CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	return false;
}

bool Arm32CapstoneHelper::InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp)
{
    switch (pInst->id)
    {

    case ARM_INS_LDR:
    case ARM_INS_LDRH:
    case ARM_INS_LDRD:
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDREXB:
    {
        if (ArmCapstoneAux::GetRValueRegType(pInst) == ARM_REG_PC) return TryInterpretDispPCRelative(pInst, outDisp);
        else outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_STR:
    case ARM_INS_STRH:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_VLDR:
    case ARM_INS_VSTR:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_ADD:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].imm;
    }break;

    case ARM_INS_MOV:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = op.imm;
            break;
        }
    }

    case ARM_INS_MVN:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = ~(op.imm);
            break;
        }
    }

    default:
        return false;
    }

    return true;
}

bool Arm32CapstoneHelper::InterpretDispPCRelativeInst(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    uint16_t regPcRelOffHolderType = ArmCapstoneAux::GetLValueRegType(pInstBegin);
    uintptr_t targetPcRelOff = ArmCapstoneAux::ResolvePCRelative((unsigned char*)pInstBegin->address, pInstBegin->detail->arm.operands[pInstBegin->detail->arm.op_count - 1].mem.disp);

    for (auto* pCurrInst = pInstBegin + 1; pCurrInst < pInstEnd; pCurrInst++)
    {

        switch (pCurrInst->id) {

        case ARM_INS_LDR:
        case ARM_INS_STR:
        {
            if (pCurrInst->detail->arm.operands[1].mem.base == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[1].mem.index == regPcRelOffHolderType)
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        case ARM_INS_ADD:
        {
            if ((pCurrInst->detail->arm.operands[1].reg == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[2].reg == regPcRelOffHolderType) ||
                (pCurrInst->detail->arm.operands[2].reg == ARM_REG_PC &&
                    pCurrInst->detail->arm.operands[1].reg == regPcRelOffHolderType))
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        }
    }

    return false;
}

bool Arm32CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
    switch (pInst->id)
    {
    case ARM_INS_BL:
    case ARM_INS_B:
    {
        outDest = pInst->detail->arm.operands[0].imm;
        return true;
    }

    }
    return pInst->address;

    return false;
}

bool Arm32CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicReturn(pInst);
}

bool Arm32CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicProlog(pInst);
}

bool Arm32CapstoneHelper::ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult, uint32_t toIgnoreNonSolidFlag, InstructionWildcardStrategy* pInstWildcardStrategy)
{
    cs_arm* pArmInst = &(pInst->detail->arm);

    if (pInstWildcardStrategy)
    {
        *pInstWildcardStrategy = InstructionWildcardStrategy();
        pInstWildcardStrategy->mSize = pInst->size;
    }

    // Special handling for Thumb-2 32-bit instructions (4 bytes).
    if (mMode == CS_MODE_THUMB && pInst->size == 4)
    {
        if (pInstWildcardStrategy)
        {
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(2);
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(3);
        }
        if(outResult) *outResult = NS_IMMDISP; 
        return true;
    }

    if (pArmInst->op_count < 1 && pInst->id != ARM_INS_BL && pInst->id != ARM_INS_B) // BL/B might have implict operands but usually explicit
        return false;

    // Branch Instructions (B, BL, BLX, CBZ, CBNZ)
    if (pInst->id == ARM_INS_B || pInst->id == ARM_INS_BL || pInst->id == ARM_INS_BLX || 
        pInst->id == ARM_INS_CBZ || pInst->id == ARM_INS_CBNZ)
    {
        if (pInstWildcardStrategy)
        {
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
            if (pInst->size == 2)
            {
                // Thumb 16-bit B, CBZ, CBNZ: Wildcard Byte 0 (offset/imm5/rn)
                // Opcode is in Byte 1 (mostly)
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
            }
            else
            {
                // ARM/Thumb-2 32-bit: Wildcard 0, 1, 2 (24-bit offset)
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(2);
            }
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // Load/Store with Offset (LDR, STR, and variants)
    if (pInst->id == ARM_INS_LDR || pInst->id == ARM_INS_STR || 
        pInst->id == ARM_INS_LDRB || pInst->id == ARM_INS_STRB ||
        pInst->id == ARM_INS_LDRH || pInst->id == ARM_INS_STRH ||
        pInst->id == ARM_INS_LDRD || pInst->id == ARM_INS_STRD ||
        pInst->id == ARM_INS_VLDR || pInst->id == ARM_INS_VSTR || pInst->id == ARM_INS_VMOV)
    {
        bool hasMemDisp = false;
        for(int i=0; i<pArmInst->op_count; i++)
        {
            if(pArmInst->operands[i].type == ARM_OP_MEM || pArmInst->operands[i].type == ARM_OP_IMM)
                hasMemDisp = true;
        }

        if(hasMemDisp)
        {
            if (pInstWildcardStrategy)
            {
                 pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
                 if (pInst->size == 2)
                 {
                     // Thumb 16-bit LDR Literal/Imm: Wildcard Byte 0
                     pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                 }
                 else
                 {
                     // ARM/Thumb-2: Wildcard 0, 1
                     pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                     pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
                 }
            }
            if(outResult) *outResult = NS_IMMDISP;
            return true;
        }
    }

    // Arithmetic / Data Processing with Immediate (ADD, SUB, MOV, CMP, TST, MOVT, MVN, AND, ORR, etc.)
    if (pInst->id == ARM_INS_ADD || pInst->id == ARM_INS_SUB || 
        pInst->id == ARM_INS_MOV || pInst->id == ARM_INS_MOVW || pInst->id == ARM_INS_MOVT || pInst->id == ARM_INS_MVN || pInst->id == ARM_INS_MOVS ||
        pInst->id == ARM_INS_CMP || pInst->id == ARM_INS_TST || 
        pInst->id == ARM_INS_AND || pInst->id == ARM_INS_ORR || pInst->id == ARM_INS_EOR || pInst->id == ARM_INS_BIC)
    {
        bool hasImm = false;
        for(int i=0; i<pArmInst->op_count; i++)
            if(pArmInst->operands[i].type == ARM_OP_IMM) hasImm = true;

        if(hasImm)
        {
            if (pInstWildcardStrategy)
            {
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
                
                // ADD/SUB: Bytes 0 (Imm rotation + partial imm)
                if(pInst->id == ARM_INS_ADD || pInst->id == ARM_INS_SUB)
                {
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                }
                // MOV/MOVW/MOVT/MVN/MOVS: Bytes 0, 1, 2 (Covers imm16 or imm12+rot and Rd)
                else if(pInst->id == ARM_INS_MOV || pInst->id == ARM_INS_MOVW || pInst->id == ARM_INS_MOVT || pInst->id == ARM_INS_MVN || pInst->id == ARM_INS_MOVS)
                {
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                    if (pInst->size > 2)
                    {
                        pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
                        pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(2);
                    }
                }
                // CMP/TST/Logic: Bytes 0, 1
                else
                {
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
                }
            }
            if(outResult) *outResult = NS_IMMDISP;
            return true;
        }
    }

    return false;
}
