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

    // Branch Instructions (B, BL, BLX)
    if (pInst->id == ARM_INS_B || pInst->id == ARM_INS_BL || pInst->id == ARM_INS_BLX)
    {
        if (pInstWildcardStrategy)
        {
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
            pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(2);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // Load/Store with Offset (LDR, STR, and variants)
    if (pInst->id == ARM_INS_LDR || pInst->id == ARM_INS_STR || 
        pInst->id == ARM_INS_LDRB || pInst->id == ARM_INS_STRB ||
        pInst->id == ARM_INS_LDRH || pInst->id == ARM_INS_STRH ||
        pInst->id == ARM_INS_LDRD || pInst->id == ARM_INS_STRD)
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
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
            }
            if(outResult) *outResult = NS_IMMDISP;
            return true;
        }
    }

    // Arithmetic / Data Processing with Immediate (ADD, SUB, MOV, CMP, TST)
    if (pInst->id == ARM_INS_ADD || pInst->id == ARM_INS_SUB || 
        pInst->id == ARM_INS_MOV || pInst->id == ARM_INS_MOVW || 
        pInst->id == ARM_INS_CMP || pInst->id == ARM_INS_TST)
    {
        bool hasImm = false;
        for(int i=0; i<pArmInst->op_count; i++)
            if(pArmInst->operands[i].type == ARM_OP_IMM) hasImm = true;

        if(hasImm)
        {
            if (pInstWildcardStrategy)
            {
                pInstWildcardStrategy->mTechnique.mWildcardedOffsets.clear();
                
                if(pInst->id == ARM_INS_ADD || pInst->id == ARM_INS_SUB)
                {
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                }
                else if(pInst->id == ARM_INS_MOV || pInst->id == ARM_INS_MOVW)
                {
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(0);
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(1);
                    pInstWildcardStrategy->mTechnique.mWildcardedOffsets.insert(2);
                }
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
