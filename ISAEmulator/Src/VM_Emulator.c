//
//文件名称：        src/VM_Emulator.c
//文件描述：        模拟器相关结构体与函数定义
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年6月5日
//
//公司名称：        北京普天网怡科技有限公司
//项目组名：
//保密级别：
//版权声明：
//
//主项目名称：      基于虚拟机的漏洞挖掘平台
//主项目描述：
//主项目启动时间：  2009年6月X日
//
//子项目名称：      虚拟机及环境仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日
//
//模块名称：        指令仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日

//
//更新日志：
//2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "VM_Defines.h"
#include "VM_Emulator.h"
#include "VM_ControlUnit.h"
#include "VM_Log.h"

#ifdef VM_ISA_INTEL_X86_32_BIT
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include <Windows.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

//临时设置的变量，用于检测内存访问情况
UINT uLastAccessMemoryStart;
size_t siLastAccessMemorySize;
PNODE MemoryAccesLogListHeadNode;
UINT uSerialJumpBack = 0;
BOOL bShellcodeIsFound = FALSE;
//函数名称：        VM_Emu_Step
//函数描述：
//返回值：
//参数描述：
//更新日志:         2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建
VM_ERR_CODE VM_Emu_Step(PVM_Emulator_t pEmulator)
{
    BYTE byIgnoreBytes[5];
    VM_ERR_CODE vm_err;
    VM_INSTRUCTION_ERR_CODE ErrCodeInstruction;
    int temp;
    PNODE * ppNode;
    PMemoryAccessLog_t pMemAccLog = NULL;
    
    
#ifdef VM_ISA_INTEL_X86_32_BIT
    static UINT uLastEIP = 0; //如果遇到EIP回转死循环(如 71 fe jno -2)，则报错退出
    UINT uOutputCharLength = 0;
    char szMnemonic[100];
    PVM_Intel_x86_ISA_t pX86 = (PVM_Intel_x86_ISA_t)pEmulator->CPUStructure.ISAPointer;
    int i;
#endif
    assert(pEmulator);
    if(NULL == pEmulator){
        return VM_ERR_FATAL_NULL_POINTER;
    }

    assert(pEmulator->ControlUnit.pfnFetchOneInstruction);
    if(NULL == pEmulator->ControlUnit.pfnFetchOneInstruction){
        return VM_ERR_FATAL_NULL_POINTER;
    }
#ifdef VM_ISA_INTEL_X86_32_BIT
    uLastEIP = ACCESS_GEN_EIP(*pX86);
    
    //是否应该判断EIP超出范围？
    
#endif
    vm_err = VM_MM_ReadOneBlock(&pEmulator->Memory.CodeSegment, uLastEIP, byIgnoreBytes, sizeof(byIgnoreBytes));
    if(VM_ERR_NO_ERROR == vm_err){
        for(i = 1; i < sizeof(byIgnoreBytes); i++){
            if(byIgnoreBytes[0] != byIgnoreBytes[i]){
                break;
            }
        }
        if(sizeof(byIgnoreBytes) == i){
            printf("%d serial bytes (@%08x) are the same(%02x), should not be invalid instruction\n", sizeof(byIgnoreBytes), uLastEIP, byIgnoreBytes[0]);
            return VM_ERR_NO_MORE_INSTRUCTION;
        }
    }
    ErrCodeInstruction = pEmulator->ControlUnit.pfnFetchOneInstruction(&pEmulator->CPUStructure, &pEmulator->Memory);
    if(VM_INSTRUCTION_ERR_SUCCEEDED != ErrCodeInstruction){
        return VM_ERR_NO_MORE_INSTRUCTION;
    }

    //pEmulator->ControlUnit.pfnOutputCpuState(&pEmulator->CPUStructure);


#ifdef VM_ISA_INTEL_X86_32_BIT
    GetInstructionMnemonic(szMnemonic, sizeof(szMnemonic), &pX86->CurrentInstruction, OPERAND_SIZE_32BIT, ADDRESS_SIZE_32BIT, ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)pEmulator->CPUStructure.ISAPointer)));
    printf("%08x:\t", uLastEIP);
    uOutputCharLength = 0;
    for(i = 0; i < pX86->CurrentInstruction.byOpcodesNum; i ++){
        printf("%02x ", pX86->CurrentInstruction.byOpcodes[i]);
        uOutputCharLength += 3;
    }
    if(pX86->CurrentInstruction.dwDataBitFlags & NEED_MODRM){
        printf("%02x ", pX86->CurrentInstruction.byModRM);
        uOutputCharLength += 3;
    }

    if(pX86->CurrentInstruction.dwDataBitFlags & NEED_SIB){
        printf("%02x ", pX86->CurrentInstruction.bySIB);
        uOutputCharLength += 3;
    }
    if(NEED_DISPLACEMENT_MASK(pX86->CurrentInstruction.dwDataBitFlags)){
        temp = NEED_DISPLACEMENT_MASK(pX86->CurrentInstruction.dwDataBitFlags);
        switch(NEED_DISPLACEMENT_MASK(pX86->CurrentInstruction.dwDataBitFlags)){
            case NEED_DISPLACEMENT_8BIT:
                printf("%02x ", pX86->CurrentInstruction.iDisplacement & 0xff);
                uOutputCharLength += 3;
                break;
            case NEED_DISPLACEMENT_16BIT:
                printf("%04x ", pX86->CurrentInstruction.iDisplacement & 0xffff);
                uOutputCharLength += 5;
                break;
            case NEED_DISPLACEMENT_32BIT:
                printf("%08x ", pX86->CurrentInstruction.iDisplacement & 0xffffffff);
                uOutputCharLength += 9;
                break;
            default:
                assert(0);//should not be here
                break;
        }
    }

    if(NEED_IMMEDIATE_BYTES_MASK(pX86->CurrentInstruction.dwDataBitFlags)){
        switch(NEED_IMMEDIATE_BYTES_MASK(pX86->CurrentInstruction.dwDataBitFlags)){
            case NEED_IMMEDIATE_BYTE:
                printf("%02x ", pX86->CurrentInstruction.uImmediate & 0xff);
                uOutputCharLength += 3;
                break;
            case NEED_IMMEDIATE_WORD:
                printf("%04x ", pX86->CurrentInstruction.uImmediate & 0xffff);
                uOutputCharLength += 5;
                break;
            case NEED_IMMEDIATE_THREE_BYTES://only for enter Iw, Ib
                printf("%06x ", pX86->CurrentInstruction.uImmediate & 0xffffff);
                uOutputCharLength += 7;
                break;
            case NEED_IMMEDIATE_DWORD:
                printf("%08x ", pX86->CurrentInstruction.uImmediate & 0xffffffff);
                uOutputCharLength += 9;
                break;
            default:
                assert(0);//should not be here
                break;
        }
    }
    if(pX86->CurrentInstruction.dwDataBitFlags & NEED_IMMEDIATE_1){
        printf("1 ");
        uOutputCharLength += 2;
    }
#define FIXED_CHAR_LENGTH 20
    for(i = uOutputCharLength; i < FIXED_CHAR_LENGTH; i ++){
        printf(" ");
    }
    printf("%s\n", szMnemonic);
#endif
    //JIF(pEmulator->ControlUnit.pfnExecuteOneInstruction(&pEmulator->CPUStructure, &pEmulator->Memory));
    vm_err = pEmulator->ControlUnit.pfnExecuteOneInstruction(&pEmulator->CPUStructure, &pEmulator->Memory);
    
#ifdef VM_ISA_INTEL_X86_32_BIT
    //死循环
    if(uLastEIP == ACCESS_GEN_EIP(*pX86)){
        vm_err = VM_ERR_FATAL_DEAD_LOOP;
        return vm_err;
    }
    if(uLastEIP > ACCESS_GEN_EIP(*pX86)){
        uSerialJumpBack ++;
        if(uSerialJumpBack > 10240){//回跳上限
            uSerialJumpBack = 0;
            return VM_ERR_FATAL_DEAD_MAXIMUM_LOOP;
        }
    }
    else{
        //此处这样处理会越过可能的shellcode
        //uSerialJumpBack = 0;
    }
//------------------------------------------------------
    //临时用于shellcode监控的代码，需要更改结构！！！
    //需要排除栈空间
    if(FALSE == bShellcodeIsFound 
        && VM_ERR_NO_ERROR == vm_err
        && siLastAccessMemorySize 
        && !(pEmulator->Memory.StackSegment.uStartAddr <= uLastAccessMemoryStart 
                    && uLastAccessMemoryStart < pEmulator->Memory.StackSegment.uStartAddr + pEmulator->Memory.StackSegment.uBlockSize)){//有数据访问
        

        ppNode = &MemoryAccesLogListHeadNode;
        while(*ppNode && (*ppNode)->pDatafield){
            assert(sizeof(MemoryAccessLog_t) == (*ppNode)->siDatafield);
            pMemAccLog = (PMemoryAccessLog_t)(*ppNode)->pDatafield;
            if(uLastAccessMemoryStart < pMemAccLog->uStartAddr){
                //Addr      01234567890123
                //Last      ^...<..$..>
                //Current       XXXXXXX
                if(uLastAccessMemoryStart + siLastAccessMemorySize >= pMemAccLog->uStartAddr){
                    if(uLastAccessMemoryStart + siLastAccessMemorySize <= pMemAccLog->uStartAddr + pMemAccLog->siAccessSize){
                        //Addr      01234567890123
                        //Last      ----------
                        //Current       XXXXXXXXXX
                        //New       **************
                        pMemAccLog->uStartAddr = uLastAccessMemoryStart;
                        pMemAccLog->siAccessSize += (pMemAccLog->uStartAddr - uLastAccessMemoryStart);
                        siLastAccessMemorySize = 0;//清除标志位
                    }
                    else {//if(uLastAccessMemoryStart + siLastAccessMemorySize > pMemAccLog->uStartAddr + pMemAccLog->siAccessSize){
                        //Addr      012345678901234
                        //Last      ---------------
                        //Current       XXXXXXXXXX
                        //New       ***************
                        pMemAccLog->uStartAddr = uLastAccessMemoryStart;
                        pMemAccLog->siAccessSize = siLastAccessMemorySize;
                        siLastAccessMemorySize = 0;//清除标志位
                    }
                    
                }
                else{//不在此内存区，访问下一个log
                        //Addr      012345678901234
                        //Last      --
                        //Current       XXXXXXXXXX
                        //New       **  XXXXXXXXXX
                }
            }
            else if(uLastAccessMemoryStart < pMemAccLog->uStartAddr + pMemAccLog->siAccessSize){
                //Addr      01234567890123
                //Last      <...^...>....$
                //Current   XXXXXXXXX
                if(uLastAccessMemoryStart + siLastAccessMemorySize <= pMemAccLog->uStartAddr + pMemAccLog->siAccessSize){
                    //Addr      01234567890123
                    //Last      <...^...$
                    //Current   XXXXXXXXX
                    //New       *********
                    siLastAccessMemorySize = 0;//清除标志位
                }
                else{
                    //Addr      01234567890123
                    //Last      <...^..>.....$
                    //Current   XXXXXXXXX
                    //New       **************
                    pMemAccLog->siAccessSize += (pMemAccLog->uStartAddr - uLastAccessMemoryStart);
                    pMemAccLog->siAccessSize += uLastAccessMemoryStart + siLastAccessMemorySize - (pMemAccLog->uStartAddr + pMemAccLog->siAccessSize);
                    siLastAccessMemorySize = 0;
                }
            }
            else{//不在此内存区，访问下一个log
                        //Addr      012345678901234
                        //Last                 ^..$
                        //Current   XXXXXXXX
            }
            ppNode = &((*ppNode)->pNext);
        }//while

        //没有找到包含区域，新建记录
        if(siLastAccessMemorySize){
            *ppNode = (PNODE)malloc(sizeof(NODE));
            if(NULL == *ppNode){
                printf("No insufficient memory!\n");
                return VM_ERR_FATAL_INSUFFICIENT_MEMORY;
            }
            memset(*ppNode, 0, sizeof(NODE));
            (*ppNode)->pDatafield = malloc(sizeof(MemoryAccessLog_t));
            if(NULL == (*ppNode)->pDatafield){
                printf("No insufficient memory!\n");
                return VM_ERR_FATAL_INSUFFICIENT_MEMORY;
            }
            (*ppNode)->siDatafield = sizeof(MemoryAccessLog_t);
            memset((*ppNode)->pDatafield, 0, sizeof(MemoryAccessLog_t));

            pMemAccLog = (PMemoryAccessLog_t)(*ppNode)->pDatafield;
            pMemAccLog->uStartAddr = uLastAccessMemoryStart;
            pMemAccLog->siAccessSize = siLastAccessMemorySize;
            siLastAccessMemorySize = 0;//清除标志位
        }

        assert(0 == siLastAccessMemorySize);//应该已经被记录，否则是程序错误
    }

    ppNode = &MemoryAccesLogListHeadNode;
    while(*ppNode && (*ppNode)->pDatafield){
        pMemAccLog = (PMemoryAccessLog_t)(*ppNode)->pDatafield;
        if(pMemAccLog->uStartAddr <= ACCESS_GEN_EIP(*pX86) && ACCESS_GEN_EIP(*pX86) < pMemAccLog->uStartAddr + pMemAccLog->siAccessSize){
            if(0 == ACCESS_GEN_EIP(*pX86) ) {//很多ret类指令经常被误报
                vm_err = VM_ERR_NO_MORE_INSTRUCTION;
            }
            else{
                //printf("maybe found shell code\n");
                //assert(0);//maybe found shell code
                //存在误报
                vm_err = VM_ERR_SHELLCODE_SEEMS_BE_FOUND;
            }
            break;
        }
        if((pEmulator->Memory.StackSegment.uStartAddr <= ACCESS_GEN_EIP(*pX86) 
            && ACCESS_GEN_EIP(*pX86) < pEmulator->Memory.StackSegment.uStartAddr + pEmulator->Memory.StackSegment.uBlockSize)){
                //printf("maybe found shell code(in stack space)\n");
                //assert(0);
                //存在误报
                vm_err = VM_ERR_SHELLCODE_SEEMS_BE_FOUND;
                break;
        }
        ppNode = &((*ppNode)->pNext);
    }

    Sleep(0);
#endif
    return vm_err;
}

//函数名称：        VM_Emu_Run
//函数描述：
//返回值：
//参数描述：
//更新日志:         2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建
VM_ERR_CODE VM_Emu_Run(PVM_Emulator_t pEmulator)
{
    return VM_ERR_FATAL_UNKNOWN;
}

//函数名称：        VM_Emu_LoadProgramCodeFromFile
//函数描述：
//返回值：
//参数描述：
//更新日志:         2010年3月24日，杨鸿博(yanghongbo@ptwy.cn)，创建
VM_ERR_CODE VM_Emu_LoadDataToMemory(PVM_MemoryBlock_t pMemoryBlock, UINT addr, PBYTE pBuffer, size_t siBufferSize)
{
    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;

    //assert(NULL != pMemoryBlock);
    assert(NULL != pBuffer);

    vm_err = VM_MM_WriteOneBlock(pMemoryBlock, addr, pBuffer, siBufferSize);

    return vm_err;
}

//函数名称：        VM_Emu_LoadProgramCodeFromFile
//函数描述：
//返回值：
//参数描述：
//更新日志:         2010年3月24日，杨鸿博(yanghongbo@ptwy.cn)，创建
VM_ERR_CODE VM_Emu_LoadProgramCodeFromFile(PVM_Emulator_t pEmulator, const char * filename,OUT size_t * pCodeSize)
{
    int  i =0 ;
    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    FILE * file = NULL;
    PVOID pCodeBuffer = NULL;
    size_t CodeSize = 0;
    assert(NULL != pEmulator);
    assert(NULL != filename);

    if(pEmulator){
        file = fopen(filename, "rb");
        if(file){
            fseek(file, 0, SEEK_END);
            CodeSize = ftell(file);
            fseek(file, 0, SEEK_SET);
            pCodeBuffer = malloc(sizeof(char) * CodeSize);;
            if(pCodeBuffer){
                fread(pCodeBuffer, sizeof(char), CodeSize, file);
                if(pCodeSize)
                    *pCodeSize = CodeSize;
                vm_err = VM_MM_WriteOneBlock(&pEmulator->Memory.CodeSegment, 0x40000000, pCodeBuffer, CodeSize);
                free(pCodeBuffer);
                pCodeBuffer = NULL;
            }
            else {
                printf("Insufficient memory\n");
            }
            fclose(file);
            file = NULL;
        }
        else{
            printf("Cannot open file:%s\n", filename);
        }
    }

    return vm_err;
}

//函数名称：        VM_Emu_LoadProgramCode
//函数描述：
//返回值：
//参数描述：
//更新日志:         2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建
VM_ERR_CODE VM_Emu_LoadProgramCode(PVM_Emulator_t pEmulator, PBYTE pCodeBuffer, size_t CodeSize)
{
    int  i =0 ;
    VM_ERR_CODE vm_err;
    assert(NULL != pEmulator);
    assert(NULL != pCodeBuffer);
    assert(CodeSize > 0);
    if(NULL == pEmulator || NULL == pCodeBuffer){
        return VM_ERR_FATAL_UNKNOWN;
    }

    //Memory.CodeSegment , 0x40000000, 0xf000
    //Memory.DataSegment , 0x50000000, 0xf000
    //Memory.StackSegment, 0x60000000, 0xf000
    vm_err = VM_MM_WriteOneBlock(&pEmulator->Memory.CodeSegment, 0x40000000, pCodeBuffer, CodeSize);

    //Binary_tree
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000,0x1); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000004,0x2); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000008,0x3); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000000C,0x4); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000010,0x5); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000014,0x6); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000018,0x7); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000001C,0x8); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000020,0x9); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000024,0xa); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000028,0xb); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000002C,0xc); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000030,0xd); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000034,0xe); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000038,0xf); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000003C,0x10); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000040,0x11); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000044,0x12); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000048,0x13); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000004C,0x14); 
    vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000050,0x15); 

    for ( i = 0x15 ; i < 0x3C00 ; i ++){
        VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000 + i * 0x4,0x0);
    }


//     //AVL_Tree_Test
//     //4, 7, 2, 9, 6, 1, 5, 8, 3
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000,0x4);       // 4
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000004,0x7);       // 7   
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000008,0x2);       // 2
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000000C,0x9);       // 9  
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000010,0x6);       // 6
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000014,0x1);       // 1
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000018,0x5);       // 5
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000001C,0x8);       // 8
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000020,0x3);       // 3
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000024,0x0);       //
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000028,0x0);       //
// 
//     for ( i = 0xb ; i < 0x3C00 ; i ++){
//         VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000 + i * 0x4,0x0);
//     }


                                         
//     //在内存中写入数据，用于检测: Binary Tree Test                                       //In Memory:
//                                                                                          //    Address     Context     Comment
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000,0x1);        //  0x50000000       1        node_1 data
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000004,0x0);        //  0x50000004      NULL      left_point
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000008,0x5000000C); //  0x50000008    0x5000000C  right pointer: point to node_2
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000000C,0x2);        //  0x5000000C       2        node_2 data
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000010,0x50000020); //  0x50000010    0x50000020  left pointer: point to node_3
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000014,0x0);        //  0x50000014      NULL      
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000018,0x0);        //  0x50000018      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000001C,0x0);        //  0x5000001C      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000020,0x3);        //  0x50000020       3        node_3 data
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000024,0x50000038); //  0x50000024    0x50000038  left pointer: point to node_4 
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000028,0x50000050); //  0x50000028    0x50000050  left pointer: point to node_5
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000002C,0x0);        //  0x5000002C      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000030,0x0);        //  0x50000030      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000034,0x0);        //  0x50000034      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000038,0x4);        //  0x50000038       4        
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000003C,0x0);        //  0x5000003C      NULL
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000040,0x0);        //  0x50000040      NULL
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000044,0x0);        //  0x50000044      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000048,0x0);        //  0x50000048      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000004C,0x0);        //  0x5000004C      ...       otherdata
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000050,0x5);        //  0x50000050      5
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000054,0x0);        //  0x50000054     NULL
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000058,0x0);        //  0x50000058     NULL

    //CMPS 等指令测试 数据：
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000,0xa4);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000004,0x12);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000008,0x35);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000000c,0x1);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000010,0x18);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000014,0x99);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000018,0x6);
// 
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000020,0xa4);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000024,0x12);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000028,0x35);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000002c,0x1);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000030,0x17);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000034,0x99);
//     vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000038,0x6);

    return vm_err;
}

VM_ERR_CODE VM_Emu_Initialize(PVM_Emulator_t pEmulator)
{
    VM_ERR_CODE vm_err;
    assert(NULL != pEmulator);

    if(NULL == pEmulator){
        return VM_ERR_FATAL_NULL_POINTER;
    }

    memset(pEmulator, 0, sizeof(VM_Emulator_t));
    pEmulator->Status = STOPPED;
#ifdef VM_ISA_INTEL_X86_32_BIT
    JIF(VM_Intel_x86_InitializeCpuStructure(&pEmulator->CPUStructure));
    JIF(VM_Intel_x86_InitializeControlUnit(&pEmulator->ControlUnit));

    VM_MM_InitializeMemory();
//-----------------------------------------------------------
    //临时用于监控的代码，后期需要修改！！！
    uLastAccessMemoryStart = 0;
    siLastAccessMemorySize = 0;
    MemoryAccesLogListHeadNode = NULL;

    //要EIP初始化批向代码段
    JIF(VM_MM_InitializeMemoryBlock(&pEmulator->Memory.CodeSegment, 0x40000000, 0xf000));
    ACCESS_GEN_CS(*((PVM_Intel_x86_ISA_t)(pEmulator->CPUStructure.ISAPointer))) = 0x0;
    ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(pEmulator->CPUStructure.ISAPointer))) = 0x40000000;

    //类似还有DS,SS等段的设置
    JIF(VM_MM_InitializeMemoryBlock(&pEmulator->Memory.DataSegment, 0x50000000, 0xf000));
    ACCESS_GEN_DS(*((PVM_Intel_x86_ISA_t)(pEmulator->CPUStructure.ISAPointer))) = 0x0;

    JIF(VM_MM_InitializeMemoryBlock(&pEmulator->Memory.StackSegment, 0x60000000, 0xf000));
    //SS段选择符，段选择机制没有使用。
    ACCESS_GEN_ES(*((PVM_Intel_x86_ISA_t)(pEmulator->CPUStructure.ISAPointer))) = 0x0;
    //栈高地址向低地址扩展！
    ACCESS_GEN_ESP(*((PVM_Intel_x86_ISA_t)(pEmulator->CPUStructure.ISAPointer))) = 0x60000000+0xf000 - 4 ;//0x60000004;

    //设置默认栈数据位(Stack-Size)大小
    pEmulator->Memory.StackSegment.uSegmentDescriptor[1] |= SEGMENT_DESCRIPTOR_MASK_DB;    

#endif
    //pEmulator->ControlUnit
    return VM_ERR_NO_ERROR;
}

VM_ERR_CODE VM_Emu_Uninitialize(PVM_Emulator_t pEmulator)
{
    VM_ERR_CODE vm_err;
    PNODE pNode;
    PNODE temp;

    assert(pEmulator);
    assert(pEmulator->CPUStructure.ISAPointer);

    VM_MM_UninitializeMemory();

    //临时用于监控的代码，后期需要修改！！！
    uLastAccessMemoryStart = 0;
    siLastAccessMemorySize = 0;
    pNode = MemoryAccesLogListHeadNode;
    temp = NULL;
    while(pNode){
        temp = pNode;
        pNode = pNode->pNext;
        free(temp);
    }
    MemoryAccesLogListHeadNode = NULL;

#ifdef VM_ISA_INTEL_X86_32_BIT
    if(NULL != pEmulator){
        VM_Intel_x86_UninitializeCpuStructure(&pEmulator->CPUStructure);
        JIF(VM_MM_UninitializeMemoryBlock(&pEmulator->Memory.CodeSegment));
        JIF(VM_MM_UninitializeMemoryBlock(&pEmulator->Memory.DataSegment));
        JIF(VM_MM_UninitializeMemoryBlock(&pEmulator->Memory.StackSegment));
    }
    else
        return VM_ERR_FATAL_NULL_POINTER;
#endif
    return VM_ERR_NO_ERROR;
}

#ifdef  __cplusplus
}
#endif
