//
//文件名称：        src/VM_Memory.c
//文件描述：        虚拟机内存管理
//创建人：          杨鸿博(yanghongbo@ptwy.cn)，创建
//创建日期：        2009年9月27日
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
//2009年9月27日，杨鸿博(yanghongbo@ptwy.cn)，创建
//2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，更新。修改内存访问模块。为了加快实现速度，目前保持原有的结构不变。
//                                                  仅修改内存模块访问的pBlock->pMemoryBlock， 为新的Memory.c
//                                                  的访问方案。工程可以运作之后，再进行完整的修改。
//                                                  修改现在的PVM_MemoryBlock_t保存的内存信息，为_VM_Intel_x86_ISA_t
//                                                  中保存的信息(VM_Intel_x86_SegmentRegister_t sSegmentRegisters)
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "VM_Defines.h"
#include "VM_Log.h"
#include "ISA/Intel_x86/MemoryPageTable.h"
#include "ISA/Intel_x86/Memory.h"
#include "VM_Memory.h"

#ifdef  __cplusplus
extern "C" {
#endif

//在VM_Emulator.c中定义
extern UINT uLastAccessMemoryStart;
extern size_t siLastAccessMemorySize;

void VM_MM_InitializeMemory()
{
    MemInitialize();
}
void VM_MM_UninitializeMemory()
{
    MemUninitialize();
}

//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
VM_ERR_CODE VM_MM_InitializeMemoryBlock(PVM_MemoryBlock_t pBlock, UINT uStartAddr, size_t MemorySize)
{
    assert(pBlock);
    //assert(NULL == pBlock->pMemoryBlock);
    assert(0 == pBlock->uBlockSize);
    //pBlock->pMemoryBlock = malloc(MemorySize);
    //if(NULL != pBlock->pMemoryBlock)

    {
        pBlock->uBlockSize = MemorySize;
        pBlock->uStartAddr = uStartAddr;
        return VM_ERR_NO_ERROR;
    }
    return VM_ERR_FATAL_INSUFFICIENT_MEMORY;
}
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
VM_ERR_CODE VM_MM_UninitializeMemoryBlock(PVM_MemoryBlock_t pBlock)
{
    //assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //free(pBlock->pMemoryBlock);
    //pBlock->pMemoryBlock = NULL;
    //pBlock->uBlockSize = 0;
    return VM_ERR_NO_ERROR;
}
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
BYTE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, UINT addr)
{
    BYTE byData = 0;
    VM_ERR_CODE err;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);   //起点检查
    //assert(addr <=  pBlock->uBlockSize);//终点检查
    //Correct 
    //assert(addr <=  pBlock->uStartAddr + pBlock->uBlockSize);

    //addr - pBlock->uStartAddr = 内存中的偏移值
    //return *(PBYTE)(pBlock->pMemoryBlock + addr - pBlock->uStartAddr );

    err = MemReadByte(addr, &byData);

    if(VM_ERR_NO_ERROR == err){
        return byData;
    }

    VM_LOG();
    return 0;
}
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
WORD VM_MM_ReadOneWord(PVM_MemoryBlock_t pBlock, UINT addr)
{
    WORD wData = 0;
    VM_ERR_CODE err;

    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr <=  pBlock->uBlockSize);//终点检查
    //Correct 
    //assert(addr +1 <=  pBlock->uStartAddr + pBlock->uBlockSize);
    //return * (PWORD)(pBlock->pMemoryBlock + addr  - pBlock->uStartAddr);
    
    err = MemReadWord(addr, &wData);

    if(VM_ERR_NO_ERROR == err){
        return wData;
    }

    VM_LOG();
    return 0;
}

//函数名称：        VM_MM_ReadOneDWord
//函数描述：        指定的内存地址中读取双字(double word)数据
//返回值：          正确：读取到的数据
//参数描述：        PVM_MemoryBlock_t ： pBlock ,内存模块,
//Intel IA-32 processor are "little endian" machines,
//Example:
//内存的内容:
//Addr: 0000 0000  ->  78
//Addr: 0000 0001  ->  56
//Addr: 0000 0002  ->  34
//Addr: 0000 0003  ->  12
//
//参数为 : addr = 0x0000 0000   , 地址为要读取的 数据的最低字节 所在的内存单元地址
//
//结果写入的内存结果为：dwData = 0x12345678
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
DWORD VM_MM_ReadOneDWord(PVM_MemoryBlock_t pBlock, UINT addr)
{
    DWORD dwData = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;

    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr + 3 <= pBlock->uStartAddr + pBlock->uBlockSize);
    //return *((PDWORD)pBlock->pMemoryBlock + addr  - pBlock->uStartAddr);  //如此返回，Error
    //return *(PDWORD)(pBlock->pMemoryBlock + addr  - pBlock->uStartAddr);

    err = MemReadDWord(addr, &dwData);

    if(VM_ERR_NO_ERROR == err){
        return dwData;
    }

    VM_LOG();
    return 0;

}

//函数参数定义有缺陷。应该将缓冲大小与需要读取的大小分离
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
//                      另：参数表应该改:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
VM_ERR_CODE VM_MM_ReadOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pDst, size_t Size)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    assert(pDst);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(Size > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr + (Size - 1) <= pBlock->uBlockSize);
    
    //memcpy(pDst, pBlock->pMemoryBlock, Size);
    return MemCopyToVMBuffer(pDst, Size, addr, Size);
}
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
VM_ERR_CODE VM_MM_WriteOneByte(PVM_MemoryBlock_t pBlock, UINT addr, BYTE byData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert( addr - pBlock->uStartAddr <=  pBlock->uBlockSize);

    //addr - pBlock->uStartAddr 求得：写入的数据在已分配的内存中的偏移量
    //*(PBYTE)(pBlock->pMemoryBlock + addr - pBlock->uStartAddr) = byData;
    //return VM_ERR_NO_ERROR;

    err = MemWriteByte(addr, byData);
    uLastAccessMemoryStart = addr ;
    siLastAccessMemorySize = 1;

    if(VM_ERR_NO_ERROR != err){
        VM_LOG();
    }
    return err;
}
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
VM_ERR_CODE VM_MM_WriteOneWord(PVM_MemoryBlock_t pBlock, UINT addr, WORD wData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert( addr - pBlock->uStartAddr + 1 <=  pBlock->uBlockSize);
    //*((PDWORD)pBlock->pMemoryBlock + addr) = wData;

    //addr - pBlock->uStartAddr 求得：写入的数据在已分配的内存中的偏移量

    //Intel IA-32 processor are "little endian" machines,
    //0x12345678 
    //Addr: 0000 0000  ->  78
    //Addr: 0000 0001  ->  56
    //Addr: 0000 0002  ->  34
    //Addr: 0000 0003  ->  12
    //So in the PVM_MemoryBlock_t : Addr is increase
    //For example :the PVM_MemoryBlock_t has 512 Bytes ,and pBlock point to this memory , uStartAddr is 0x5000 0000
    // pBlock + 1 mean that : now the address is : 0x5000 0001
    //*(PWORD)(pBlock->pMemoryBlock + addr - pBlock->uStartAddr) = wData;

    //return VM_ERR_NO_ERROR;

    err = MemWriteWord(addr, wData);

    uLastAccessMemoryStart = addr ;
    siLastAccessMemorySize = 2;
    if(VM_ERR_NO_ERROR != err){
        VM_LOG();
    }
    return err;
}

//函数名称：        VM_MM_WriteOneDWord
//函数描述：        写入双字(double word)块到指定的内存地址中
//返回值：          正确：VM_ERR_NO_ERROR
//参数描述：        PVM_MemoryBlock_t ： pBlock ,内存模块,
//Intel IA-32 processor are "little endian" machines,
//Example:
//参数为 : addr = 0x0000 0000 , dwData = 0x12345678
//结果写入的内存结果为：
//Addr: 0000 0000  ->  78
//Addr: 0000 0001  ->  56
//Addr: 0000 0002  ->  34
//Addr: 0000 0003  ->  12
//更新日志:             2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
VM_ERR_CODE VM_MM_WriteOneDWord(PVM_MemoryBlock_t pBlock, UINT addr, DWORD dwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);//新的内存访问方案不需要限制访问空间
    //assert(pBlock->uBlockSize > 0);//新的内存访问方案不需要限制访问空间
    //assert(addr >= pBlock->uStartAddr);//新的内存访问方案不需要限制访问空间
    //assert( addr - pBlock->uStartAddr + 3 <=  pBlock->uBlockSize);//新的内存访问方案不需要限制访问空间
    //*(PDWORD)(pBlock->pMemoryBlock + addr - pBlock->uStartAddr) = dwData;
    //return VM_ERR_NO_ERROR;

    err = MemWriteDWord(addr, dwData);

    uLastAccessMemoryStart = addr ;
    siLastAccessMemorySize = 4;
    if(VM_ERR_NO_ERROR != err){
        VM_LOG();
    }
    return err;
}


//函数名称：        VM_MM_WriteOneBlock
//函数描述：        写入一块指定大小的数据块到指定的内存地址中
//返回值：          正确：VM_ERR_NO_ERROR
//参数描述：        PVM_MemoryBlock_t ： pBlock ,内存模块, 
//                  UINT  ： addr ,内存块的起始地址
//                  BYTE *： pSrc ,指向待写入的数据缓冲区
//                  size_t： 写入的数据大小
//更新日志:         2009年9月21日，劳生(laosheng@ptwy.cn)，添加备注
//                  2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，修改内存访问代码，使用内存页方式。
//                  //另：参数表应该改:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
VM_ERR_CODE VM_MM_WriteOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    //assert(pBlock);
    assert(pSrc);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(Size > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr + (Size - 1) <= malloc()函数分配的内存起始地址 + pBlock->uBlockSize);
    //检查是否有足够空间，写入
    // addr - pBlock->uStartAddr = ① 求得 要写入的偏移量
    // ① + size -1 = ②　求得写入的结束地址
    //assert( addr - pBlock->uStartAddr + (Size - 1) <=  pBlock->uBlockSize);

    //memcpy(pBlock->pMemoryBlock, pSrc, Size);

    //return VM_ERR_NO_ERROR;

    err = MemCopyFromVMBuffer(addr, Size, pSrc, Size);
    uLastAccessMemoryStart = addr ;
    siLastAccessMemorySize = Size ;
    if(VM_ERR_NO_ERROR != err){
        VM_LOG();
    }
    return err;
}

#ifdef  __cplusplus
}
#endif
