//
//�ļ����ƣ�        src/VM_Memory.c
//�ļ�������        ������ڴ����
//�����ˣ�          ��販(yanghongbo@ptwy.cn)������
//�������ڣ�        2009��9��27��
//
//��˾���ƣ�        �������������Ƽ����޹�˾
//��Ŀ������
//���ܼ���
//��Ȩ������
//
//����Ŀ���ƣ�      �����������©���ھ�ƽ̨
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//����Ŀ���ƣ�      �����������������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//ģ�����ƣ�        ָ�������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��

//
//������־��
//2009��9��27�գ���販(yanghongbo@ptwy.cn)������
//2010��3��22�գ���販(yanghongbo@ptwy.cn)�����¡��޸��ڴ����ģ�顣Ϊ�˼ӿ�ʵ���ٶȣ�Ŀǰ����ԭ�еĽṹ���䡣
//                                                  ���޸��ڴ�ģ����ʵ�pBlock->pMemoryBlock�� Ϊ�µ�Memory.c
//                                                  �ķ��ʷ��������̿�������֮���ٽ����������޸ġ�
//                                                  �޸����ڵ�PVM_MemoryBlock_t������ڴ���Ϣ��Ϊ_VM_Intel_x86_ISA_t
//                                                  �б������Ϣ(VM_Intel_x86_SegmentRegister_t sSegmentRegisters)
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

//��VM_Emulator.c�ж���
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

//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
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
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
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
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
BYTE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, UINT addr)
{
    BYTE byData = 0;
    VM_ERR_CODE err;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);   //�����
    //assert(addr <=  pBlock->uBlockSize);//�յ���
    //Correct 
    //assert(addr <=  pBlock->uStartAddr + pBlock->uBlockSize);

    //addr - pBlock->uStartAddr = �ڴ��е�ƫ��ֵ
    //return *(PBYTE)(pBlock->pMemoryBlock + addr - pBlock->uStartAddr );

    err = MemReadByte(addr, &byData);

    if(VM_ERR_NO_ERROR == err){
        return byData;
    }

    VM_LOG();
    return 0;
}
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
WORD VM_MM_ReadOneWord(PVM_MemoryBlock_t pBlock, UINT addr)
{
    WORD wData = 0;
    VM_ERR_CODE err;

    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr <=  pBlock->uBlockSize);//�յ���
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

//�������ƣ�        VM_MM_ReadOneDWord
//����������        ָ�����ڴ��ַ�ж�ȡ˫��(double word)����
//����ֵ��          ��ȷ����ȡ��������
//����������        PVM_MemoryBlock_t �� pBlock ,�ڴ�ģ��,
//Intel IA-32 processor are "little endian" machines,
//Example:
//�ڴ������:
//Addr: 0000 0000  ->  78
//Addr: 0000 0001  ->  56
//Addr: 0000 0002  ->  34
//Addr: 0000 0003  ->  12
//
//����Ϊ : addr = 0x0000 0000   , ��ַΪҪ��ȡ�� ���ݵ�����ֽ� ���ڵ��ڴ浥Ԫ��ַ
//
//���д����ڴ���Ϊ��dwData = 0x12345678
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
DWORD VM_MM_ReadOneDWord(PVM_MemoryBlock_t pBlock, UINT addr)
{
    DWORD dwData = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;

    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr + 3 <= pBlock->uStartAddr + pBlock->uBlockSize);
    //return *((PDWORD)pBlock->pMemoryBlock + addr  - pBlock->uStartAddr);  //��˷��أ�Error
    //return *(PDWORD)(pBlock->pMemoryBlock + addr  - pBlock->uStartAddr);

    err = MemReadDWord(addr, &dwData);

    if(VM_ERR_NO_ERROR == err){
        return dwData;
    }

    VM_LOG();
    return 0;

}

//��������������ȱ�ݡ�Ӧ�ý������С����Ҫ��ȡ�Ĵ�С����
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
//                      ��������Ӧ�ø�:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
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
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
VM_ERR_CODE VM_MM_WriteOneByte(PVM_MemoryBlock_t pBlock, UINT addr, BYTE byData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert( addr - pBlock->uStartAddr <=  pBlock->uBlockSize);

    //addr - pBlock->uStartAddr ��ã�д����������ѷ�����ڴ��е�ƫ����
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
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
VM_ERR_CODE VM_MM_WriteOneWord(PVM_MemoryBlock_t pBlock, UINT addr, WORD wData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert( addr - pBlock->uStartAddr + 1 <=  pBlock->uBlockSize);
    //*((PDWORD)pBlock->pMemoryBlock + addr) = wData;

    //addr - pBlock->uStartAddr ��ã�д����������ѷ�����ڴ��е�ƫ����

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

//�������ƣ�        VM_MM_WriteOneDWord
//����������        д��˫��(double word)�鵽ָ�����ڴ��ַ��
//����ֵ��          ��ȷ��VM_ERR_NO_ERROR
//����������        PVM_MemoryBlock_t �� pBlock ,�ڴ�ģ��,
//Intel IA-32 processor are "little endian" machines,
//Example:
//����Ϊ : addr = 0x0000 0000 , dwData = 0x12345678
//���д����ڴ���Ϊ��
//Addr: 0000 0000  ->  78
//Addr: 0000 0001  ->  56
//Addr: 0000 0002  ->  34
//Addr: 0000 0003  ->  12
//������־:             2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
VM_ERR_CODE VM_MM_WriteOneDWord(PVM_MemoryBlock_t pBlock, UINT addr, DWORD dwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    assert(pBlock);
    //assert(pBlock->pMemoryBlock);//�µ��ڴ���ʷ�������Ҫ���Ʒ��ʿռ�
    //assert(pBlock->uBlockSize > 0);//�µ��ڴ���ʷ�������Ҫ���Ʒ��ʿռ�
    //assert(addr >= pBlock->uStartAddr);//�µ��ڴ���ʷ�������Ҫ���Ʒ��ʿռ�
    //assert( addr - pBlock->uStartAddr + 3 <=  pBlock->uBlockSize);//�µ��ڴ���ʷ�������Ҫ���Ʒ��ʿռ�
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


//�������ƣ�        VM_MM_WriteOneBlock
//����������        д��һ��ָ����С�����ݿ鵽ָ�����ڴ��ַ��
//����ֵ��          ��ȷ��VM_ERR_NO_ERROR
//����������        PVM_MemoryBlock_t �� pBlock ,�ڴ�ģ��, 
//                  UINT  �� addr ,�ڴ�����ʼ��ַ
//                  BYTE *�� pSrc ,ָ���д������ݻ�����
//                  size_t�� д������ݴ�С
//������־:         2009��9��21�գ�����(laosheng@ptwy.cn)����ӱ�ע
//                  2010��3��22�գ���販(yanghongbo@ptwy.cn)���޸��ڴ���ʴ��룬ʹ���ڴ�ҳ��ʽ��
//                  //��������Ӧ�ø�:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
VM_ERR_CODE VM_MM_WriteOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size)
{
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    //assert(pBlock);
    assert(pSrc);
    //assert(pBlock->pMemoryBlock);
    //assert(pBlock->uBlockSize > 0);
    //assert(Size > 0);
    //assert(addr >= pBlock->uStartAddr);
    //assert(addr + (Size - 1) <= malloc()����������ڴ���ʼ��ַ + pBlock->uBlockSize);
    //����Ƿ����㹻�ռ䣬д��
    // addr - pBlock->uStartAddr = �� ��� Ҫд���ƫ����
    // �� + size -1 = �ڡ����д��Ľ�����ַ
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
