#ifndef _VM_MEMORY_H_
#define _VM_MEMORY_H_
//
//�ļ����ƣ�        Include/VM_MemoryManagement.h
//�ļ�������        ������ڴ����ӿ�
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��18��
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
//Update Log:
//������־��
//2009��6��18�գ���販(yanghongbo@ptwy.cn)������


#include "VM_Defines.h"

#ifdef  __cplusplus
extern "C" {
#endif



//���ƣ�_VM_MemoryBlock_t
//������
//������־��2009��6��22�գ���販(yanghongbo@ptwy.cn)������
//           2009��9��17�գ���販(yanghongbo@ptwy.cn)���޸ı���
//
typedef struct _VM_MemoryBlock_t {
    UINT32 uSegmentDescriptor[2];
    //MEMORY_SIZE uMemoryBlockSize;��SegmentDescriptor�еõ�
    //BYTE *  pMemoryBlock;
    UINT    uStartAddr;//��Ŀ������ӳ���ַ
    size_t  uBlockSize;
}VM_MemoryBlock_t, * PVM_MemoryBlock_t;

//���ƣ�_VM_Memory_t
//������
//������־��2009��6��24�գ���販(yanghongbo@ptwy.cn)������
//           2009��9��17�գ���販(yanghongbo@ptwy.cn)���޸ı���
//
typedef struct _VM_Memory_t {
    VM_MemoryBlock_t CodeSegment;
    VM_MemoryBlock_t DataSegment;
    VM_MemoryBlock_t StackSegment;
}VM_Memory_t, * PVM_Memory_t;

//��ʱ��˶���
VM_ERR_CODE VM_MM_InitializeMemoryBlock(PVM_MemoryBlock_t pBlock, UINT uStartAddr, size_t MemorySize);
VM_ERR_CODE VM_MM_UninitializeMemoryBlock(PVM_MemoryBlock_t pBlock);

void VM_MM_InitializeMemory();
void VM_MM_UninitializeMemory();

BYTE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, UINT addr);
//����������ʽVM_ERR_CODE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, ADDRESS addr, BYTE * pbyData);
WORD VM_MM_ReadOneWord(PVM_MemoryBlock_t pBlock, UINT addr);
DWORD VM_MM_ReadOneDWord(PVM_MemoryBlock_t pBlock, UINT addr);
//������Ӧ�ø�:BYTE * pDst, size_t Size, PVM_MemoryBlock_t pBlock, UINT addr, size_t sizeToRead
VM_ERR_CODE VM_MM_ReadOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pDst, size_t Size);
VM_ERR_CODE VM_MM_WriteOneByte(PVM_MemoryBlock_t pBlock, UINT addr, BYTE byData);
VM_ERR_CODE VM_MM_WriteOneWord(PVM_MemoryBlock_t pBlock, UINT addr, WORD wData);
VM_ERR_CODE VM_MM_WriteOneDWord(PVM_MemoryBlock_t pBlock, UINT addr, DWORD dwData);
//������Ӧ�ø�:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
VM_ERR_CODE VM_MM_WriteOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size);

#ifdef  __cplusplus
}
#endif


#endif//_VM_MEMORY_H_

