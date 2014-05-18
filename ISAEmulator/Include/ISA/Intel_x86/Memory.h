#ifndef _INTEL_X86_MEMORY_H_
#define _INTEL_X86_MEMORY_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Memory.h
//�ļ�������        Intel x86�ܹ��µ��ڴ�ģ���װ
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��3��16��
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
//2010��3��16�գ���販(yanghongbo@ptwy.cn)������

#define MEMORY_MAXIMUM_ADDRESS  PAGE_MAXIMUM_ADDRESS


void MemUninitialize();
void MemInitialize();


//�������ƣ�MemReadByte
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, PBYTE pData
//���������ڴ��ж�ȡһ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
//VM_ERR_CODE MemReadByte(UINT uAddr, PBYTE pbyData);
#define MemReadByte(uAddr, pbyData) MemPageReadByte(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pbyData)

//�������ƣ�MemWriteByte
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, BYTE data
//���������ڴ���д��һ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
#define MemWriteByte(uAddr, data) MemPageWriteByte(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), data)

//�������ƣ�MemReadWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, PWORD pData
//���������ڴ��ж�ȡһ����
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemReadWord(UINT uAddr, PWORD pwData);
//�������ƣ�MemWriteWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, BYTE data
//���������ڴ���д��һ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemWriteWord(UINT uAddr, WORD wData);
//�������ƣ�MemReadDWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, PDWORD pdwData
//���������ڴ��ж�ȡһ��˫��
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemReadDWord(UINT uAddr, PDWORD pdwData);

//�������ƣ�MemWriteWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uAddr, DWORD dwData
//���������ڴ���д��һ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemWriteDWord(UINT uAddr, DWORD dwData);

//�������ƣ�MemCopyFromVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite
//�����������������Ƶ����⻷���ڴ���
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemCopyFromVMBuffer(UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite);

//�������ƣ�MemCopyToVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite
//�����������⻷���ڴ��и��Ƶ�������
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcAddr, size_t sizeToRead);
#endif //_INTEL_X86_MEMORY_H_