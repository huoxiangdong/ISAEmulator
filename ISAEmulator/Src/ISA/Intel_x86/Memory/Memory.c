//
//�ļ����ƣ�        src/ISA/Intel_x86/Memory/Memory.c
//�ļ�������        Intel x86�ܹ��µ��ڴ�ģ��
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��3��22��
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
//2010��3��22�գ���販(yanghongbo@ptwy.cn)������

#include "VM_Defines.h"
#include "ISA/Intel_x86/MemoryPageTable.h"
#include "ISA/Intel_x86/Memory.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define _CRT_SECURE_NO_DEPRECATE 1

void MemInitialize()
{
    MemPageInitialize();
}

void MemUninitialize()
{
    MemPageUninitialize();
}

VM_ERR_CODE MemReadWord(UINT uAddr, PWORD pwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    WORD wData = 0;
    BYTE byData = 0;
    assert(pwData);
    if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr) || (PAGE_OFFSET_MASK(uAddr) < PAGE_SIZE)){
        //˫�ֽ�δ���룬���߲�����ҳ����
        err = MemReadByte(uAddr, &byData);
        if(VM_ERR_NO_ERROR == err){
            wData = byData;
            err = MemReadByte(uAddr+1, &byData);
            if(VM_ERR_NO_ERROR == err){
                wData |= byData << 8;
                *pwData = wData;
            }
        }
    }
    else {
        //��ַ�ֽڶ���
        err = MemPageReadWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pwData);
    }

    return err;
}



VM_ERR_CODE MemWriteWord(UINT uAddr, WORD wData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    BYTE byData = 0;
    if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr) || (PAGE_OFFSET_MASK(uAddr) < PAGE_SIZE)){
        //˫�ֽ�δ���룬���߲�����ҳ����
        err = MemWriteByte(uAddr, (BYTE)(wData & 0xff));
        if(VM_ERR_NO_ERROR == err){
            err = MemWriteByte(uAddr+1, (BYTE)(wData >> 8));
        }
    }
    else {
        //��ַ�ֽڶ���
        err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), wData);
    }
    return err;
}



VM_ERR_CODE MemReadDWord(UINT uAddr, PDWORD pdwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    DWORD dwData = 0;
    WORD wData = 0;
    BYTE byData = 0;

    assert(pdwData);
    if(IS_PAGE_ADDRESS_DWORD_ALIGNED(uAddr)){
        //��ַ�ֽڶ���
        err = MemPageReadDWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pdwData);
    }
    else if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr)){
        //˫�ֽ�δ����
        err = MemPageReadWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), &wData);
        if(VM_ERR_NO_ERROR == err){//����һ����
            dwData = wData;
            err = MemPageReadWord(PAGE_INDEX_MASK(uAddr+2), PAGE_OFFSET_MASK(uAddr+2), &wData);//�п��ܲ�����ҳ����
            if(VM_ERR_NO_ERROR == err){//���ڶ�����
                dwData |= (DWORD)wData << 16;
                *pdwData = dwData;
            }
        }
    }
    else {
        err = MemReadByte(uAddr, &byData);
        if(VM_ERR_NO_ERROR == err){//����һ���ֽ�
            dwData = byData;
            err = MemReadWord(uAddr+1, &wData);//���ﴦ���ҳ����
            if(VM_ERR_NO_ERROR == err){//���ڶ��������ֽ�
                dwData |= (DWORD)wData << 8;
                err = MemReadByte(uAddr+3, &byData);
                if(VM_ERR_NO_ERROR == err){//�����ĸ��ֽ�
                    dwData |= (DWORD)byData << 24;
                    *pdwData = dwData;
                }
            }
        }
    }

    return err;
}



VM_ERR_CODE MemWriteDWord(UINT uAddr, DWORD dwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;

    if(IS_PAGE_ADDRESS_DWORD_ALIGNED(uAddr)){
        //˫�ֶ���
        err = MemPageWriteDWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), dwData);
    }
    else if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr)){
        //�ֶ���
        err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), (WORD)(dwData & 0xffff));
        if(VM_ERR_NO_ERROR == err){
            err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr+2), PAGE_OFFSET_MASK(uAddr+2), (WORD)(dwData >> 16));
        }
    }
    else {
        //δ����
        err = MemWriteByte(uAddr, (BYTE)(dwData & 0xff));
        if(VM_ERR_NO_ERROR == err){
            err = MemWriteWord(uAddr+1, (WORD)(((dwData >> 8) & 0xffff)));//���ﴦ���ҳ����
            if(VM_ERR_NO_ERROR == err){
                err = MemWriteByte(uAddr, (BYTE)(dwData & 0xff));
            }
        }
    }
    return err;
}

/*
VM_ERR_CODE MemCopy(UINT srcAddr, UINT dstAddr)
{
    
}
*/

//�ϲ�����Ҫһ��ϵͳ������(Windows/Linux)�İ�װ
VM_ERR_CODE MemCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcAddr, size_t sizeToRead)
{
    return MemPageCopyToVMBuffer(pBuffer, sizeBuffer, PAGE_INDEX_MASK(uSrcAddr), PAGE_OFFSET_MASK(uSrcAddr), sizeToRead);
}

VM_ERR_CODE MemCopyFromVMBuffer(UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite)
{
    return MemPageCopyFromVMBuffer(PAGE_INDEX_MASK(uDstAddr), PAGE_OFFSET_MASK(uDstAddr), pBuffer, sizeBuffer, sizeToWrite);
}

#ifdef  __cplusplus
}
#endif
