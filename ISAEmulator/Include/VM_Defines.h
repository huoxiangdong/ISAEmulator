#ifndef _VM_DEFINES_H_
#define _VM_DEFINES_H_
//
//�ļ����ƣ�        Include/VM_Defines.h
//�ļ�������        �����궨��
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��5��
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
//2009��6��5�գ���販(yanghongbo@ptwy.cn)������

//���ƣ��������Ͷ���
//������
//������־��2009��6��12�գ���販(yanghongbo@ptwy.cn)������
#include "VM_Config.h"
#ifdef  __cplusplus
extern "C" {
#endif

#define _NOT_IMPLEMENTED 0
#define VM_NOT_IMPLEMENTED() assert(_NOT_IMPLEMENTED);

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#define JIF(x)  \
            vm_err = (x);    \
            if(VM_ERR_NO_ERROR != vm_err){   \
                assert(VM_ERR_NO_ERROR == vm_err);  \
                return vm_err;                      \
            }

#if defined(VM_ISA_INTEL_X86_64_BIT)
//    typedef UINT64 ADDRESS;
//    typedef UINT64 MEMORY_SIZE;
#elif defined(VM_ISA_INTEL_X86_32_BIT)
//    typedef UINT32 ADDRESS;
//    typedef UINT32 MEMORY_SIZE;
    typedef unsigned long long int UINT64;
    typedef unsigned long int UINT32;
    typedef unsigned short int UINT16;

    typedef long long int INT64;
    typedef long int INT32;
    typedef short int INT16;
#endif

#define  _8_BITS    8
#define  _16_BITS  16
#define  _32_BITS  32
#define  _64_BITS  64

#define IN
#define OUT
#define INOUT

typedef unsigned int UINT;
typedef unsigned char UINT8;
typedef int INT;
typedef char INT8;

typedef int INT;
typedef INT BOOL;
#define FALSE 0
#define TRUE  1

typedef UINT8 BYTE;
typedef UINT16 WORD;
typedef UINT32 DWORD;

//ָ��
typedef void * PVOID;
typedef BYTE * PBYTE;
typedef WORD * PWORD;
typedef DWORD * PDWORD;

#ifndef NULL
#define NULL ((PVOID)0)
#endif

//���ƣ�VM_ERR_CODE
//�����������õĴ�����룬�󲿷ֺ���ʹ�õķ���ֵ
//������־��2009��6��5�գ���販(yanghongbo@ptwy.cn)������������ERR_NO_ERROR, ERR_FATAL
//��Ҫ�������ִ������ϲ�Ϊ��һ�ı�����
typedef enum _VM_ERR_CODE {
    VM_ERR_NO_ERROR = 0,                //����
    VM_ERR_FATAL_UNKNOWN,               //δ֪����
    VM_ERR_FATAL_NULL_POINTER,          //��ָ�����
    VM_ERR_FATAL_INVALID_POINTER,       //��Чָ��
    VM_ERR_FATAL_INSUFFICIENT_MEMORY,   //�ڴ治��
    VM_ERR_FATAL_CANNOT_EXECUTE_INSTRUCTION, //�޷�ִ��ָ��
    VM_ERR_NO_MORE_INSTRUCTION,         //û��ָ��
    VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION, //�Ƿ������ڴ�
    VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT, //�ڴ��ַδ����
    VM_ERR_FATAL_DEAD_LOOP,             //loop 0����ѭ��
    VM_ERR_FATAL_DEAD_MAXIMUM_LOOP,     //loop -X����ѭ������һ�����������
    VM_ERR_SHELLCODE_SEEMS_BE_FOUND,    //�ҵ�����shellcode
}VM_ERR_CODE;

typedef enum _VM_INSTRUCTION_ERR_CODE {
    VM_INSTRUCTION_ERR_SUCCEEDED = 0,                //����
    VM_INSTRUCTION_ERR_FATAL_UNKNOWN,
    VM_INSTRUCTION_ERR_NOT_IMPLEMENTED,
    VM_INSTRUCTION_ERR_INTEGER_OVERFLOW,                //����ʱ�Ĵ���û�а취����ϴ������ Integer overflow
    VM_INSTRUCTION_ERR_INVALID_OPCODE,
    VM_INSTRUCTION_ERR_INVALID_PARAMETER,
    VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO,
    VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM,          //�ɷ���VM_ERR_CODE�ĺ�������
}VM_INSTRUCTION_ERR_CODE;

#ifdef  __cplusplus
}
#endif

#endif//_VM_DEFINES_H_
