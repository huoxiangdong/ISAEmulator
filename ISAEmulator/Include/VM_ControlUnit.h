#ifndef _VM_CONTROL_UNIT_H_
#define _VM_CONTROL_UNIT_H_
//
//�ļ����ƣ�        Include/VM_ControlUnit.h
//�ļ�������        ģ����CPU�ṹ��ض���
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��16��
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
//2009��6��16�գ���販(yanghongbo@ptwy.cn)������

#include "VM_Config.h"
#include "VM_Defines.h"

#include "VM_ISARelated.h"
#include "VM_Memory.h"

struct _VM_Emulator_t;
typedef void (*PFN_OUTPUT_CPU_STATE)(struct _VM_CPUStructure_t * pCpuStructure);
typedef VM_INSTRUCTION_ERR_CODE (*PFN_FETCH_ONE_INSTRUCTION)(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);
typedef VM_ERR_CODE (*PFN_EXECUTE_ONE_INSTRUCTION)(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);
typedef size_t (*PFN_GET_CURRENT_INSTRUCTION_MNEMONIC)(char *, size_t, const struct _VM_CPUStructure_t *);
//���ƣ�VM_ControlUnit_t
//������
//������־��2009��6��16�գ���販(yanghongbo@ptwy.cn)������
typedef struct _VM_ControlUnit_t {
    PFN_OUTPUT_CPU_STATE pfnOutputCpuState;
    PFN_FETCH_ONE_INSTRUCTION pfnFetchOneInstruction;
    PFN_EXECUTE_ONE_INSTRUCTION pfnExecuteOneInstruction;
    PFN_GET_CURRENT_INSTRUCTION_MNEMONIC pfnGetCurrentInstructionMnemonic;
}VM_ControlUnit_t, * PVM_ControlUnit_t;

//VM_ERR_CODE VM_CU_***();

#endif//_VM_CONTROL_UNIT_H_
