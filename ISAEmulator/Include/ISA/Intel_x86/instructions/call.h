#ifndef _CALL_H_
#define _CALL_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Instructions/call.h
//�ļ�������        callָ��ͷ�ļ�
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��17��
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
//2009��8��17�գ�����(laosheng@ptwy.cn)������

VM_INSTRUCTION_ERR_CODE call_9a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE call_e8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_2_call(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_3_call(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

#endif //_CALL_H_