#ifndef _MUL_H_
#define _MUL_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Instructions/mul.h
//�ļ�������        mulָ��ͷ�ļ�
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��7��
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
//2009��8��7�գ�����(laosheng@ptwy.cn)������

//Performs an unsigned multiplication of the first operand (destination operand) and 
//the second operand(source operand) and stores result in the destination operand.

VM_INSTRUCTION_ERR_CODE unary_grp3_f6_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

#endif //_MUL_H_