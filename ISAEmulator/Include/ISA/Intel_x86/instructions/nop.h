#ifndef _NOP_H_
#define _NOP_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Instructions/nop.h
//�ļ�������        nopָ��ͷ�ļ�
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


//Replaces the value of operand(the destination operand) with its two's complement.
//(This operation is equivalent to subtracting the operand from 0.)

VM_INSTRUCTION_ERR_CODE nop_90(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

#endif //_NOP_H_