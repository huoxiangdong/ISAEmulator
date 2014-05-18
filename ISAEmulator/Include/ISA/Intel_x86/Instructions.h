#ifndef _INTEL_X86_INSTRUCTIONS_H_
#define _INTEL_X86_INSTRUCTIONS_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86_Instructions.h
//�ļ�������        Intel x86 CPU�ܹ���ISA��ָ����涨��
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��8��3��
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
//2009��8��3�գ���販(yanghongbo@ptwy.cn)������
//2010��4��8�գ���販(yanghongbo@ptwy.cn)�����£���ʼ����˫�ֽ�ָ��

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "Instructions/aaa.h"
#include "Instructions/aad.h"
#include "Instructions/aam.h"
#include "Instructions/aas.h"
#include "Instructions/adc.h"
#include "Instructions/add.h"
#include "Instructions/and.h"
#include "Instructions/bound.h"
#include "Instructions/call.h"
#include "Instructions/cmp.h"
#include "Instructions/cmps.h"
#include "Instructions/daa.h"
#include "Instructions/das.h"
#include "Instructions/dec.h"
#include "Instructions/div.h"
#include "Instructions/enter.h"
#include "Instructions/idiv.h"
#include "Instructions/imul.h"
#include "Instructions/inc.h"
#include "Instructions/jcc.h"
#include "Instructions/jmp.h"
#include "Instructions/lahf.h"
#include "Instructions/lds.h"
#include "Instructions/leave.h"
#include "Instructions/les.h"
#include "Instructions/lodscc.h"
#include "Instructions/loopcc.h"
#include "Instructions/misc.h"
#include "Instructions/mov.h"
#include "Instructions/movs.h"
#include "Instructions/mul.h"
#include "Instructions/neg.h"
#include "Instructions/nop.h"
#include "Instructions/not.h"
#include "Instructions/or.h"
#include "Instructions/pop.h"
#include "Instructions/popf.h"
#include "Instructions/push.h"
#include "Instructions/pushf.h"
#include "Instructions/rcl.h"
#include "Instructions/rcr.h"
#include "Instructions/ret.h"
#include "Instructions/rol.h"
#include "Instructions/ror.h"
#include "Instructions/sahf.h"
#include "Instructions/sal.h"
#include "Instructions/sar.h"
#include "Instructions/sbb.h"
#include "Instructions/scas.h"
#include "Instructions/shr.h"
#include "Instructions/stoscc.h"
#include "Instructions/sub.h"
#include "Instructions/test.h"
#include "Instructions/xchg.h"
#include "Instructions/xlat.h"
#include "Instructions/xor.h"

//two-byte opcode
#include "Instructions/movxx.h"

#endif //_INTEL_X86_INSTRUCTIONS_H_