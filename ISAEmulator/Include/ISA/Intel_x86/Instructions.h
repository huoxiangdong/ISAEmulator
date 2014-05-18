#ifndef _INTEL_X86_INSTRUCTIONS_H_
#define _INTEL_X86_INSTRUCTIONS_H_
//
//文件名称：        Include/ISA/Intel_x86_Instructions.h
//文件描述：        Intel x86 CPU架构（ISA）指令仿真定义
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年8月3日
//
//公司名称：        北京普天网怡科技有限公司
//项目组名：
//保密级别：
//版权声明：
//
//主项目名称：      基于虚拟机的漏洞挖掘平台
//主项目描述：
//主项目启动时间：  2009年6月X日
//
//子项目名称：      虚拟机及环境仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日
//
//模块名称：        指令仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日

//
//Update Log:
//更新日志：
//2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，创建
//2010年4月8日，杨鸿博(yanghongbo@ptwy.cn)，更新，开始增加双字节指令

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