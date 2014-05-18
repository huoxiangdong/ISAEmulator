#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "VM_Defines.h"
#include "ISA/Intel_x86/testsuite.h"

#pragma warning (once: 4409 4731 4410 4101 4102);

PBYTE GetMovxxBinCode(size_t * pCodeSize)
{
    PBYTE pBinCode = NULL;
    PBYTE pStart = NULL;
    PBYTE pEnd = NULL;
    INT8 charTest;
    INT16 shortIntTest;
    INT32 intTest;        //32Bits 
    long long int longLongIntTest; //64Bit

    assert(pCodeSize);
    _asm {
        jmp getpointer
codestart:
        mov ah, -1
        movsx dx, ah
        movsx edx, ah
        movzx dx, ah
        movzx edx, ah

        mov ax, -1
        movsx edx, ax
        movzx edx, ax

getpointer:
           mov ebx, codestart
           mov [pStart], ebx
           mov eax, getpointer
           mov [pEnd], eax
    }

    
    *pCodeSize = (size_t)(pEnd - pStart);
    pBinCode = pStart;//(PBYTE)malloc(*pCodeSize);

    return pBinCode;
}

PBYTE GetTestBinraryCode(size_t * pCodeSize)
{
    return GetMovxxBinCode(pCodeSize);
}

PBYTE GetTestBinraryCode2(size_t * pCodeSize)
{
    PBYTE pBinCode = NULL;
    PBYTE pStart = NULL;
    PBYTE pEnd = NULL;
    INT8 charTest;
    INT16 shortIntTest;
    INT32 intTest;        //32Bits 
    long long int longLongIntTest; //64Bit

    assert(pCodeSize);
    _asm {
        jmp getpointer
codestart:
//         xor    eax , eax
//         xor    edx , edx 
//         xor    ecx , ecx
//         mov    ebx , 0x50000000      
//         mov    eax , 0x62e147ad
//         mov    ecx , 0x62e147ad
//         mov    edx , 0x62e147ad
// 
//         mov    dword ptr[ebx+22h] , 0x12345678
//         mov    dword ptr[ebx+2222h] , 0x12345678

        //Building A binary Search Tree
        //There is no doubt what to do with entry number 1 when it arrives. It will be placed in a  leaf node whose left and right pointers should both be set to NULL
        //Node number 2 goes above node 1. Since node2 links to need 1 , we obviously must keep some way to remember where node 1 is until entry 2 arrives.
        //Node3 is again a leaf ,but it is in the right subtree of node2,so we must remember a pointer to node 2

        //Does this mean that we must keep a list of pointers to all nodes previously processed , to determine how to link in the next one ?
        //The answer is no, since when node 2 is added , all connections for node 1 are complete . Node2 must be remembered until node4 is added , to establish the left link from node4 ,but then
        //a pointer to node 2 is no longer needed. Similarly, node 4 must be remembered until node8 has been processed. 

        //It should now be clear that to establish future links, we need only remember pointers to one node on each level, the last node processed on that level. 
        //For example, a tree with 20 levels(hence 20 entries)can accommodate 2^20 -1 > 1,000,000

        //                          ┍--
        //                          ④
        //　　　　　　　　　　　　 /
        //                        ②  
        //                       /  \　　　　　┍--
        //                      ①  ③　　　　 ⑤　　　　　　　　　　　 
        //　　　3层，所以 list_node[1] -> ⑤  , list_node[3] ->④   list_node[0] = NULL
        //
        //build_tree(const List<Record> &supply)
        //Post : if the entries of supply are in increasing order , 
        //       a code of success is returned and the Search_tree is built out of these entries as a balanced tree. 
        //       Otherwise, a code of fail is returned and a balanced is constructed from the longest increasing sequence of entries at the start of supply

        //pass List supply
            mov    eax , 0x50000000 //temp输入的数据
            mov    ebx , 0x15       //个数  
            call   BuildTree
            jmp    QUIT_AVL

            //Last_node.size= 0x5000018C                =  0
            //Last_node start Address after 100 numbers // 0x50000000 + 0x190(400 = 4 * 100)  = 0x50000190
            //Last_node[0] must be 0(NULL)    size = 1
            //Last_node[1] = 0x001264B8

            //Out put Memory address : = 0x50000000 + 0x320(800= 4 * 100) = 0x50000320
            //
            //struct BinaryTreeNode{
            //    Date date;
            //    struct BinaryTreeNode * left;
            //    struct BinaryTreeNode * right;
            //};    //12 Bytes
            //
            //temp node save
            //126AF4= 126644 + 4B0(12 Byte * 100)

            //int count = 0 // number of entries insert so far
            //Record  x , last_x ;
            //List  // pointers to last nodes on each level
            //while (supply.retrieve(count ,x)== success){
            //     if(count >0 && x <= last_x){   //以增序方式 the entries of supply are in increasing order ,
            //        ordered_data  = fail;
            //        break;
            //      }
            //      build_insert(++count , x , last_node); //last_node 保存one node on each level  , count 由0 -> max 自然数顺序
            //      last_x = x ;
            //}
            //root = find_root(last_node);
            //connect_trees(last_node);
BuildTree:  push eax 
            push ebx
            mov  ecx , 0x50000190
            mov  [ecx] , 0x0        //Last_node[0]为NULL， Last_node 仅是指针数组
            mov  [ecx - 0x4], 0x1   //Last_node.size 为0
            mov  ecx , ebx          //输入的函数个数
            mov  ebx , 0x0          //count
            mov  edi , 0x0           //last_x
ReadInput:  mov  edx , [eax+ebx*4]   //从输入的数据中读取一个数据
            cmp  edx , 0
            jz   EndReadInput        //读入完毕  ！= success
            cmp  edx , edi           //x <= last_x
            jle  ERROR_RETURN        //return error

            inc   ebx        //count ++

            push eax 
            push ebx
            push ecx
            mov  eax, ebx     //count
            mov  ebx, edx     //x
            mov  ecx, edi     //last_node
            call BuildInsert
            pop  ecx
            pop  ebx
            pop  eax
            mov  edi , edx
            loop  ReadInput
EndReadInput:mov  eax , 0x50000190   //last_node 指向每一层的指针
             call FindRoot        //返回值
             mov  eax , 0x50000190    //last_node 指向每一层的指针
             call ConnectTree
ERROR_RETURN:pop ebx
             pop eax
             ret

             //build_insert(int count, const Record &new_data , List<Binary_node<Record> *> &last_node)
             //Post : A new node ,containing the Record new_data,has been inserted as the rightmost node of a partially completed binary search tree. 
             //       The level of this new node is one more than the highest power of 2 that divides count.
             //int  level;
             //for(level = 1 ; count % 2 == 0 ; level ++ )    //level 求出层次从而找出 list_node 中的 index 
             //{
             //    count /= 2;
             //}
             //
             //Binary_node<Record> * next_node = new Binary_node<Record>(new_data), *parent ;// one level higher in last_node
             //
             //last_node.retrieve(level - 1, next_node->left);
             //
             //if (last_node.size() <= level){
             //    last_node.insert(level, next_node);
             //} 
             //else{
             //    last_node.replace(level, next_node);
             //}
             //
             //if ( last_node.retrieve(level + 1 ,parent) == success && parent -> right = NULL)){
             //    parent->right = next_node;
             //}

BuildInsert:push eax     //count    //form1 to n
            push ebx     //new_data 
            push ecx     //Last_node  ; We keep these pointers in a List called last_node
            push edx     //level
            push esi
            push edi

            xor  esi , esi
            mov  esi , eax        //The count Node
            dec  esi
            sal  esi , 0x2        //mult 4
            imul esi ,esi ,0x3    //定位BinaryNodeTree[] 的下标
            mov  edx, 1            //level initid
            //for 循(trfh)
FindLevel:  test eax, 0x1//模2不用算只要看二进制最后一位就行了.
            jnz  CT_NEXT1//%2 不成立，退出
            sar  eax ,1
            inc  edx          //level
            jmp FindLevel

CT_NEXT1:   //常数均为内存变量的地址。在编译的时候都已经知道
        //Begin new a Binary Node
        add  esi, 0x50000320 //new Node address
            mov  [esi],ebx   //new_data
            mov  [esi+0x4],0 //left = NULL
            mov  [esi+0x8],0 //right= NULL 
            //End   new a Binary Node

            //Last_node.size : 0x5000018C
            //Last_node area : 0x50000190   = Last_node[0] = NULL
            mov  edi , [0x5000018C + edx * 4]//leveln -1 : 指针的内容
        //mov  eax ,[edi]       //leveln -1 指向的 Binary_Node 内存地址
        mov  [esi+0x4] , edi  //last_node .retrieve(level -1, next_node_left)  next_node->left = Last_node[leveln-1] 指针的内容

            mov  eax ,0x5000018C
            cmp  [eax],edx     //Last_node.size() <= leve ?
            jg   NEXT          //Insert a new pointer
            mov  [0x50000190 + edx * 4] , esi //leveln point to next_node
            inc  [eax]         //Last_node.size ++
        jmp  FINAL1
NEXT:       mov  [0x50000190 + edx * 4] , esi //leveln point to next_node    
FINAL1:     mov  eax ,[0x50000190 + edx * 4 +4] //parent = level+1
        cmp  eax , 0        
            jz   RETRUN_BI               //last_node.retrieve(level + 1, parent) == success
            cmp  [eax+0x8] , 0           //parent->right == NULL
            jnz  RETRUN_BI
            mov [eax+0x8], esi
RETRUN_BI:  pop  edi    
            pop  esi
            pop  edx
            pop  ecx
            pop  ebx
            pop  eax
            ret 


            //Finishing the Task
            //Finding the root of the tree is easy: The root is the highest node in the tree, hence its pointer is the last entry the List last_node.
            //The pointers to the last node encountered on each level are stored in the list last_node

            //find_root(List<Binary_node<Record> *> &last_node)
            //pre: The list last_node contains pointers to the last node on each occupied(已占用的;在使用的;) level of the binary search tree
            //post: A pointer to the root of the newly created binary search trees is returned
            //
            //   list_node.retrieve(last_node.size()-1 , high_node);
            //
            //return high_node;
            //input eax = Last_node[0] address
            //return eax //Last_node[high] address
FindRoot:   push ebx
            mov ebx, [eax-0x4]   //Last_node.size
            mov eax, [eax + ebx * 0x4]
            pop  ebx
            ret

            //Connect_tree
            //Pre: The nearly-completed binary search tree has been initialized.The List Last_node has benn initialized and contains links to
            //the last node on each level of the tree
            //Post:The final links have been added to complete the binary search tree
            //input = eax = &last_node 
ConnectTree:push  ebx //high_node
            push  ecx //low_node
            push  edx //high_level
            push  edi //low_level
            push  esi 
            mov   edx ,[eax-0x4] 
            dec   edx     

            //while(high_level > 2)
CT_WHILE:   cmp   edx , 0x2
            jle   RETURN_CT
            mov   ebx , [eax+edx*0x4]   //last_node.retrieve(high_level, high_node)
            cmp   dword ptr [ebx+0x8] ,0
            jz    NEXT_CTELSE
            dec   ebx           //high_node --
            jmp   NEXT_CTEND_ELSE
NEXT_CTELSE:mov   edi , edx   // low_level = high_level
CT_DO:      dec   edi         //--low_level
            mov   ecx,[eax+edi*0x4]  //last_node(--low_level, low_node);
            cmp   ecx , 0
            jz    CT_END_DO_WHILE
            mov   esi , [ecx]      //low_data
            cmp   esi , [ebx]      //low_data < high_node->data
            jge   CT_END_DO_WHILE
            loop  CT_DO
CT_END_DO_WHILE:
            mov   [ebx+0x8], ecx   //high_node->right = low_node
            mov   edx , edi
            jmp   CT_WHILE
NEXT_CTEND_ELSE:
RETURN_CT:  pop  esi
            pop  edi
            pop  edx
            pop  ecx
            pop  ebx
            ret

QUIT_AVL : 
         mov  eax ,0x500003D4    //root
         push ebx   //used to to_delete
         push ecx   //used to parent
         push edx
         cmp  eax , 0
         jz   REMOVE_ROOT_RETRUN
         mov  ebx , eax    // to_delete = sub_root;
         cmp  [eax+0x8] , 0   //right == NULL
         jne  LEFT_SR
         mov  eax, [eax+0x4]  //sub_root = sub_root->left;
LEFT_SR: cmp  [eax+0x4] , 0   //left == NULL
         jne  NOEMPTY
         mov  eax, [eax+0x8]  //sub_root = sub_root->right
NOEMPTY: mov  ebx, [eax+0x4]; //Move left to find predecessor
         mov  ecx , eax       //parent = sub_root;
FIND_RIGHT_MAX:               //while(to_delete->rgiht != NULL)
         cmp  [ebx+0x8] , 0                                             //while 条件判断语句
         jz   WHILE_END_SR                                              //不成立退出
         mov  ecx , ebx       //parent = to_delete;                     //循环体
         mov  ebx , [ebx+0x8] //to_delete = to_delete->right
         jmp  FIND_RIGHT_MAX                                            //jmp 判断
WHILE_END_SR:                 //end loop
         mov  edx, [ebx]      //edx = to_delete->data;
         mov  [eax],edx       //sub_root->data = to_delete->data;
         cmp  ecx , eax       //parent == sub_root
         jne  ELSE
         mov  edx, [ebx+0x4] //edx = to_delete->left
         mov  [eax+0x4],edx  //sub_root->left = to_delete_left
             jmp  DO_DELETE 
ELSE:    mov  edx ,[ebx+0x4] //edx = to_delete->left
         mov  [ecx+0x8],edx  //parent->right = to_delete->left
DO_DELETE:mov  dword ptr [ebx],0
          mov  dword ptr [ebx+0x4],0
          mov  dword ptr [ebx+0x8],0
REMOVE_ROOT_RETRUN:
         pop  edx
         pop  ecx
         pop  eax


QUIT :  sahf

        mov    eax , 0x62e147a
        mov    ecx , 0x7fff8000
        mov    edx , 0x62e147ad
        mov    ebx , 0x6e147
        mov    esi , 0xade14754
        mov    edi , 0x7fffffff
        mov    esp , 0x34dd2134
        mov    ebp , 0xfffffffe

        test   al , 0x80
        test   ax , 0x8000
        test   eax, 0x80000000

        test   dh ,bl

        test   dx ,si
        test   bx , ax
        test   ebx, eax

        test   ch , 0x80
        test   bx , 0x8000
        test   edx, 0x80000000

        mov    eax , 0x80007fff
        mov    ecx , 0x7fff8000
        mov    edx , 0x62e147ad
        mov    ebx , 0x6e147
        mov    esi , 0xade14754
        mov    edi , 0x7fffffff
        mov    esp , 0x34dd2134
        mov    ebp , 0xfffffffe

        xchg   ax , bx
        xchg   eax , ebx




        mov   ecx , 0x10
        mov   esi , 0x50000040
        cld
        rep   lodsb

        

        shr    al, 1         
        shr    ah, 1         
        shr    bl, 1         
        shr    bh, 1         
        shr    cl, 1         
        shr    ch, 1         
        shr    dl, 1         
        shr    dh, 1         
        shr    ax, 1         
        shr    bx, 1         
        shr    cx, 1         
        shr    dx, 1         
        shr    sp, 1         
        shr    bp, 1         
        shr    si, 1         
        shr    di, 1         
        shr    eax, 1        
        shr    ebx, 1        
        shr    ecx, 1        
        shr    edx, 1        
        shr    esp, 1        
        shr    ebp, 1        
        shr    esi, 1        
        shr    edi, 1        

        mov    cl , 2

        shr    al, cl         
        shr    dh, cl        
        shr    di, cl          
        shr    edi, cl           

        shr    al, 0x32          
        shr    dl, 0x32          
        shr    dh, 0x32          
        shr    ax, 0x32          
        shr    si, 0x32          
        shr    di, 0x32          
        shr    eax, 0x32         
        shr    ebx, 0x32         
        shr    ecx, 0x32         
        shr    esi, 0x32         
        shr    edi, 0x32         

        mov   ebx , 0x50000000
        shr    byte ptr[ebx]    , 1         
        shr    word ptr[ebx], 1          
        shr    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        shr    byte ptr[ebx]    , cl        
        shr    word ptr[ebx], cl  
        shr    dword ptr[ebx]     , cl     
        

        //DAS TEST
        mov  ax , 0x11
        mov  bx , 0x6
        sub  ax , bx    //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0  
        das         //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0 

        //DAA TEST
        mov  ax , 0x5
        mov  bx , 0x6
        add  ax , bx    //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0 
        daa         //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0    

        //AAM test
        mov   eax , 0x21
        mov   ebx , 0x5
        sub   eax , ebx
        aas
        sahf      //测试完成时暂停断点使用
        //AAD TEST
        mov   ax , 0x604   //AH = 6 , AL = 4 表示的是 ：64
        aad 
        //AAA TEST
        mov   ax , 0x6   //6 + 9 = 15
        mov   bx , 0x9   //00000110+00001001=00001111
        add   al , bl    
        aaa          //结果AH= 1  AL= 5 

        //
        
        _emit 0x66 //call 0002   Opersize =16  sp-2 
        _emit 0xe8
        _emit 0x02
        _emit 0x00
        _emit 0x9a   ////9A 11 12 13 14 15 16    call  1615:14131211 
        _emit 0x11
        _emit 0x12
        _emit 0x13
        _emit 0x14
        _emit 0x15
        _emit 0x16
         enter  1104h,22h
        //Add test 
        mov al, 0x70     //0111 , 0000 b   = 112           // 两个正整数相加溢出的 测试用例
        mov bl, 0x61     //0110 , 0001 b   = 97      , 97 + 112= 209   // D1 : 1101 , 0001 超出的 -128 -- + 127 的表示范围
        add al, bl

        mov bl,0xc9     //1100 ,  1001 b  = -55           // 两个负整数相加溢出的 测试用例
        mov al,0xb0     //1011 ,  0000 b  = -80     , -55 + -80 = -135  //结果:0x179 :  0001 , 0111 , 1001  , al = 0111 , 10001 
        add al, bl

        //Mov 
        //88-89
        mov    ebx, 0x50000001      // BB 01 00 00 50   
        mov    ah, [ebx]        // 8A 23        
        mov    al, [ebx]        // 8A 03        
        mov    ax, [ebx]        // 66 8B 03         //In the Console print the instruction: mov eax,[ebx[ebx]       
        mov    eax, [ebx]           // 8B 03        
        mov    al , 0x98        // B0        
        mov    ah , 0x76        // B4           
        mov    ax , 0x5441          // 66 B8     
        mov    eax , 0x32757698     // B8  

        mov    [ebx] ,al        // 88 03       
        mov    [ebx] ,ah        // 88 23       
        mov    [ebx] ,ax        // 66 89 03    
        mov    [ebx] , eax          // 89 03       


        mov    charTest, ah //88 25 AE 13 41 00
        mov    charTest, al //88 05 AE 13 41 00
        mov    charTest, bh //88 3D AE 13 41 00
        mov    charTest, bl //88 1D AE 13 41 00
        mov    charTest, dh //88 35 AE 13 41 00
        mov    charTest, dl //88 15 AE 13 41 00
        mov    charTest, ch //88 2D AE 13 41 00
        mov    charTest, cl //88 0D AE 13 41 00
        mov    byte ptr [eax+8],ah //88 60 08
        mov    byte ptr [eax],ah   //88 20
        mov    byte ptr [eax+4A2CB72h],ah //88 A0 72 CB A2 04
        mov    word ptr [ebx],ax          //66 89 03   寄16=>[寄32]
        mov    dword ptr [ebx],eax        //89 03    寄32=>[寄32]
        mov    shortIntTest,ax   //66 89 05 AE 13 41 00 
        mov    dword ptr [ebx],eax        //89 03 
        mov    word ptr [eax+8],ax        //66 89 40 08 寄16=>[寄32+位移8]
        mov    dword ptr [eax+8],eax      //89 40 08 寄32=>[寄32+位移8]
        mov    word ptr [eax-1],ax        //66 89 40 FF  mov  [eax+0xffffffff],ax 寄16=>[寄32+位移32]
        mov    dword ptr [eax-1],eax      //89 40 FF mov  [eax+0xffffffff],eax 寄32=>[寄32+位移32]

        //8a     
        mov    ah,byte ptr [eax] //8A 20   mov  ah, [eax]      
        mov    ah,byte ptr [eax+8] //8A 60 08 mov  ah, [eax+0x8]        
        mov    ah,byte ptr [eax-77777778h] //8A A0 88 88 88 88  mov  ah, [eax+0x88888888]

        //8b  
        mov    bx,dx  //66 8B DA
        mov    ax,bx //66 8B C3 
        mov    eax,ebx //8B C3     
        mov    ax,word ptr [eax] //66 8B 00   mov  ax,[eax]       
        mov    eax,dword ptr [ebx] //8B 03 mov  eax,[ebx]
        mov    ax,word ptr [ebx+8] //66 8B 43 08 mov  ax,[ebx+0x8]
        mov    eax,dword ptr [ebx+8] //8B 43 08   mov  eax,[ebx+0x8]
        mov    ax,word ptr [ebx-77777778h] //66 8B 83 88 88 88 88  mov  ax,[ebx+0x88888888]
        mov    eax,dword ptr [ebx-77777778h] //8B 83 88 88 88 88  mov  eax,[ebx+0x88888888]

        //8c 
        mov    ax,cs //66 8C C8    mov ax, cs  //寄:段=>寄16
        mov    word ptr [eax],cs //66 8C 08  mov [eax],cs
        mov    word ptr [ebx+8],cs //66 8C 4B 08 mov [ebx+0x8],cs
        mov    word ptr [ebx+77777777h],cs //66 8C 8B 77 77 77 77 mov [ebx+0x77777777],cs

        //8e   
        mov    es,cx //8E C1    mov es, cx
        mov    ds,bx //66 8E DB    mov ds, bx
        mov    es,word ptr [ebx] //66 8E 03   mov es,[ebx]
        mov    es,word ptr [ebx+8] //66 8E 43 08      mov es,[ebx+8]
        mov    fs,word ptr [ecx+77777777h] //66 8E A1 77 77 77 77  FS寄存器指向当前活动线程的TEB结构（线程结构）

        //A0--A3
        mov    al,byte ptr ds:[00000007h] //A0 07 00 00 00         mov al, ds:[0x7]
        mov    ax,word ptr cs:[00000007h] //2E A1 07 00 00 00   mov ax, cs:[0x7]  
        mov    eax,dword ptr es:[77777777h] //A1 77 77 77 77 mov eax,es:[0x77777777]
        mov    byte ptr ds:[00000007h],al // 3E A2 07 00 00 00  mov ds:[0x07],al
        mov    word ptr ds:[00000111h],ax //66 3E A3 11 01 00 00  mov ds:[0x111],ax
        mov    dword ptr es:[12345678h],eax //26 A3 78 56 34 12 

        //B0--BF
        mov    al,11h //B0 11           
        mov    cl,11h //B1 11           
        mov    dl,11h //B2 11  
        mov    bl,11h //B3 11
        mov    ah,11h //B4 11        
        mov    ch,11h //B5 11        
        mov    dh,11h // B6 11
        mov    bh,11h // B7 11  
        mov    ax,1111h //66 B8 11 11      
        mov    eax,1111111h // B8 11 11 11 01   
        mov    cx,1111h // 66 B9 11 11      
        mov    ecx,1111111h // B9 11 11 11 01   
        mov    dx,1111h // 66 BA 11 11      
        mov    edx,1111111h // BA 11 11 11 01   
        mov    bx,1111h //66 BB 11 11      
        mov    bx,1111h // 66 BB 11 11      
        mov    sp,1111h // 66 BC 11 11      
        mov    esp,1111111h // BC 11 11 11 01   
        mov    bp,1111h // 66 BD 11 11     
        mov    ebp,1111111h // BD 11 11 11 01   
        mov    si,1111h //66 BE 11 11     
        mov    esi,1111111h // BE 11 11 11 01   
        mov    di,1111h // 66 BF 11 11      
        mov    edi,1111111h // BF 11 11 11 01   

        //C6
        mov    byte ptr [ebx],11h // C6 03 11        
        mov    byte ptr [eax+8],11h //C6 40 08 11     
        mov    byte ptr [ecx+77777777h],11h // C6 81 77 77 77 77 11  mov  [ecx+0x77777777],0x11

        //C7
        mov    word ptr [ebx],4444h // 66 C7 03 44 44   
        mov    word ptr [eax+8],4444h // 66 C7 40 08 44 44 
        mov    dword ptr [eax+8],4444h // C7 40 08 44 44 00 00 
        mov    word ptr [ecx+77777777h],4444h //  66 C7 81 77 77 77 77 44 44 
        mov    dword ptr [ecx+7777777h],44444444h // C7 81 77 77 77 07 44 44 44 44 


       
        //OR
        or    byte ptr [charTest],al           //08 45 FB         
        or    word ptr [shortIntTest],ax       //66 09 45 EC      
        or    dword ptr [intTest],eax          //09 45 E0         
        or    bl,byte ptr [charTest]           //0A 5D FB         
        or    bl,byte ptr [ebx]        //0A 1B        
        or    bl,byte ptr [ebx+22h]        //0A 5B 22         
        or    bl,byte ptr [ebx+22222222h]      //0A 9B 22 22 22 22
        or    cx,word ptr [shortIntTest]       //66 0B 4D EC      
        or    cx,word ptr [ebx]        //66 0B 0B         
        or    cx,word ptr [ebx+22h]        //66 0B 4B 22      
        or    cx,word ptr [ebx+22222222h]      //66 0B 8B 22 22 22 22 
        or    ecx,dword ptr [intTest]          //0B 4D E0         
        or    ecx,dword ptr [ebx]          //0B 0B        
        or    ecx,dword ptr [ebx+22h]          //0B 4B 22         
        or    ecx,dword ptr [ebx+22222222h]    //0B 8B 22 22 22 22
        or    al,22h           //0C 22        
        or    eax,22222222h        //0D 22 22 22 22   
        or    bl,22h           //80 CB 22         
        or    byte ptr [charTest],22h          //80 4D FB 22      
        or    dx,2222h         //66 81 CA 22 22   
        or    word ptr [shortIntTest],2222h    //66 81 4D EC 22 22
        or    edx,2222h        //81 CA 22 22 00 00
        or    dword ptr [intTest],22222222h    //81 4D E0 22 22 22 22
        or    cx,22h           //66 83 C9 22      
        or    ecx,22h          //83 C9 22         

        //SBB
        sbb    byte ptr [charTest],al          //18 45 FB         
        sbb    word ptr [shortIntTest],ax      //66 19 45 EC      
        sbb    dword ptr [intTest],eax         //19 45 E0         
        sbb    bl,byte ptr [charTest]          //1A 5D FB         
        sbb    bl,byte ptr [ebx]           //1A 1B        
        sbb    bl,byte ptr [ebx+22h]           //1A 5B 22         
        sbb    bl,byte ptr [ebx+22222222h]     //1A 9B 22 22 22 22
        sbb    cx,word ptr [shortIntTest]      //66 1B 4D EC      
        sbb    cx,word ptr [ebx]           //66 1B 0B         
        sbb    cx,word ptr [ebx+22h]           //66 1B 4B 22      
        sbb    cx,word ptr [ebx+22222222h]     //66 1B 8B 22 22 22 22 
        sbb    ecx,dword ptr [intTest]         //1B 4D E0         
        sbb    ecx,dword ptr [ebx]         //1B 0B        
        sbb    ecx,dword ptr [ebx+22h]         //1B 4B 22         
        sbb    ecx,dword ptr [ebx+22222222h]   //1B 8B 22 22 22 22
        sbb    al,22h          //1C 22        
        sbb    eax,22222222h           //1D 22 22 22 22   
        sbb    bl,22h          //80 DB 22         
        sbb    byte ptr [charTest],22h         //80 5D FB 22      
        sbb    dx,2222h        //66 81 DA 22 22   
        sbb    word ptr [shortIntTest],2222h   //66 81 5D EC 22 22
        sbb    edx,2222h           //81 DA 22 22 00 00
        sbb    dword ptr [intTest],22222222h   //81 5D E0 22 22 22 22 
        sbb    cx,22h          //66 83 D9 22      
        sbb    ecx,22h         //83 D9 22      

        //SUB
        sub    byte ptr [charTest],al          //28 45 FB         
        sub    word ptr [shortIntTest],ax      //66 29 45 EC      
        sub    dword ptr [intTest],eax         //29 45 E0         
        sub    bl,byte ptr [charTest]          //2A 5D FB         
        sub    bl,byte ptr [ebx]           //2A 1B        
        sub    bl,byte ptr [ebx+22h]           //2A 5B 22         
        sub    bl,byte ptr [ebx+22222222h]     //2A 9B 22 22 22 22
        sub    cx,word ptr [shortIntTest]      //66 2B 4D EC      
        sub    cx,word ptr [ebx]           //66 2B 0B         
        sub    cx,word ptr [ebx+22h]           //66 2B 4B 22      
        sub    cx,word ptr [ebx+22222222h]     //66 2B 8B 22 22 22 22 
        sub    ecx,dword ptr [intTest]         //2B 4D E0         
        sub    ecx,dword ptr [ebx]         //2B 0B        
        sub    ecx,dword ptr [ebx+22h]         //2B 4B 22         
        sub    ecx,dword ptr [ebx+22222222h]   //2B 8B 22 22 22 22
        sub    al,22h          //2C 22        
        sub    eax,22222222h           //2D 22 22 22 22   
        sub    bl,22h          //80 EB 22         
        sub    byte ptr [charTest],22h         //80 6D FB 22      
        sub    dx,2222h        //66 81 EA 22 22   
        sub    word ptr [shortIntTest],2222h   //66 81 6D EC 22 22
        sub    edx,2222h           //81 EA 22 22 00 00
        sub    dword ptr [intTest],22222222h   //81 6D E0 22 22 22 22 
        sub    cx,22h          //66 83 E9 22      
        sub    ecx,22h         //83 E9 22  

         

        //IDIV
        idiv    al         //F6 F8        
        idiv    ah         //F6 FC        
        idiv    bh         //F6 FF        
        idiv    bl         //F6 FB        
        idiv    dh         //F6 FE        
        idiv    dl         //F6 FA        
        idiv    ch         //F6 FD        
        idiv    cl         //F6 F9        
        idiv    ax         //66 F7 F8         
        idiv    ax         //66 F7 FB         
        idiv    ax         //66 F7 FA         
        idiv    ax         //66 F7 F9         
        idiv    eax        //F7 F8        
        idiv    eax        //F7 FB        
        idiv    eax        //F7 FA        
        idiv    eax        //F7 F9        
        idiv    byte ptr [charTest]        //F6 7D FB         
        idiv    word ptr [shortIntTest] //66 F7 7D EC      
        idiv    dword ptr [intTest]    //F7 7D E0    

        //MUL 
        mul    al           //F6 E0        
        mul    al           //F6 E4        
        mul    al           //F6 E7        
        mul    al           //F6 E3        
        mul    al           //F6 E6        
        mul    al           //F6 E2        
        mul    al           //F6 E5        
        mul    al           //F6 E1        
        mul    ax           //66 F7 E0         
        mul    ax           //66 F7 E3         
        mul    ax           //66 F7 E2         
        mul    ax           //66 F7 E1         
        mul    eax         //F7 E0        
        mul    eax         //F7 E3        
        mul    eax         //F7 E2        
        mul    eax         //F7 E1        
        mul    byte ptr [charTest]      //F6 65 FB         
        mul    word ptr [shortIntTest]  //66 F7 65 EC      
        mul    dword ptr [intTest]     //F7 65 E0  


        //AAA
        aaa  //37
        //AAS
        aas  //3F

        //AAD
        aad

        //AAM
        aam

        //BOUND
        bound    ax,dword ptr [shortIntTest]   //66 62 45 EC      
        bound    ax,dword ptr [ebx]        //66 62 03         
        bound    ax,dword ptr [ebx+8]          //66 62 43 08      
        bound    ax,dword ptr [ebx+77777777h]  //66 62 83 77 77 77 77 
        bound    eax,qword ptr [edx]           //62 02        
        bound    eax,qword ptr [ebx+8]         //62 43 08         
        bound    eax,qword ptr [ebx+77777777h] //62 83 77 77 77 77
        bound   ax, [edx]         //66 62 02   
        bound   bx, [edx]         //66 62 1A   
        bound   ebp, qword ptr [ecx+0x6]  //62 69 06   
        bound   edx, longLongIntTest      //62 55 D0   
        bound   bx, shortIntTest         //66 62 5D EC
        bound   ax, intTest          //66 62 45 E0
        bound   ax, charTest         //66 62 45 FB

        //CALL
        call    dword ptr [ebp-0Bh]         //FF 55 F5         
        call    dword ptr cs:[15h]          //2E FF 15 15 00 00 00 
        call    codestart           //   
        call    dword ptr [shortIntTest]    //FF 55 EC         
        call    ebx         //FF D3        
        call    eax         //FF D0        
        call    dword ptr [intTest]         //FF 55 E0         
        call    dword ptr [longLongIntTest] //FF 55 D0         
        call    dword ptr [eax]         //FF 10        
        call    dword ptr [eax+8]           //FF 50 08         
        call    dword ptr [eax+11111111h]   //FF 90 11 11 11 11

        //
        cmps  charTest,charTest          //A6     
        cmps  shortIntTest, shortIntTest  //66 A7  
        cmps  intTest, intTest        //A7     
        cmpsb             //A6     
        cmpsw             //66 A7  
        cmpsd             //A7    


        //EA 没有形成
        jmp    near ptr codestart        //  EB FE        
        jmp    [eax]         //  FF 20        
        jmp    ax            //  FF E0        
        jmp    eax           //  FF E0        
        jmp    0x44444444[eax]           //  FF A0 44 44 44 44    
        jmp    0x44444444[eax+0x44]          //  FF A0 88 44 44 44    
        jmp    0x4444[eax +0x44444444]       //  FF A0 88 88 44 44    
        jmp    0x44444444[eax+0x222222222]   //  FF A0 66 66 66 66    
        jmp    es:0x11111111         //  26 FF 25 11 11 11 11
        jmp    shortIntTest          //  FF 65 EC         
        jmp    longLongIntTest           //  FF 65 D0         
        jmp    0x4444[eax]           //  FF A0 44 44 00 00    
        jmp    0x4444[eax+0x2222]        //  FF A0 66 66 00 00    
        jmp    0x44444444[eax+0x222222222]   //  FF A0 66 66 66 66    
        jmp    shortIntTest[0x4444]          //  FF A5 30 44 00 00    
        jmp    ds:0x444          //  3E FF 25 44 04 00 00


        //lahf : 9f  Load:Ah <- EFLAGS(SF:ZF:0:AF:0:PF:1:CF)
        lahf

        //xor 
        xor    al, 0x22        //34 22           
        xor    ax, 0x2222          //66 35 22 22         
        xor    eax,0x222222222         //35 22 22 22 22    

        xor    bl, 0x22        //80 F3 22        
        xor    charTest, 0x22          //80 75 FB 22    

        xor    shortIntTest, 0x2222    //66 81 75 EC 22 22   
        xor    bx, 0x2222          //66 81 F3 22 22    
        xor    intTest, 0x22222222     //81 75 E0 22 22 22 22
        xor    ebx, 0x22222222         //81 F3 22 22 22 22 

        xor    bx,0x22        //66 83 F3 22         
        xor    ebx,0x22        //83 F3 22

        xor    charTest,bl        //30 5D FB        
        xor    shortIntTest, dx        //66 31 55 EC         
        xor    intTest, ebx        //31 5D E0 

        xor    dl, charTest           //32 55 FB        
        xor    dx, shortIntTest       //66 33 55 EC         
        xor    ebx, intTest        //33 5D E0    
        xor    bl, al         //32 D8           
        xor    bx, ax         //66 33 D8        
        xor    ebx,edx        //33 DA 

        //inc
        inc    ax           //  66 40         
        inc    eax          //  40          
        inc    cx           //  66 41       
        inc    ecx          //  41          
        inc    dx           //  66 42       
        inc    edx          //  42          
        inc    bx           //  66 43       
        inc    ebx          //  43          
        inc    sp           //  66 44       
        inc    esp          //  44          
        inc    bp           //  66 45       
        inc    ebp          //  45          
        inc    si           //  66 46       
        inc    esi          //  46          
        inc    di           //  66 47       
        inc    edi          //  47          
        inc    al           //  FE C0       
        inc    cl           //  FE C1       
        inc    dl           //  FE C2       
        inc    bl           //  FE C3       
        inc    ah           //  FE C4       
        inc    bh           //  FE C7       
        inc    dh           //  FE C6       
        inc    ch           //  FE C5       
        inc    charTest     //  FE 45 FB    
        inc    shortIntTest //  66 FF 45 EC 
        inc    intTest      //  FF 45 E0  

        //     
        lds    ax,charTest   //66 C5 45 FB  
        lds    ax,[eax]      //66 C5 00     
        lds    bx,[eax]      //66 C5 18     
        lds    cx,[eax]      //66 C5 08     
        lds    dx,[eax]      //66 C5 10     
        lds    sp,[eax]      //66 C5 20     
        lds    bp,[eax]      //66 C5 28     
        lds    si,[eax]      //66 C5 30     
        lds    di,[eax]      //66 C5 38  

        lds    ax,[ebx]      //66 C5 03     
        lds    bx,[ebx]      //66 C5 1B     
        lds    cx,[ebx]      //66 C5 0B     
        lds    dx,[ebx]      //66 C5 13     
        lds    sp,[ebx]      //66 C5 23     
        lds    bp,[ebx]      //66 C5 2B     
        lds    si,[ebx]      //66 C5 33     
        lds    di,[ebx]      //66 C5 3B  

        lds    ax,[ecx]      //66 C5 01     
        lds    bx,[ecx]      //66 C5 19     
        lds    cx,[ecx]      //66 C5 09     
        lds    dx,[ecx]      //66 C5 11     
        lds    sp,[ecx]      //66 C5 21     
        lds    bp,[ecx]      //66 C5 29     
        lds    si,[ecx]      //66 C5 31     
        lds    di,[ecx]      //66 C5 39   

        lds    ax,[edx]      //66 C5 02     
        lds    bx,[edx]      //66 C5 1A     
        lds    cx,[edx]      //66 C5 0A     
        lds    dx,[edx]      //66 C5 12     
        lds    sp,[edx]      //66 C5 22     
        lds    bp,[edx]      //66 C5 2A     
        lds    si,[edx]      //66 C5 32     
        lds    di,[edx]      //66 C5 3A    

        lds    ax,[esp]      //66 C5 04 24  
        lds    bx,[esp]      //66 C5 1C 24  
        lds    cx,[esp]      //66 C5 0C 24  
        lds    dx,[esp]      //66 C5 14 24  
        lds    sp,[esp]      //66 C5 24 24  
        lds    bp,[esp]      //66 C5 2C 24  
        lds    si,[esp]      //66 C5 34 24  
        lds    di,[esp]      //66 C5 3C 24  

        lds    ax,[ebp]      //66 C5 45 00  
        lds    bx,[ebp]      //66 C5 5D 00  
        lds    cx,[ebp]      //66 C5 4D 00  
        lds    dx,[ebp]      //66 C5 55 00  
        lds    sp,[ebp]      //66 C5 65 00  
        lds    bp,[ebp]      //66 C5 6D 00  
        lds    si,[ebp]      //66 C5 75 00  
        lds    di,[ebp]      //66 C5 7D 00  

        lds    ax,[esi]      //66 C5 06     
        lds    bx,[esi]      //66 C5 1E     
        lds    cx,[esi]      //66 C5 0E     
        lds    dx,[esi]      //66 C5 16     
        lds    sp,[esi]      //66 C5 26     
        lds    bp,[esi]      //66 C5 2E     
        lds    si,[esi]      //66 C5 36     
        lds    di,[esi]      //66 C5 3E     

        lds    ax,[edi]      //66 C5 07     
        lds    bx,[edi]      //66 C5 1F     
        lds    cx,[edi]      //66 C5 0F     
        lds    dx,[edi]      //66 C5 17     
        lds    sp,[edi]      //66 C5 27     
        lds    bp,[edi]      //66 C5 2F     
        lds    si,[edi]      //66 C5 37     
        lds    di,[edi]      //66 C5 3F    

        lds    eax,charTest  //C5 45 FB     
        lds    eax,[eax]     //C5 00        
        lds    ebx,[eax]     //C5 18        
        lds    ecx,[eax]     //C5 08        
        lds    edx,[eax]     //C5 10        
        lds    esp,[eax]     //C5 20        
        lds    ebp,[eax]     //C5 28        
        lds    esi,[eax]     //C5 30        
        lds    edi,[eax]     //C5 38  

        lds    eax,[ebx]     //C5 03        
        lds    ebx,[ebx]     //C5 1B        
        lds    ecx,[ebx]     //C5 0B        
        lds    edx,[ebx]     //C5 13        
        lds    esp,[ebx]     //C5 23        
        lds    ebp,[ebx]     //C5 2B        
        lds    esi,[ebx]     //C5 33        
        lds    edi,[ebx]     //C5 3B  

        lds    eax,[ecx]     //C5 01        
        lds    ebx,[ecx]     //C5 19        
        lds    ecx,[ecx]     //C5 09        
        lds    edx,[ecx]     //C5 11        
        lds    esp,[ecx]     //C5 21        
        lds    ebp,[ecx]     //C5 29        
        lds    esi,[ecx]     //C5 31        
        lds    edi,[ecx]     //C5 39  

        lds    eax,[edx]     //C5 02        
        lds    ebx,[edx]     //C5 1A        
        lds    ecx,[edx]     //C5 0A        
        lds    edx,[edx]     //C5 12        
        lds    esp,[edx]     //C5 22        
        lds    ebp,[edx]     //C5 2A        
        lds    esi,[edx]     //C5 32        
        lds    edi,[edx]     //C5 3A  

        lds    eax,[esp]     //C5 04 24     
        lds    ebx,[esp]     //C5 1C 24     
        lds    ecx,[esp]     //C5 0C 24     
        lds    edx,[esp]     //C5 14 24     
        lds    esp,[esp]     //C5 24 24     
        lds    ebp,[esp]     //C5 2C 24     
        lds    esi,[esp]     //C5 34 24     
        lds    edi,[esp]     //C5 3C 24   

        lds    eax,[ebp]     //C5 45 00     
        lds    ebx,[ebp]     //C5 5D 00     
        lds    ecx,[ebp]     //C5 4D 00     
        lds    edx,[ebp]     //C5 55 00     
        lds    esp,[ebp]     //C5 65 00     
        lds    ebp,[ebp]     //C5 6D 00     
        lds    esi,[ebp]     //C5 75 00     
        lds    edi,[ebp]     //C5 7D 00    

        lds    eax,[esi]     //C5 06        
        lds    ebx,[esi]     //C5 1E        
        lds    ecx,[esi]     //C5 0E        
        lds    edx,[esi]     //C5 16        
        lds    esp,[esi]     //C5 26        
        lds    ebp,[esi]     //C5 2E        
        lds    esi,[esi]     //C5 36        
        lds    edi,[esi]     //C5 3E       

        lds    eax,[edi]     //C5 07        
        lds    ebx,[edi]     //C5 1F        
        lds    ecx,[edi]     //C5 0F        
        lds    edx,[edi]     //C5 17        
        lds    esp,[edi]     //C5 27        
        lds    ebp,[edi]     //C5 2F        
        lds    esi,[edi]     //C5 37        
        lds    edi,[edi]     //C5 3F  

        les    ax,charTest   //66 C4 45 FB  
        les    ax,[eax]      //66 C4 00     
        les    bx,[eax]      //66 C4 18     
        les    cx,[eax]      //66 C4 08     
        les    dx,[eax]      //66 C4 10     
        les    sp,[eax]      //66 C4 20     
        les    bp,[eax]      //66 C4 28     
        les    si,[eax]      //66 C4 30     
        les    di,[eax]      //66 C4 38  

        les    ax,[ebx]      //66 C4 03     
        les    bx,[ebx]      //66 C4 1B     
        les    cx,[ebx]      //66 C4 0B     
        les    dx,[ebx]      //66 C4 13     
        les    sp,[ebx]      //66 C4 23     
        les    bp,[ebx]      //66 C4 2B     
        les    si,[ebx]      //66 C4 33     
        les    di,[ebx]      //66 C4 3B  

        les    ax,[ecx]      //66 C4 01     
        les    bx,[ecx]      //66 C4 19     
        les    cx,[ecx]      //66 C4 09     
        les    dx,[ecx]      //66 C4 11     
        les    sp,[ecx]      //66 C4 21     
        les    bp,[ecx]      //66 C4 29     
        les    si,[ecx]      //66 C4 31     
        les    di,[ecx]      //66 C4 39 

        les    ax,[edx]      //66 C4 02     
        les    bx,[edx]      //66 C4 1A     
        les    cx,[edx]      //66 C4 0A     
        les    dx,[edx]      //66 C4 12     
        les    sp,[edx]      //66 C4 22     
        les    bp,[edx]      //66 C4 2A     
        les    si,[edx]      //66 C4 32     
        les    di,[edx]      //66 C4 3A   

        les    ax,[esp]      //66 C4 04 24  
        les    bx,[esp]      //66 C4 1C 24  
        les    cx,[esp]      //66 C4 0C 24  
        les    dx,[esp]      //66 C4 14 24  
        les    sp,[esp]      //66 C4 24 24  
        les    bp,[esp]      //66 C4 2C 24  
        les    si,[esp]      //66 C4 34 24  
        les    di,[esp]      //66 C4 3C 24  

        les    ax,[ebp]      //66 C4 45 00  
        les    bx,[ebp]      //66 C4 5D 00  
        les    cx,[ebp]      //66 C4 4D 00  
        les    dx,[ebp]      //66 C4 55 00  
        les    sp,[ebp]      //66 C4 65 00  
        les    bp,[ebp]      //66 C4 6D 00  
        les    si,[ebp]      //66 C4 75 00  
        les    di,[ebp]      //66 C4 7D 00  

        les    ax,[esi]      //66 C4 06     
        les    bx,[esi]      //66 C4 1E     
        les    cx,[esi]      //66 C4 0E     
        les    dx,[esi]      //66 C4 16     
        les    sp,[esi]      //66 C4 26     
        les    bp,[esi]      //66 C4 2E     
        les    si,[esi]      //66 C4 36     
        les    di,[esi]      //66 C4 3E   

        les    ax,[edi]      //66 C4 07     
        les    bx,[edi]      //66 C4 1F     
        les    cx,[edi]      //66 C4 0F     
        les    dx,[edi]      //66 C4 17     
        les    sp,[edi]      //66 C4 27     
        les    bp,[edi]      //66 C4 2F     
        les    si,[edi]      //66 C4 37     
        les    di,[edi]      //66 C4 3F    

        les    eax,charTest  //C4 45 FB     
        les    eax,[eax]     //C4 00        
        les    ebx,[eax]     //C4 18        
        les    ecx,[eax]     //C4 08        
        les    edx,[eax]     //C4 10        
        les    esp,[eax]     //C4 20        
        les    ebp,[eax]     //C4 28        
        les    esi,[eax]     //C4 30        
        les    edi,[eax]     //C4 38    

        les    eax,[ebx]     //C4 03        
        les    ebx,[ebx]     //C4 1B        
        les    ecx,[ebx]     //C4 0B        
        les    edx,[ebx]     //C4 13        
        les    esp,[ebx]     //C4 23        
        les    ebp,[ebx]     //C4 2B        
        les    esi,[ebx]     //C4 33        
        les    edi,[ebx]     //C4 3B  

        les    eax,[ecx]     //C4 01        
        les    ebx,[ecx]     //C4 19        
        les    ecx,[ecx]     //C4 09        
        les    edx,[ecx]     //C4 11        
        les    esp,[ecx]     //C4 21        
        les    ebp,[ecx]     //C4 29        
        les    esi,[ecx]     //C4 31        
        les    edi,[ecx]     //C4 39  

        les    eax,[edx]     //C4 02        
        les    ebx,[edx]     //C4 1A        
        les    ecx,[edx]     //C4 0A        
        les    edx,[edx]     //C4 12        
        les    esp,[edx]     //C4 22        
        les    ebp,[edx]     //C4 2A        
        les    esi,[edx]     //C4 32        
        les    edi,[edx]     //C4 3A    

        les    eax,[esp]     //C4 04 24     
        les    ebx,[esp]     //C4 1C 24     
        les    ecx,[esp]     //C4 0C 24     
        les    edx,[esp]     //C4 14 24     
        les    esp,[esp]     //C4 24 24     
        les    ebp,[esp]     //C4 2C 24     
        les    esi,[esp]     //C4 34 24     
        les    edi,[esp]     //C4 3C 24   

        les    eax,[ebp]     //C4 45 00     
        les    ebx,[ebp]     //C4 5D 00     
        les    ecx,[ebp]     //C4 4D 00     
        les    edx,[ebp]     //C4 55 00     
        les    esp,[ebp]     //C4 65 00     
        les    ebp,[ebp]     //C4 6D 00     
        les    esi,[ebp]     //C4 75 00     
        les    edi,[ebp]     //C4 7D 00    

        les    eax,[esi]     //C4 06        
        les    ebx,[esi]     //C4 1E        
        les    ecx,[esi]     //C4 0E        
        les    edx,[esi]     //C4 16        
        les    esp,[esi]     //C4 26        
        les    ebp,[esi]     //C4 2E        
        les    esi,[esi]     //C4 36        
        les    edi,[esi]     //C4 3E    

        les    eax,[edi]     //C4 07        
        les    ebx,[edi]     //C4 1F        
        les    ecx,[edi]     //C4 0F        
        les    edx,[edi]     //C4 17        
        les    esp,[edi]     //C4 27        
        les    ebp,[edi]     //C4 2F        
        les    esi,[edi]     //C4 37        
        les    edi,[edi]     //C4 3F  

        lss    ax,charTest   //66 0F B2 45 FB   
        lss    ax,[eax]      //66 0F B2 00      
        lss    bx,[eax]      //66 0F B2 18      
        lss    cx,[eax]      //66 0F B2 08      
        lss    dx,[eax]      //66 0F B2 10      
        lss    sp,[eax]      //66 0F B2 20      
        lss    bp,[eax]      //66 0F B2 28      
        lss    si,[eax]      //66 0F B2 30      
        lss    di,[eax]      //66 0F B2 38   

        lss    ax,[ebx]      //66 0F B2 03      
        lss    bx,[ebx]      //66 0F B2 1B      
        lss    cx,[ebx]      //66 0F B2 0B      
        lss    dx,[ebx]      //66 0F B2 13      
        lss    sp,[ebx]      //66 0F B2 23      
        lss    bp,[ebx]      //66 0F B2 2B      
        lss    si,[ebx]      //66 0F B2 33      
        lss    di,[ebx]      //66 0F B2 3B   

        lss    ax,[ecx]      //66 0F B2 01      
        lss    bx,[ecx]      //66 0F B2 19      
        lss    cx,[ecx]      //66 0F B2 09      
        lss    dx,[ecx]      //66 0F B2 11      
        lss    sp,[ecx]      //66 0F B2 21      
        lss    bp,[ecx]      //66 0F B2 29      
        lss    si,[ecx]      //66 0F B2 31      
        lss    di,[ecx]      //66 0F B2 39   

        lss    ax,[edx]      //66 0F B2 02      
        lss    bx,[edx]      //66 0F B2 1A      
        lss    cx,[edx]      //66 0F B2 0A      
        lss    dx,[edx]      //66 0F B2 12      
        lss    sp,[edx]      //66 0F B2 22      
        lss    bp,[edx]      //66 0F B2 2A      
        lss    si,[edx]      //66 0F B2 32      
        lss    di,[edx]      //66 0F B2 3A  

        lss    ax,[esp]      //66 0F B2 04 24   
        lss    bx,[esp]      //66 0F B2 1C 24   
        lss    cx,[esp]      //66 0F B2 0C 24   
        lss    dx,[esp]      //66 0F B2 14 24   
        lss    sp,[esp]      //66 0F B2 24 24   
        lss    bp,[esp]      //66 0F B2 2C 24   
        lss    si,[esp]      //66 0F B2 34 24   
        lss    di,[esp]      //66 0F B2 3C 24   

        lss    ax,[ebp]      //66 0F B2 45 00   
        lss    bx,[ebp]      //66 0F B2 5D 00   
        lss    cx,[ebp]      //66 0F B2 4D 00   
        lss    dx,[ebp]      //66 0F B2 55 00   
        lss    sp,[ebp]      //66 0F B2 65 00   
        lss    bp,[ebp]      //66 0F B2 6D 00   
        lss    si,[ebp]      //66 0F B2 75 00   
        lss    di,[ebp]      //66 0F B2 7D 00   

        lss    ax,[esi]      //66 0F B2 06      
        lss    bx,[esi]      //66 0F B2 1E      
        lss    cx,[esi]      //66 0F B2 0E      
        lss    dx,[esi]      //66 0F B2 16      
        lss    sp,[esi]      //66 0F B2 26      
        lss    bp,[esi]      //66 0F B2 2E      
        lss    si,[esi]      //66 0F B2 36      
        lss    di,[esi]      //66 0F B2 3E     

        lss    ax,[edi]      //66 0F B2 07      
        lss    bx,[edi]      //66 0F B2 1F      
        lss    cx,[edi]      //66 0F B2 0F      
        lss    dx,[edi]      //66 0F B2 17      
        lss    sp,[edi]      //66 0F B2 27      
        lss    bp,[edi]      //66 0F B2 2F      
        lss    si,[edi]      //66 0F B2 37      
        lss    di,[edi]      //66 0F B2 3F     

        lss    eax,charTest  //0F B2 45 FB      
        lss    eax,[eax]     //0F B2 00         
        lss    ebx,[eax]     //0F B2 18         
        lss    ecx,[eax]     //0F B2 08         
        lss    edx,[eax]     //0F B2 10         
        lss    esp,[eax]     //0F B2 20         
        lss    ebp,[eax]     //0F B2 28         
        lss    esi,[eax]     //0F B2 30         
        lss    edi,[eax]     //0F B2 38       

        lss    eax,[ebx]     //0F B2 03         
        lss    ebx,[ebx]     //0F B2 1B         
        lss    ecx,[ebx]     //0F B2 0B         
        lss    edx,[ebx]     //0F B2 13         
        lss    esp,[ebx]     //0F B2 23         
        lss    ebp,[ebx]     //0F B2 2B         
        lss    esi,[ebx]     //0F B2 33         
        lss    edi,[ebx]     //0F B2 3B      

        lss    eax,[ecx]     //0F B2 01         
        lss    ebx,[ecx]     //0F B2 19         
        lss    ecx,[ecx]     //0F B2 09         
        lss    edx,[ecx]     //0F B2 11         
        lss    esp,[ecx]     //0F B2 21         
        lss    ebp,[ecx]     //0F B2 29         
        lss    esi,[ecx]     //0F B2 31         
        lss    edi,[ecx]     //0F B2 39   

        lss    eax,[edx]     //0F B2 02         
        lss    ebx,[edx]     //0F B2 1A         
        lss    ecx,[edx]     //0F B2 0A         
        lss    edx,[edx]     //0F B2 12         
        lss    esp,[edx]     //0F B2 22         
        lss    ebp,[edx]     //0F B2 2A         
        lss    esi,[edx]     //0F B2 32         
        lss    edi,[edx]     //0F B2 3A    

        lss    eax,[esp]     //0F B2 04 24      
        lss    ebx,[esp]     //0F B2 1C 24      
        lss    ecx,[esp]     //0F B2 0C 24      
        lss    edx,[esp]     //0F B2 14 24      
        lss    esp,[esp]     //0F B2 24 24      
        lss    ebp,[esp]     //0F B2 2C 24      
        lss    esi,[esp]     //0F B2 34 24      
        lss    edi,[esp]     //0F B2 3C 24   

        lss    eax,[ebp]     //0F B2 45 00      
        lss    ebx,[ebp]     //0F B2 5D 00      
        lss    ecx,[ebp]     //0F B2 4D 00      
        lss    edx,[ebp]     //0F B2 55 00      
        lss    esp,[ebp]     //0F B2 65 00      
        lss    ebp,[ebp]     //0F B2 6D 00      
        lss    esi,[ebp]     //0F B2 75 00      
        lss    edi,[ebp]     //0F B2 7D 00    

        lss    eax,[esi]     //0F B2 06         
        lss    ebx,[esi]     //0F B2 1E         
        lss    ecx,[esi]     //0F B2 0E         
        lss    edx,[esi]     //0F B2 16         
        lss    esp,[esi]     //0F B2 26         
        lss    ebp,[esi]     //0F B2 2E         
        lss    esi,[esi]     //0F B2 36         
        lss    edi,[esi]     //0F B2 3E    

        lss    eax,[edi]     //0F B2 07         
        lss    ebx,[edi]     //0F B2 1F         
        lss    ecx,[edi]     //0F B2 0F         
        lss    edx,[edi]     //0F B2 17         
        lss    esp,[edi]     //0F B2 27         
        lss    ebp,[edi]     //0F B2 2F         
        lss    esi,[edi]     //0F B2 37         
        lss    edi,[edi]     //0F B2 3F 

        lfs    ax,charTest   //66 0F B4 45 FB    
        lfs    ax,[eax]      //66 0F B4 00       
        lfs    bx,[eax]      //66 0F B4 18       
        lfs    cx,[eax]      //66 0F B4 08       
        lfs    dx,[eax]      //66 0F B4 10       
        lfs    sp,[eax]      //66 0F B4 20       
        lfs    bp,[eax]      //66 0F B4 28       
        lfs    si,[eax]      //66 0F B4 30       
        lfs    di,[eax]      //66 0F B4 38 

        lfs    ax,[ebx]      //66 0F B4 03       
        lfs    bx,[ebx]      //66 0F B4 1B       
        lfs    cx,[ebx]      //66 0F B4 0B       
        lfs    dx,[ebx]      //66 0F B4 13       
        lfs    sp,[ebx]      //66 0F B4 23       
        lfs    bp,[ebx]      //66 0F B4 2B       
        lfs    si,[ebx]      //66 0F B4 33       
        lfs    di,[ebx]      //66 0F B4 3B   

        lfs    ax,[ecx]      //66 0F B4 01       
        lfs    bx,[ecx]      //66 0F B4 19       
        lfs    cx,[ecx]      //66 0F B4 09       
        lfs    dx,[ecx]      //66 0F B4 11       
        lfs    sp,[ecx]      //66 0F B4 21       
        lfs    bp,[ecx]      //66 0F B4 29       
        lfs    si,[ecx]      //66 0F B4 31       
        lfs    di,[ecx]      //66 0F B4 39  

        lfs    ax,[edx]      //66 0F B4 02       
        lfs    bx,[edx]      //66 0F B4 1A       
        lfs    cx,[edx]      //66 0F B4 0A       
        lfs    dx,[edx]      //66 0F B4 12       
        lfs    sp,[edx]      //66 0F B4 22       
        lfs    bp,[edx]      //66 0F B4 2A       
        lfs    si,[edx]      //66 0F B4 32       
        lfs    di,[edx]      //66 0F B4 3A   

        lfs    ax,[esp]      //66 0F B4 04 24    
        lfs    bx,[esp]      //66 0F B4 1C 24    
        lfs    cx,[esp]      //66 0F B4 0C 24    
        lfs    dx,[esp]      //66 0F B4 14 24    
        lfs    sp,[esp]      //66 0F B4 24 24    
        lfs    bp,[esp]      //66 0F B4 2C 24    
        lfs    si,[esp]      //66 0F B4 34 24    
        lfs    di,[esp]      //66 0F B4 3C 24    

        lfs    ax,[ebp]      //66 0F B4 45 00    
        lfs    bx,[ebp]      //66 0F B4 5D 00    
        lfs    cx,[ebp]      //66 0F B4 4D 00    
        lfs    dx,[ebp]      //66 0F B4 55 00    
        lfs    sp,[ebp]      //66 0F B4 65 00    
        lfs    bp,[ebp]      //66 0F B4 6D 00    
        lfs    si,[ebp]      //66 0F B4 75 00    
        lfs    di,[ebp]      //66 0F B4 7D 00    

        lfs    ax,[esi]      //66 0F B4 06       
        lfs    bx,[esi]      //66 0F B4 1E       
        lfs    cx,[esi]      //66 0F B4 0E       
        lfs    dx,[esi]      //66 0F B4 16       
        lfs    sp,[esi]      //66 0F B4 26       
        lfs    bp,[esi]      //66 0F B4 2E       
        lfs    si,[esi]      //66 0F B4 36       
        lfs    di,[esi]      //66 0F B4 3E     

        lfs    ax,[edi]      //66 0F B4 07       
        lfs    bx,[edi]      //66 0F B4 1F       
        lfs    cx,[edi]      //66 0F B4 0F       
        lfs    dx,[edi]      //66 0F B4 17       
        lfs    sp,[edi]      //66 0F B4 27       
        lfs    bp,[edi]      //66 0F B4 2F       
        lfs    si,[edi]      //66 0F B4 37       
        lfs    di,[edi]      //66 0F B4 3F    

        lfs    eax,charTest  //0F B4 45 FB       
        lfs    eax,[eax]     //0F B4 00          
        lfs    ebx,[eax]     //0F B4 18          
        lfs    ecx,[eax]     //0F B4 08          
        lfs    edx,[eax]     //0F B4 10          
        lfs    esp,[eax]     //0F B4 20          
        lfs    ebp,[eax]     //0F B4 28          
        lfs    esi,[eax]     //0F B4 30          
        lfs    edi,[eax]     //0F B4 38     

        lfs    eax,[ebx]     //0F B4 03          
        lfs    ebx,[ebx]     //0F B4 1B          
        lfs    ecx,[ebx]     //0F B4 0B          
        lfs    edx,[ebx]     //0F B4 13          
        lfs    esp,[ebx]     //0F B4 23          
        lfs    ebp,[ebx]     //0F B4 2B          
        lfs    esi,[ebx]     //0F B4 33          
        lfs    edi,[ebx]     //0F B4 3B    

        lfs    eax,[ecx]     //0F B4 01          
        lfs    ebx,[ecx]     //0F B4 19          
        lfs    ecx,[ecx]     //0F B4 09          
        lfs    edx,[ecx]     //0F B4 11          
        lfs    esp,[ecx]     //0F B4 21          
        lfs    ebp,[ecx]     //0F B4 29          
        lfs    esi,[ecx]     //0F B4 31          
        lfs    edi,[ecx]     //0F B4 39     

        lfs    eax,[edx]     //0F B4 02          
        lfs    ebx,[edx]     //0F B4 1A          
        lfs    ecx,[edx]     //0F B4 0A          
        lfs    edx,[edx]     //0F B4 12          
        lfs    esp,[edx]     //0F B4 22          
        lfs    ebp,[edx]     //0F B4 2A          
        lfs    esi,[edx]     //0F B4 32          
        lfs    edi,[edx]     //0F B4 3A          

        lfs    eax,[esp]     //0F B4 04 24       
        lfs    ebx,[esp]     //0F B4 1C 24       
        lfs    ecx,[esp]     //0F B4 0C 24       
        lfs    edx,[esp]     //0F B4 14 24       
        lfs    esp,[esp]     //0F B4 24 24       
        lfs    ebp,[esp]     //0F B4 2C 24       
        lfs    esi,[esp]     //0F B4 34 24       
        lfs    edi,[esp]     //0F B4 3C 24    

        lfs    eax,[ebp]     //0F B4 45 00       
        lfs    ebx,[ebp]     //0F B4 5D 00       
        lfs    ecx,[ebp]     //0F B4 4D 00       
        lfs    edx,[ebp]     //0F B4 55 00       
        lfs    esp,[ebp]     //0F B4 65 00       
        lfs    ebp,[ebp]     //0F B4 6D 00       
        lfs    esi,[ebp]     //0F B4 75 00       
        lfs    edi,[ebp]     //0F B4 7D 00   

        lfs    eax,[esi]     //0F B4 06          
        lfs    ebx,[esi]     //0F B4 1E          
        lfs    ecx,[esi]     //0F B4 0E          
        lfs    edx,[esi]     //0F B4 16          
        lfs    esp,[esi]     //0F B4 26          
        lfs    ebp,[esi]     //0F B4 2E          
        lfs    esi,[esi]     //0F B4 36          
        lfs    edi,[esi]     //0F B4 3E     

        lfs    eax,[edi]     //0F B4 07          
        lfs    ebx,[edi]     //0F B4 1F          
        lfs    ecx,[edi]     //0F B4 0F          
        lfs    edx,[edi]     //0F B4 17          
        lfs    esp,[edi]     //0F B4 27          
        lfs    ebp,[edi]     //0F B4 2F          
        lfs    esi,[edi]     //0F B4 37          
        lfs    edi,[edi]     //0F B4 3F  

        lgs    ax,charTest   //66 0F B5 45 FB  
        lgs    ax,[eax]      //66 0F B5 00     
        lgs    bx,[eax]      //66 0F B5 18     
        lgs    cx,[eax]      //66 0F B5 08     
        lgs    dx,[eax]      //66 0F B5 10     
        lgs    sp,[eax]      //66 0F B5 20     
        lgs    bp,[eax]      //66 0F B5 28     
        lgs    si,[eax]      //66 0F B5 30     
        lgs    di,[eax]      //66 0F B5 38    

        lgs    ax,[ebx]      //66 0F B5 03     
        lgs    bx,[ebx]      //66 0F B5 1B     
        lgs    cx,[ebx]      //66 0F B5 0B     
        lgs    dx,[ebx]      //66 0F B5 13     
        lgs    sp,[ebx]      //66 0F B5 23     
        lgs    bp,[ebx]      //66 0F B5 2B     
        lgs    si,[ebx]      //66 0F B5 33     
        lgs    di,[ebx]      //66 0F B5 3B   

        lgs    ax,[ecx]      //66 0F B5 01     
        lgs    bx,[ecx]      //66 0F B5 19     
        lgs    cx,[ecx]      //66 0F B5 09     
        lgs    dx,[ecx]      //66 0F B5 11     
        lgs    sp,[ecx]      //66 0F B5 21     
        lgs    bp,[ecx]      //66 0F B5 29     
        lgs    si,[ecx]      //66 0F B5 31     
        lgs    di,[ecx]      //66 0F B5 39   

        lgs    ax,[edx]      //66 0F B5 02     
        lgs    bx,[edx]      //66 0F B5 1A     
        lgs    cx,[edx]      //66 0F B5 0A     
        lgs    dx,[edx]      //66 0F B5 12     
        lgs    sp,[edx]      //66 0F B5 22     
        lgs    bp,[edx]      //66 0F B5 2A     
        lgs    si,[edx]      //66 0F B5 32     
        lgs    di,[edx]      //66 0F B5 3A   

        lgs    ax,[esp]      //66 0F B5 04 24  
        lgs    bx,[esp]      //66 0F B5 1C 24  
        lgs    cx,[esp]      //66 0F B5 0C 24  
        lgs    dx,[esp]      //66 0F B5 14 24  
        lgs    sp,[esp]      //66 0F B5 24 24  
        lgs    bp,[esp]      //66 0F B5 2C 24  
        lgs    si,[esp]      //66 0F B5 34 24  
        lgs    di,[esp]      //66 0F B5 3C 24  

        lgs    ax,[ebp]      //66 0F B5 45 00  
        lgs    bx,[ebp]      //66 0F B5 5D 00  
        lgs    cx,[ebp]      //66 0F B5 4D 00  
        lgs    dx,[ebp]      //66 0F B5 55 00  
        lgs    sp,[ebp]      //66 0F B5 65 00  
        lgs    bp,[ebp]      //66 0F B5 6D 00  
        lgs    si,[ebp]      //66 0F B5 75 00  
        lgs    di,[ebp]      //66 0F B5 7D 00  

        lgs    ax,[esi]      //66 0F B5 06     
        lgs    bx,[esi]      //66 0F B5 1E     
        lgs    cx,[esi]      //66 0F B5 0E     
        lgs    dx,[esi]      //66 0F B5 16     
        lgs    sp,[esi]      //66 0F B5 26     
        lgs    bp,[esi]      //66 0F B5 2E     
        lgs    si,[esi]      //66 0F B5 36     
        lgs    di,[esi]      //66 0F B5 3E     

        lgs    ax,[edi]      //66 0F B5 07     
        lgs    bx,[edi]      //66 0F B5 1F     
        lgs    cx,[edi]      //66 0F B5 0F     
        lgs    dx,[edi]      //66 0F B5 17     
        lgs    sp,[edi]      //66 0F B5 27     
        lgs    bp,[edi]      //66 0F B5 2F     
        lgs    si,[edi]      //66 0F B5 37     
        lgs    di,[edi]      //66 0F B5 3F    

        lgs    eax,charTest  //0F B5 45 FB     
        lgs    eax,[eax]     //0F B5 00        
        lgs    ebx,[eax]     //0F B5 18        
        lgs    ecx,[eax]     //0F B5 08        
        lgs    edx,[eax]     //0F B5 10        
        lgs    esp,[eax]     //0F B5 20        
        lgs    ebp,[eax]     //0F B5 28        
        lgs    esi,[eax]     //0F B5 30        
        lgs    edi,[eax]     //0F B5 38    

        lgs    eax,[ebx]     //0F B5 03        
        lgs    ebx,[ebx]     //0F B5 1B        
        lgs    ecx,[ebx]     //0F B5 0B        
        lgs    edx,[ebx]     //0F B5 13        
        lgs    esp,[ebx]     //0F B5 23        
        lgs    ebp,[ebx]     //0F B5 2B        
        lgs    esi,[ebx]     //0F B5 33        
        lgs    edi,[ebx]     //0F B5 3B    

        lgs    eax,[ecx]     //0F B5 01        
        lgs    ebx,[ecx]     //0F B5 19        
        lgs    ecx,[ecx]     //0F B5 09        
        lgs    edx,[ecx]     //0F B5 11        
        lgs    esp,[ecx]     //0F B5 21        
        lgs    ebp,[ecx]     //0F B5 29        
        lgs    esi,[ecx]     //0F B5 31        
        lgs    edi,[ecx]     //0F B5 39    

        lgs    eax,[edx]     //0F B5 02        
        lgs    ebx,[edx]     //0F B5 1A        
        lgs    ecx,[edx]     //0F B5 0A        
        lgs    edx,[edx]     //0F B5 12        
        lgs    esp,[edx]     //0F B5 22        
        lgs    ebp,[edx]     //0F B5 2A        
        lgs    esi,[edx]     //0F B5 32        
        lgs    edi,[edx]     //0F B5 3A        

        lgs    eax,[esp]     //0F B5 04 24     
        lgs    ebx,[esp]     //0F B5 1C 24     
        lgs    ecx,[esp]     //0F B5 0C 24     
        lgs    edx,[esp]     //0F B5 14 24     
        lgs    esp,[esp]     //0F B5 24 24     
        lgs    ebp,[esp]     //0F B5 2C 24     
        lgs    esi,[esp]     //0F B5 34 24     
        lgs    edi,[esp]     //0F B5 3C 24     

        lgs    eax,[ebp]     //0F B5 45 00     
        lgs    ebx,[ebp]     //0F B5 5D 00     
        lgs    ecx,[ebp]     //0F B5 4D 00     
        lgs    edx,[ebp]     //0F B5 55 00     
        lgs    esp,[ebp]     //0F B5 65 00     
        lgs    ebp,[ebp]     //0F B5 6D 00     
        lgs    esi,[ebp]     //0F B5 75 00     
        lgs    edi,[ebp]     //0F B5 7D 00     

        lgs    eax,[esi]     //0F B5 06        
        lgs    ebx,[esi]     //0F B5 1E        
        lgs    ecx,[esi]     //0F B5 0E        
        lgs    edx,[esi]     //0F B5 16        
        lgs    esp,[esi]     //0F B5 26        
        lgs    ebp,[esi]     //0F B5 2E        
        lgs    esi,[esi]     //0F B5 36        
        lgs    edi,[esi]     //0F B5 3E        

        lgs    eax,[edi]     //0F B5 07        
        lgs    ebx,[edi]     //0F B5 1F        
        lgs    ecx,[edi]     //0F B5 0F        
        lgs    edx,[edi]     //0F B5 17        
        lgs    esp,[edi]     //0F B5 27        
        lgs    ebp,[edi]     //0F B5 2F        
        lgs    esi,[edi]     //0F B5 37        
        lgs    edi,[edi]     //0F B5 3F    

        //LEAVE
        leave

        //LODCC
        lodsb
        lodsw
        lodsd

        //
        movsb
        movsd
        movsw

        neg    charTest      //F6 5D FB       
        neg    shortIntTest  //66 F7 5D EC    
        neg    intTest       //F7 5D E0      

        neg    al        //F6 D8          
        neg    ah        //F6 DC          
        neg    bl        //F6 DB          
        neg    bh        //F6 DF          
        neg    cl        //F6 D9          
        neg    ch        //F6 DD          
        neg    dl        //F6 DA          
        neg    dh        //F6 DE 

        neg    ax        //66 F7 D8       
        neg    bx        //66 F7 DB       
        neg    cx        //66 F7 D9       
        neg    dx        //66 F7 DA       
        neg    sp        //66 F7 DC       
        neg    bp           //66 F7 DD       
        neg    si           //66 F7 DE       
        neg    di           //66 F7 DF  

        neg    eax          //F7 D8          
        neg    ebx          //F7 DB          
        neg    ecx          //F7 D9          
        neg    edx          //F7 DA          
        neg    esp          //F7 DC          
        neg    ebp          //F7 DD          
        neg    esi          //F7 DE          
        neg    edi          //F7 DF      

        //NOP
        nop

        //NOT
        not    charTest      //F6 55 FB           
        not    shortIntTest  //66 F7 55 EC        
        not    intTest       //F7 55 E0  

        not    al        //F6 D0          
        not    ah        //F6 D4          
        not    bl        //F6 D3          
        not    bh        //F6 D7          
        not    cl        //F6 D1          
        not    ch        //F6 D5          
        not    dl        //F6 D2          
        not    dh        //F6 D6   

        not    ax        //66 F7 D0           
        not    bx        //66 F7 D3           
        not    cx        //66 F7 D1           
        not    dx        //66 F7 D2           
        not    sp        //66 F7 D4           
        not    bp        //66 F7 D5          
        not    si        //66 F7 D6          
        not    di        //66 F7 D7   

        not    eax           //F7 D0         
        not    ebx           //F7 D3         
        not    ecx           //F7 D1         
        not    edx           //F7 D2         
        not    esp           //F7 D4         
        not    ebp           //F7 D5         
        not    esi           //F7 D6         
        not    edi           //F7 D7   

        //
        pop    charTest      //66 8F 45 FB          
        pop    shortIntTest  //66 8F 45 EC          
        pop    intTest       //8F 45 E0         
        pop    al        //66 58        
        pop    ah        //66 5C        
        pop    bl        //66 5B        
        pop    bh        //66 5F        
        pop    cl        //66 59        
        pop    ch        //66 5D        
        pop    dl        //66 5A        
        pop    dh        //66 5E        
        pop    ax        //66 58        
        pop    bx        //66 5B        
        pop    cx        //66 59        
        pop    dx        //66 5A        
        pop    sp        //66 5C        
        pop    bp        //66 5D           
        pop    si        //66 5E           
        pop    di        //66 5F           
        pop    eax           //58          
        pop    ebx           //5B          
        pop    ecx           //59          
        pop    edx           //5A          
        pop    esp           //5C          
        pop    ebp           //5D          
        pop    esi           //5E          
        pop    edi           //5F           
        pop    ds        //1F           
        pop    es        //07           
        pop    ss        //17           
//        pop  fs        //0F A1        
//        pop  gs        //0F A9 

        popf
        popfd

        //
        push    0x11          // 6A 11          
        push    0x2222        // 68 22 22 00 00     
        push    0x33333333    // 68 33 33 33 33     
        push    charTest      // FF 75 FB           
        push    shortIntTest  // 66 FF 75 EC           
        push    intTest       // FF 75 E0           
        push    al        // 50         
        push    ah        // 54         
        push    bl        // 53         
        push    bh        // 57         
        push    cl        // 51         
        push    ch        // 55         
        push    dl        // 52         
        push    dh        // 56         
        push    ax        // 66 50          
        push    bx        // 66 53          
        push    cx        // 66 51          
        push    dx        // 66 52          
        push    sp        // 66 54          
        push    bp        // 66 55         
        push    si        // 66 56         
        push    di        // 66 57         
        push    eax           // 50        
        push    ebx           // 53        
        push    ecx           // 51        
        push    edx           // 52        
        push    esp           // 54        
        push    ebp           // 55        
        push    esi           // 56        
        push    edi           // 57         
        push    ds        // 1E         
        push    es        // 06         
        push    ss        // 16         
        push    fs        // 0F A0          
        push    gs        // 0F A8    

        pushf
        pushfd

        //

        rcr    charTest    , 1    //D0 5D FB    
        rcr    shortIntTest, 1    //66 D1 5D EC 
        rcr    intTest     , 1    //D1 5D E0    
        rcr    charTest    , cl   //D2 5D FB    
        rcr    shortIntTest, cl   //66 D3 5D EC 
        rcr    intTest     , cl   //D3 5D E0   

        rcr    al, 1          //D0 D8       
        rcr    ah, 1          //D0 DC       
        rcr    bl, 1          //D0 DB       
        rcr    bh, 1          //D0 DF       
        rcr    cl, 1          //D0 D9       
        rcr    ch, 1          //D0 DD       
        rcr    dl, 1          //D0 DA       
        rcr    dh, 1          //D0 DE       
        rcr    ax, 1          //66 D1 D8    
        rcr    bx, 1          //66 D1 DB    
        rcr    cx, 1          //66 D1 D9    
        rcr    dx, 1          //66 D1 DA    
        rcr    sp, 1          //66 D1 DC    
        rcr    bp, 1          //66 D1 DD    
        rcr    si, 1          //66 D1 DE    
        rcr    di, 1          //66 D1 DF    
        rcr    eax, 1         //D1 D8       
        rcr    ebx, 1         //D1 DB       
        rcr    ecx, 1         //D1 D9       
        rcr    edx, 1         //D1 DA       
        rcr    esp, 1         //D1 DC       
        rcr    ebp, 1         //D1 DD       
        rcr    esi, 1         //D1 DE       
        rcr    edi, 1         //D1 DF  

        rcr    al, cl         //D2 D8       
        rcr    ah, cl         //D2 DC       
        rcr    bl, cl         //D2 DB       
        rcr    bh, cl         //D2 DF       
        rcr    cl, cl         //D2 D9       
        rcr    ch, cl         //D2 DD       
        rcr    dl, cl         //D2 DA       
        rcr    dh, cl         //D2 DE       
        rcr    ax, cl         //66 D3 D8    
        rcr    bx, cl         //66 D3 DB    
        rcr    cx, cl         //66 D3 D9    
        rcr    dx, cl         //66 D3 DA    
        rcr    sp, cl         //66 D3 DC    
        rcr    bp, cl         //66 D3 DD    
        rcr    si, cl         //66 D3 DE    
        rcr    di, cl         //66 D3 DF    
        rcr    eax, cl        //D3 D8       
        rcr    ebx, cl        //D3 DB       
        rcr    ecx, cl        //D3 D9       
        rcr    edx, cl        //D3 DA       
        rcr    esp, cl        //D3 DC       
        rcr    ebp, cl        //D3 DD       
        rcr    esi, cl        //D3 DE       
        rcr    edi, cl        //D3 DF   

        rcr    al, 0x22           //C0 D8 22    
        rcr    ah, 0x22           //C0 DC 22    
        rcr    bl, 0x22           //C0 DB 22    
        rcr    bh, 0x22           //C0 DF 22    
        rcr    cl, 0x22           //C0 D9 22    
        rcr    ch, 0x22           //C0 DD 22    
        rcr    dl, 0x22           //C0 DA 22    
        rcr    dh, 0x22           //C0 DE 22    
        rcr    ax, 0x22           //66 C1 D8 22 
        rcr    bx, 0x22           //66 C1 DB 22 
        rcr    cx, 0x22           //66 C1 D9 22 
        rcr    dx, 0x22           //66 C1 DA 22 
        rcr    sp, 0x22           //66 C1 DC 22 
        rcr    bp, 0x22           //66 C1 DD 22 
        rcr    si, 0x22           //66 C1 DE 22 
        rcr    di, 0x22           //66 C1 DF 22 
        rcr    eax, 0x22          //C1 D8 22    
        rcr    ebx, 0x22          //C1 DB 22    
        rcr    ecx, 0x22          //C1 D9 22    
        rcr    edx, 0x22          //C1 DA 22    
        rcr    esp, 0x22          //C1 DC 22    
        rcr    ebp, 0x22          //C1 DD 22    
        rcr    esi, 0x22          //C1 DE 22    
        rcr    edi, 0x22          //C1 DF 22    

        rcl    charTest    , 1    //D0 55 FB           
        rcl    shortIntTest, 1    //66 D1 55 EC         
        rcl    intTest     , 1    //D1 55 E0           
        rcl    charTest    , cl   //D2 55 FB           
        rcl    shortIntTest, cl   //66 D3 55 EC        
        rcl    intTest     , cl   //D3 55 E0  

        rcl    al, 1          //D0 D0          
        rcl    ah, 1          //D0 D4           
        rcl    bl, 1          //D0 D3        
        rcl    bh, 1          //D0 D7           
        rcl    cl, 1          //D0 D1           
        rcl    ch, 1          //D0 D5           
        rcl    dl, 1          //D0 D2           
        rcl    dh, 1          //D0 D6           
        rcl    ax, 1          //66 D1 D0        
        rcl    bx, 1          //66 D1 D3        
        rcl    cx, 1          //66 D1 D1        
        rcl    dx, 1          //66 D1 D2        
        rcl    sp, 1          //66 D1 D4        
        rcl    bp, 1          //66 D1 D5           
        rcl    si, 1          //66 D1 D6           
        rcl    di, 1          //66 D1 D7           
        rcl    eax, 1         //D1 D0          
        rcl    ebx, 1         //D1 D3          
        rcl    ecx, 1         //D1 D1          
        rcl    edx, 1         //D1 D2          
        rcl    esp, 1         //D1 D4          
        rcl    ebp, 1         //D1 D5          
        rcl    esi, 1         //D1 D6          
        rcl    edi, 1         //D1 D7      

        rcl    al, cl         //D2 D0          
        rcl    ah, cl         //D2 D4          
        rcl    bl, cl         //D2 D3          
        rcl    bh, cl         //D2 D7          
        rcl    cl, cl         //D2 D1          
        rcl    ch, cl         //D2 D5          
        rcl    dl, cl         //D2 D2          
        rcl    dh, cl         //D2 D6          
        rcl    ax, cl         //66 D3 D0           
        rcl    bx, cl         //66 D3 D3           
        rcl    cx, cl         //66 D3 D1           
        rcl    dx, cl         //66 D3 D2           
        rcl    sp, cl         //66 D3 D4           
        rcl    bp, cl         //66 D3 D5           
        rcl    si, cl         //66 D3 D6           
        rcl    di, cl         //66 D3 D7           
        rcl    eax, cl        //D3 D0          
        rcl    ebx, cl        //D3 D3          
        rcl    ecx, cl        //D3 D1          
        rcl    edx, cl        //D3 D2          
        rcl    esp, cl        //D3 D4          
        rcl    ebp, cl        //D3 D5          
        rcl    esi, cl        //D3 D6          
        rcl    edi, cl        //D3 D7    

        rcl    al, 0x22           //C0 D0 22        
        rcl    ah, 0x22           //C0 D4 22           
        rcl    bl, 0x22           //C0 D3 22        
        rcl    bh, 0x22           //C0 D7 22           
        rcl    cl, 0x22           //C0 D1 22           
        rcl    ch, 0x22           //C0 D5 22          
        rcl    dl, 0x22           //C0 D2 22          
        rcl    dh, 0x22           //C0 D6 22          
        rcl    ax, 0x22           //66 C1 D0 22           
        rcl    bx, 0x22           //66 C1 D3 22           
        rcl    cx, 0x22           //66 C1 D1 22         
        rcl    dx, 0x22           //66 C1 D2 22           
        rcl    sp, 0x22           //66 C1 D4 22           
        rcl    bp, 0x22           //66 C1 D5 22          
        rcl    si, 0x22           //66 C1 D6 22          
        rcl    di, 0x22           //66 C1 D7 22          
        rcl    eax, 0x22          //C1 D0 22        
        rcl    ebx, 0x22          //C1 D3 22        
        rcl    ecx, 0x22          //C1 D1 22        
        rcl    edx, 0x22          //C1 D2 22        
        rcl    esp, 0x22          //C1 D4 22          
        rcl    ebp, 0x22          //C1 D5 22          
        rcl    esi, 0x22          //C1 D6 22          
        rcl    edi, 0x22          //C1 D7 22 

        rol    charTest    , 1    //D0 45 FB        
        rol    shortIntTest, 1    //66 D1 45 EC      
        rol    intTest     , 1    //D1 45 E0        
        rol    charTest    , cl   //D2 45 FB        
        rol    shortIntTest, cl   //66 D3 45 EC     
        rol    intTest     , cl   //D3 45 E0   

        rol    al, 1          //D0 C0           
        rol    ah, 1          //D0 C4        
        rol    bl, 1          //D0 C3         
        rol    bh, 1          //D0 C7        
        rol    cl, 1          //D0 C1        
        rol    ch, 1          //D0 C5        
        rol    dl, 1          //D0 C2        
        rol    dh, 1          //D0 C6        
        rol    ax, 1          //66 D1 C0         
        rol    bx, 1          //66 D1 C3         
        rol    cx, 1          //66 D1 C1         
        rol    dx, 1          //66 D1 C2         
        rol    sp, 1          //66 D1 C4         
        rol    bp, 1          //66 D1 C5        
        rol    si, 1          //66 D1 C6        
        rol    di, 1          //66 D1 C7        
        rol    eax, 1         //D1 C0           
        rol    ebx, 1         //D1 C3           
        rol    ecx, 1         //D1 C1           
        rol    edx, 1         //D1 C2           
        rol    esp, 1         //D1 C4           
        rol    ebp, 1         //D1 C5           
        rol    esi, 1         //D1 C6           
        rol    edi, 1         //D1 C7  

        rol    al, cl         //D2 C0           
        rol    ah, cl         //D2 C4           
        rol    bl, cl         //D2 C3           
        rol    bh, cl         //D2 C7           
        rol    cl, cl         //D2 C1           
        rol    ch, cl         //D2 C5           
        rol    dl, cl         //D2 C2           
        rol    dh, cl         //D2 C6           
        rol    ax, cl         //66 D3 C0        
        rol    bx, cl         //66 D3 C3        
        rol    cx, cl         //66 D3 C1        
        rol    dx, cl         //66 D3 C2        
        rol    sp, cl         //66 D3 C4        
        rol    bp, cl         //66 D3 C5        
        rol    si, cl         //66 D3 C6        
        rol    di, cl         //66 D3 C7        
        rol    eax, cl        //D3 C0           
        rol    ebx, cl        //D3 C3           
        rol    ecx, cl        //D3 C1           
        rol    edx, cl        //D3 C2           
        rol    esp, cl        //D3 C4           
        rol    ebp, cl        //D3 C5           
        rol    esi, cl        //D3 C6           
        rol    edi, cl        //D3 C7  

        rol    al, 0x22           //C0 C0 22         
        rol    ah, 0x22           //C0 C4 22        
        rol    bl, 0x22           //C0 C3 22         
        rol    bh, 0x22           //C0 C7 22        
        rol    cl, 0x22           //C0 C1 22        
        rol    ch, 0x22           //C0 C5 22           
        rol    dl, 0x22           //C0 C2 22           
        rol    dh, 0x22           //C0 C6 22           
        rol    ax, 0x22           //66 C1 C0 22        
        rol    bx, 0x22           //66 C1 C3 22        
        rol    cx, 0x22           //66 C1 C1 22      
        rol    dx, 0x22           //66 C1 C2 22        
        rol    sp, 0x22           //66 C1 C4 22        
        rol    bp, 0x22           //66 C1 C5 22       
        rol    si, 0x22           //66 C1 C6 22       
        rol    di, 0x22           //66 C1 C7 22       
        rol    eax, 0x22          //C1 C0 22         
        rol    ebx, 0x22          //C1 C3 22         
        rol    ecx, 0x22          //C1 C1 22         
        rol    edx, 0x22          //C1 C2 22         
        rol    esp, 0x22          //C1 C4 22           
        rol    ebp, 0x22          //C1 C5 22           
        rol    esi, 0x22          //C1 C6 22           
        rol    edi, 0x22          //C1 C7 22  

        ror    charTest    , 1    //D0 4D FB        
        ror    shortIntTest, 1    //66 D1 4D EC     
        ror    intTest     , 1    //D1 4D E0        
        ror    charTest    , cl   //D2 4D FB        
        ror    shortIntTest, cl   //66 D3 4D EC     
        ror    intTest     , cl   //D3 4D E0  

        ror    al, 1          //D0 C8           
        ror    ah, 1          //D0 CC           
        ror    bl, 1          //D0 CB        
        ror    bh, 1          //D0 CF           
        ror    cl, 1          //D0 C9           
        ror    ch, 1          //D0 CD           
        ror    dl, 1          //D0 CA           
        ror    dh, 1          //D0 CE           
        ror    ax, 1          //66 D1 C8        
        ror    bx, 1          //66 D1 CB        
        ror    cx, 1          //66 D1 C9        
        ror    dx, 1          //66 D1 CA        
        ror    sp, 1          //66 D1 CC        
        ror    bp, 1          //66 D1 CD        
        ror    si, 1          //66 D1 CE        
        ror    di, 1          //66 D1 CF        
        ror    eax, 1         //D1 C8           
        ror    ebx, 1         //D1 CB           
        ror    ecx, 1         //D1 C9           
        ror    edx, 1         //D1 CA           
        ror    esp, 1         //D1 CC           
        ror    ebp, 1         //D1 CD           
        ror    esi, 1         //D1 CE           
        ror    edi, 1         //D1 CF    

        ror    al, cl         //D2 C8           
        ror    ah, cl         //D2 CC           
        ror    bl, cl         //D2 CB           
        ror    bh, cl         //D2 CF           
        ror    cl, cl         //D2 C9           
        ror    ch, cl         //D2 CD           
        ror    dl, cl         //D2 CA           
        ror    dh, cl         //D2 CE           
        ror    ax, cl         //66 D3 C8        
        ror    bx, cl         //66 D3 CB        
        ror    cx, cl         //66 D3 C9        
        ror    dx, cl         //66 D3 CA        
        ror    sp, cl         //66 D3 CC        
        ror    bp, cl         //66 D3 CD        
        ror    si, cl         //66 D3 CE        
        ror    di, cl         //66 D3 CF        
        ror    eax, cl        //D3 C8           
        ror    ebx, cl        //D3 CB           
        ror    ecx, cl        //D3 C9           
        ror    edx, cl        //D3 CA           
        ror    esp, cl        //D3 CC           
        ror    ebp, cl        //D3 CD           
        ror    esi, cl        //D3 CE           
        ror    edi, cl        //D3 CF    

        ror    al, 0x22           //C0 C8 22        
        ror    ah, 0x22           //C0 CC 22           
        ror    bl, 0x22           //C0 CB 22        
        ror    bh, 0x22           //C0 CF 22           
        ror    cl, 0x22           //C0 C9 22           
        ror    ch, 0x22           //C0 CD 22          
        ror    dl, 0x22           //C0 CA 22          
        ror    dh, 0x22           //C0 CE 22          
        ror    ax, 0x22           //66 C1 C8 22       
        ror    bx, 0x22           //66 C1 CB 22       
        ror    cx, 0x22           //66 C1 C9 22     
        ror    dx, 0x22           //66 C1 CA 22       
        ror    sp, 0x22           //66 C1 CC 22       
        ror    bp, 0x22           //66 C1 CD 22      
        ror    si, 0x22           //66 C1 CE 22      
        ror    di, 0x22           //66 C1 CF 22      
        ror    eax, 0x22          //C1 C8 22        
        ror    ebx, 0x22          //C1 CB 22        
        ror    ecx, 0x22          //C1 C9 22        
        ror    edx, 0x22          //C1 CA 22        
        ror    esp, 0x22          //C1 CC 22          
        ror    ebp, 0x22          //C1 CD 22          
        ror    esi, 0x22          //C1 CE 22          
        ror    edi, 0x22          //C1 CF 22  

        //RET (N)
        ret        //C3       
        ret 0x11   //C2 11 00 

        //SAHF
        sahf

        //sal shl
        sal    charTest    , 1    // D0 65 FB      
        sal    shortIntTest, 1    // 66 D1 65 EC   
        sal    intTest     , 1    // D1 65 E0      
        sal    charTest    , cl   // D2 65 FB      
        sal    shortIntTest, cl   // 66 D3 65 EC   
        sal    intTest     , cl   // D3 65 E0      
        sal    charTest    , 0x22 // C0 65 FB 22   
        sal    shortIntTest, 0x22 // 66 C1 65 EC 22
        sal    intTest     , 0x22 // C1 65 E0 22   
        sal    al, 1          // D0 E0         
        sal    ah, 1          // D0 E4         
        sal    bl, 1          // D0 E3         
        sal    bh, 1          // D0 E7         
        sal    cl, 1          // D0 E1         
        sal    ch, 1          // D0 E5         
        sal    dl, 1          // D0 E2         
        sal    dh, 1          // D0 E6         
        sal    ax, 1          // 66 D1 E0      
        sal    bx, 1          // 66 D1 E3      
        sal    cx, 1          // 66 D1 E1      
        sal    dx, 1          // 66 D1 E2      
        sal    sp, 1          // 66 D1 E4      
        sal    bp, 1          // 66 D1 E5      
        sal    si, 1          // 66 D1 E6      
        sal    di, 1          // 66 D1 E7      
        sal    eax, 1         // D1 E0         
        sal    ebx, 1         // D1 E3         
        sal    ecx, 1         // D1 E1         
        sal    edx, 1         // D1 E2         
        sal    esp, 1         // D1 E4         
        sal    ebp, 1         // D1 E5         
        sal    esi, 1         // D1 E6         
        sal    edi, 1         // D1 E7         
        sal    al, cl         // D2 E0         
        sal    ah, cl         // D2 E4         
        sal    bl, cl         // D2 E3         
        sal    bh, cl         // D2 E7         
        sal    cl, cl         // D2 E1         
        sal    ch, cl         // D2 E5         
        sal    dl, cl         // D2 E2         
        sal    dh, cl         // D2 E6         
        sal    ax, cl         // 66 D3 E0      
        sal    bx, cl         // 66 D3 E3      
        sal    cx, cl         // 66 D3 E1      
        sal    dx, cl         // 66 D3 E2      
        sal    sp, cl         // 66 D3 E4      
        sal    bp, cl         // 66 D3 E5      
        sal    si, cl         // 66 D3 E6      
        sal    di, cl         // 66 D3 E7      
        sal    eax, cl        // D3 E0         
        sal    ebx, cl        // D3 E3         
        sal    ecx, cl        // D3 E1         
        sal    edx, cl        // D3 E2         
        sal    esp, cl        // D3 E4         
        sal    ebp, cl        // D3 E5         
        sal    esi, cl        // D3 E6         
        sal    edi, cl        // D3 E7         
        sal    al, 0x22           // C0 E0 22      
        sal    ah, 0x22           // C0 E4 22      
        sal    bl, 0x22           // C0 E3 22      
        sal    bh, 0x22           // C0 E7 22      
        sal    cl, 0x22           // C0 E1 22      
        sal    ch, 0x22           // C0 E5 22      
        sal    dl, 0x22           // C0 E2 22      
        sal    dh, 0x22           // C0 E6 22      
        sal    ax, 0x22           // 66 C1 E0 22   
        sal    bx, 0x22           // 66 C1 E3 22   
        sal    cx, 0x22           // 66 C1 E1 22   
        sal    dx, 0x22           // 66 C1 E2 22   
        sal    sp, 0x22           // 66 C1 E4 22   
        sal    bp, 0x22           // 66 C1 E5 22   
        sal    si, 0x22           // 66 C1 E6 22   
        sal    di, 0x22           // 66 C1 E7 22   
        sal    eax, 0x22          // C1 E0 22      
        sal    ebx, 0x22          // C1 E3 22      
        sal    ecx, 0x22          // C1 E1 22      
        sal    edx, 0x22          // C1 E2 22      
        sal    esp, 0x22          // C1 E4 22      
        sal    ebp, 0x22          // C1 E5 22      
        sal    esi, 0x22          // C1 E6 22      
        sal    edi, 0x22          // C1 E7 22      


        //
        sar    charTest    , 1    //D0 7D FB           
        sar    shortIntTest, 1    //66 D1 7D EC        
        sar    intTest     , 1    //D1 7D E0           
        sar    charTest    , cl   //D2 7D FB           
        sar    shortIntTest, cl   //66 D3 7D EC        
        sar    intTest     , cl   //D3 7D E0         
        sar    charTest    , 0x22 //C0 7D FB 22        
        sar    shortIntTest, 0x22 //66 C1 7D EC 22     
        sar    intTest     , 0x22 //C1 7D E0 22      
        sar    al, 1          //D0 F8          
        sar    ah, 1          //D0 FC          
        sar    bl, 1          //D0 FB           
        sar    bh, 1          //D0 FF          
        sar    cl, 1          //D0 F9          
        sar    ch, 1          //D0 FD          
        sar    dl, 1          //D0 FA          
        sar    dh, 1          //D0 FE          
        sar    ax, 1          //66 D1 F8           
        sar    bx, 1          //66 D1 FB           
        sar    cx, 1          //66 D1 F9           
        sar    dx, 1          //66 D1 FA           
        sar    sp, 1          //66 D1 FC           
        sar    bp, 1          //66 D1 FD           
        sar    si, 1          //66 D1 FE           
        sar    di, 1          //66 D1 FF           
        sar    eax, 1         //D1 F8          
        sar    ebx, 1         //D1 FB          
        sar    ecx, 1         //D1 F9          
        sar    edx, 1         //D1 FA          
        sar    esp, 1         //D1 FC          
        sar    ebp, 1         //D1 FD          
        sar    esi, 1         //D1 FE          
        sar    edi, 1         //D1 FF        
        sar    al, cl         //D2 F8          
        sar    ah, cl         //D2 FC          
        sar    bl, cl         //D2 FB          
        sar    bh, cl         //D2 FF          
        sar    cl, cl         //D2 F9          
        sar    ch, cl         //D2 FD          
        sar    dl, cl         //D2 FA          
        sar    dh, cl         //D2 FE          
        sar    ax, cl         //66 D3 F8           
        sar    bx, cl         //66 D3 FB           
        sar    cx, cl         //66 D3 F9           
        sar    dx, cl         //66 D3 FA           
        sar    sp, cl         //66 D3 FC           
        sar    bp, cl         //66 D3 FD           
        sar    si, cl         //66 D3 FE           
        sar    di, cl         //66 D3 FF           
        sar    eax, cl        //D3 F8          
        sar    ebx, cl        //D3 FB          
        sar    ecx, cl        //D3 F9          
        sar    edx, cl        //D3 FA          
        sar    esp, cl        //D3 FC          
        sar    ebp, cl        //D3 FD          
        sar    esi, cl        //D3 FE          
        sar    edi, cl        //D3 FF        
        sar    al, 0x22           //C0 F8 22           
        sar    ah, 0x22           //C0 FC 22          
        sar    bl, 0x22           //C0 FB 22           
        sar    bh, 0x22           //C0 FF 22          
        sar    cl, 0x22           //C0 F9 22          
        sar    ch, 0x22           //C0 FD 22         
        sar    dl, 0x22           //C0 FA 22         
        sar    dh, 0x22           //C0 FE 22         
        sar    ax, 0x22           //66 C1 F8 22          
        sar    bx, 0x22           //66 C1 FB 22          
        sar    cx, 0x22           //66 C1 F9 22        
        sar    dx, 0x22           //66 C1 FA 22          
        sar    sp, 0x22           //66 C1 FC 22          
        sar    bp, 0x22           //66 C1 FD 22         
        sar    si, 0x22           //66 C1 FE 22         
        sar    di, 0x22           //66 C1 FF 22         
        sar    eax, 0x22          //C1 F8 22           
        sar    ebx, 0x22          //C1 FB 22           
        sar    ecx, 0x22          //C1 F9 22           
        sar    edx, 0x22          //C1 FA 22           
        sar    esp, 0x22          //C1 FC 22         
        sar    ebp, 0x22          //C1 FD 22         
        sar    esi, 0x22          //C1 FE 22         
        sar    edi, 0x22          //C1 FF 22   


        shr    charTest    , 1    // D0 6D FB        
        shr    shortIntTest, 1    // 66 D1 6D EC         
        shr    intTest     , 1    // D1 6D E0        
        shr    charTest    , cl   // D2 6D FB        
        shr    shortIntTest, cl   // 66 D3 6D EC         
        shr    intTest     , cl   // D3 6D E0          
        shr    charTest    , 0x22 // C0 6D FB 22         
        shr    shortIntTest, 0x22 // 66 C1 6D EC 22      
        shr    intTest     , 0x22 // C1 6D E0 22       
        shr    al, 1          // D0 E8           
        shr    ah, 1          // D0 EC           
        shr    bl, 1          // D0 EB        
        shr    bh, 1          // D0 EF           
        shr    cl, 1          // D0 E9           
        shr    ch, 1          // D0 ED           
        shr    dl, 1          // D0 EA           
        shr    dh, 1          // D0 EE           
        shr    ax, 1          // 66 D1 E8        
        shr    bx, 1          // 66 D1 EB        
        shr    cx, 1          // 66 D1 E9        
        shr    dx, 1          // 66 D1 EA        
        shr    sp, 1          // 66 D1 EC        
        shr    bp, 1          // 66 D1 ED        
        shr    si, 1          // 66 D1 EE        
        shr    di, 1          // 66 D1 EF        
        shr    eax, 1         // D1 E8           
        shr    ebx, 1         // D1 EB           
        shr    ecx, 1         // D1 E9           
        shr    edx, 1         // D1 EA           
        shr    esp, 1         // D1 EC           
        shr    ebp, 1         // D1 ED           
        shr    esi, 1         // D1 EE           
        shr    edi, 1         // D1 EF         
        shr    al, cl         // D2 E8           
        shr    ah, cl         // D2 EC           
        shr    bl, cl         // D2 EB           
        shr    bh, cl         // D2 EF           
        shr    cl, cl         // D2 E9           
        shr    ch, cl         // D2 ED           
        shr    dl, cl         // D2 EA           
        shr    dh, cl         // D2 EE           
        shr    ax, cl         // 66 D3 E8        
        shr    bx, cl         // 66 D3 EB        
        shr    cx, cl         // 66 D3 E9        
        shr    dx, cl         // 66 D3 EA        
        shr    sp, cl         // 66 D3 EC        
        shr    bp, cl         // 66 D3 ED        
        shr    si, cl         // 66 D3 EE        
        shr    di, cl         // 66 D3 EF        
        shr    eax, cl        // D3 E8           
        shr    ebx, cl        // D3 EB           
        shr    ecx, cl        // D3 E9           
        shr    edx, cl        // D3 EA           
        shr    esp, cl        // D3 EC           
        shr    ebp, cl        // D3 ED           
        shr    esi, cl        // D3 EE           
        shr    edi, cl        // D3 EF         
        shr    al, 0x22           // C0 E8 22        
        shr    ah, 0x22           // C0 EC 22           
        shr    bl, 0x22           // C0 EB 22        
        shr    bh, 0x22           // C0 EF 22           
        shr    cl, 0x22           // C0 E9 22           
        shr    ch, 0x22           // C0 ED 22          
        shr    dl, 0x22           // C0 EA 22          
        shr    dh, 0x22           // C0 EE 22          
        shr    ax, 0x22           // 66 C1 E8 22           
        shr    bx, 0x22           // 66 C1 EB 22           
        shr    cx, 0x22           // 66 C1 E9 22         
        shr    dx, 0x22           // 66 C1 EA 22           
        shr    sp, 0x22           // 66 C1 EC 22           
        shr    bp, 0x22           // 66 C1 ED 22          
        shr    si, 0x22           // 66 C1 EE 22          
        shr    di, 0x22           // 66 C1 EF 22          
        shr    eax, 0x22          // C1 E8 22        
        shr    ebx, 0x22          // C1 EB 22        
        shr    ecx, 0x22          // C1 E9 22        
        shr    edx, 0x22          // C1 EA 22        
        shr    esp, 0x22          // C1 EC 22          
        shr    ebp, 0x22          // C1 ED 22          
        shr    esi, 0x22          // C1 EE 22          
        shr    edi, 0x22          // C1 EF 22   

        scasb
        scasw
        scasd

        stosb
        stosw
        stosd

        test    al, 0x22         //A8 22        
        test    ax, 0x2222           //66 A9 22 22          
        test    eax, 0x22222222       //A9 22 22 22 22       
        test    charTest,0x22          //F6 45 FB 22           
        test    shortIntTest,0x2222    //66 F7 45 EC 22 22    
        test    intTest,0x22222222    //F7 45 E0 22 22 22 22
        test    ah, 0x22         //F6 C4 22         
        test    bl, 0x22         //F6 C3 22         
        test    bh, 0x22         //F6 C7 22         
        test    cl, 0x22         //F6 C1 22         
        test    ch, 0x22         //F6 C5 22         
        test    dl, 0x22         //F6 C2 22         
        test    dh, 0x22         //F6 C6 22         
        test    ax, 0x2222           //66 A9 22 22      
        test    bx, 0x2222           //66 F7 C3 22 22   
        test    cx, 0x2222           //66 F7 C1 22 22   
        test    dx, 0x2222           //66 F7 C2 22 22   
        test    sp, 0x2222           //66 F7 C4 22 22   
        test    bp, 0x2222           //66 F7 C5 22 22   
        test    si, 0x2222           //66 F7 C6 22 22   
        test    di, 0x2222           //66 F7 C7 22 22   
        test    eax, 0x22222222      //A9 22 22 22 22   
        test    ebx, 0x22222222      //F7 C3 22 22 22 22
        test    ecx, 0x22222222      //F7 C1 22 22 22 22
        test    edx, 0x22222222      //F7 C2 22 22 22 22
        test    esp, 0x22222222      //F7 C4 22 22 22 22
        test    ebp, 0x22222222      //F7 C5 22 22 22 22
        test    esi, 0x22222222      //F7 C6 22 22 22 22
        test    edi, 0x22222222      //F7 C7 22 22 22 22
        test    al, charTest         //84 45 FB         
        test    ah, charTest         //84 65 FB         
        test    bl, charTest         //84 5D FB         
        test    bh, charTest         //84 7D FB         
        test    cl, charTest         //84 4D FB         
        test    ch, charTest         //84 6D FB         
        test    dl, charTest         //84 55 FB         
        test    dh, charTest         //84 75 FB         
        test    ax, shortIntTest     //66 85 45 EC      
        test    bx, shortIntTest     //66 85 5D EC      
        test    cx, shortIntTest     //66 85 4D EC      
        test    dx, shortIntTest     //66 85 55 EC      
        test    sp, shortIntTest     //66 85 65 EC      
        test    bp, shortIntTest     //66 85 6D EC      
        test    si, shortIntTest     //66 85 75 EC      
        test    di, shortIntTest     //66 85 7D EC      
        test    eax,  intTest      //85 45 E0         
        test    ebx,  intTest      //85 5D E0         
        test    edx,  intTest      //85 55 E0         
        test    ecx,  intTest      //85 4D E0         
        test    esp,  intTest      //85 65 E0         
        test    ebp,  intTest      //85 6D E0         
        test    esi,  intTest      //85 75 E0         
        test    edi,  intTest      //85 7D E0         
        test    al,al          //84 C0        
        test    al,ah          //84 C4        
        test    al,bl          //84 C3        
        test    al,bh          //84 C7        
        test    al,cl          //84 C1        
        test    al,ch          //84 C5        
        test    al,dl          //84 C2        
        test    al,dh          //84 C6        
        test    ah,al          //84 E0        
        test    ah,ah          //84 E4        
        test    ah,bl          //84 E3        
        test    ah,bh          //84 E7        
        test    ah,cl          //84 E1        
        test    ah,ch          //84 E5        
        test    ah,dl          //84 E2        
        test    ah,dh          //84 E6        
        test    bl,al          //84 D8         
        test    bl,ah          //84 DC         
        test    bl,bl          //84 DB         
        test    bl,bh          //84 DF         
        test    bl,cl          //84 D9         
        test    bl,ch          //84 DD         
        test    bl,dl          //84 DA         
        test    bl,dh          //84 DE         
        test    bh,al          //84 F8         
        test    bh,ah          //84 FC         
        test    bh,bl          //84 FB         
        test    bh,bh          //84 FF         
        test    bh,cl          //84 F9         
        test    bh,ch          //84 FD         
        test    bh,dl          //84 FA         
        test    bh,dh          //84 FE         
        test    cl,al          //84 C8         
        test    cl,ah          //84 CC         
        test    cl,bl          //84 CB         
        test    cl,bh          //84 CF         
        test    cl,cl          //84 C9         
        test    cl,ch          //84 CD         
        test    cl,dl          //84 CA         
        test    cl,dh          //84 CE         
        test    ch,al          //84 E8         
        test    ch,ah          //84 EC         
        test    ch,bl          //84 EB         
        test    ch,bh          //84 EF         
        test    ch,cl          //84 E9         
        test    ch,ch          //84 ED         
        test    ch,dl          //84 EA         
        test    ch,dh          //84 EE         
        test    dl,al          //84 D0         
        test    dl,ah          //84 D4         
        test    dl,bl          //84 D3         
        test    dl,bh          //84 D7         
        test    dl,cl          //84 D1         
        test    dl,ch          //84 D5         
        test    dl,dl          //84 D2         
        test    dl,dh          //84 D6         
        test    dh,al          //84 F0         
        test    dh,ah          //84 F4         
        test    dh,bl          //84 F3         
        test    dh,bh          //84 F7         
        test    dh,cl          //84 F1         
        test    dh,ch          //84 F5         
        test    dh,dl          //84 F2         
        test    dh,dh          //84 F6         
        test    ax,ax          //66 85 C0          
        test    ax,bx          //66 85 C3          
        test    ax,dx          //66 85 C2          
        test    ax,cx          //66 85 C1          
        test    ax,sp          //66 85 C4          
        test    ax,bp          //66 85 C5          
        test    ax,si          //66 85 C6          
        test    ax,di          //66 85 C7          
        test    bx,ax          //66 85 D8          
        test    bx,bx          //66 85 DB          
        test    bx,dx          //66 85 DA          
        test    bx,cx          //66 85 D9          
        test    bx,sp          //66 85 DC          
        test    bx,bp          //66 85 DD          
        test    bx,si          //66 85 DE          
        test    bx,di          //66 85 DF          
        test    cx,ax          //66 85 C8          
        test    cx,bx          //66 85 CB          
        test    cx,dx          //66 85 CA          
        test    cx,cx          //66 85 C9          
        test    cx,sp          //66 85 CC          
        test    cx,bp          //66 85 CD          
        test    cx,si          //66 85 CE          
        test    cx,di          //66 85 CF          
        test    dx,ax          //66 85 D0          
        test    dx,bx          //66 85 D3          
        test    dx,cx          //66 85 D1          
        test    dx,dx          //66 85 D2          
        test    dx,sp          //66 85 D4          
        test    dx,bp          //66 85 D5          
        test    dx,si          //66 85 D6          
        test    dx,di          //66 85 D7          
        test    sp,ax          //66 85 E0          
        test    sp,bx          //66 85 E3          
        test    sp,dx          //66 85 E2          
        test    sp,cx          //66 85 E1          
        test    sp,sp          //66 85 E4          
        test    sp,bp          //66 85 E5          
        test    sp,si          //66 85 E6          
        test    sp,di          //66 85 E7          
        test    bp,ax          //66 85 E8          
        test    bp,bx          //66 85 EB          
        test    bp,cx          //66 85 E9          
        test    bp,dx          //66 85 EA          
        test    bp,sp          //66 85 EC          
        test    bp,bp          //66 85 ED          
        test    bp,di          //66 85 EF          
        test    bp,si          //66 85 EE          
        test    si,ax          //66 85 F0          
        test    si,bx          //66 85 F3          
        test    si,dx          //66 85 F2          
        test    si,cx          //66 85 F1          
        test    si,sp          //66 85 F4          
        test    si,bp          //66 85 F5          
        test    si,si          //66 85 F6          
        test    si,di          //66 85 F7          
        test    di,ax          //66 85 F8          
        test    di,bx          //66 85 FB          
        test    di,cx          //66 85 F9          
        test    di,dx          //66 85 FA          
        test    di,sp          //66 85 FC          
        test    di,bp          //66 85 FD          
        test    di,si          //66 85 FE          
        test    di,di          //66 85 FF          
        test    eax,eax        //85 C0         
        test    eax,ebx        //85 C3         
        test    eax,edx        //85 C2         
        test    eax,ecx        //85 C1         
        test    eax,esp        //85 C4         
        test    eax,ebp        //85 C5         
        test    eax,esi        //85 C6         
        test    eax,edi        //85 C7         
        test    ebx,eax        //85 D8         
        test    ebx,ebx        //85 DB         
        test    ebx,edx        //85 DA         
        test    ebx,ecx        //85 D9         
        test    ebx,esp        //85 DC         
        test    ebx,ebp        //85 DD         
        test    ebx,esi        //85 DE         
        test    ebx,edi        //85 DF         
        test    ecx,eax        //85 C8         
        test    ecx,ebx        //85 CB         
        test    ecx,edx        //85 CA         
        test    ecx,ecx        //85 C9         
        test    ecx,esp        //85 CC         
        test    ecx,ebp        //85 CD         
        test    ecx,esi        //85 CE         
        test    ecx,edi        //85 CF         
        test    edx,eax        //85 D0         
        test    edx,ebx        //85 D3         
        test    edx,ecx        //85 D1         
        test    edx,edx        //85 D2         
        test    edx,esp        //85 D4         
        test    edx,ebp        //85 D5         
        test    edx,esi        //85 D6         
        test    edx,edi        //85 D7         
        test    esp,eax        //85 E0         
        test    esp,ebx        //85 E3         
        test    esp,edx        //85 E2         
        test    esp,ecx        //85 E1         
        test    esp,esp        //85 E4         
        test    esp,ebp        //85 E5         
        test    esp,esi        //85 E6         
        test    esp,edi        //85 E7         
        test    ebp,eax        //85 E8         
        test    ebp,ebx        //85 EB         
        test    ebp,ecx        //85 E9         
        test    ebp,edx        //85 EA         
        test    ebp,esp        //85 EC         
        test    ebp,ebp        //85 ED         
        test    ebp,edi        //85 EF         
        test    ebp,esi        //85 EE         
        test    esi,eax        //85 F0         
        test    esi,ebx        //85 F3         
        test    esi,edx        //85 F2         
        test    esi,ecx        //85 F1         
        test    esi,esp        //85 F4         
        test    esi,ebp        //85 F5         
        test    esi,esi        //85 F6         
        test    esi,edi        //85 F7         
        test    edi,eax        //85 F8         
        test    edi,ebx        //85 FB         
        test    edi,ecx        //85 F9         
        test    edi,edx        //85 FA         
        test    edi,esp        //85 FC         
        test    edi,ebp        //85 FD         
        test    edi,esi        //85 FE         
        test    edi,edi        //85 FF 

        //XCHG
        xchg    ax,ax          //66 90          
        xchg    ax,bx          //66 93          
        xchg    ax,dx          //66 92          
        xchg    ax,cx          //66 91          
        xchg    ax,sp          //66 94          
        xchg    ax,bp          //66 95          
        xchg    ax,si          //66 96          
        xchg    ax,di          //66 97          
        xchg    bx,ax          //66 93          
        xchg    dx,ax          //66 92          
        xchg    cx,ax          //66 91          
        xchg    sp,ax          //66 94          
        xchg    bp,ax          //66 95          
        xchg    si,ax          //66 96          
        xchg    di,ax          //66 97          
        xchg    eax,eax        //90         
        xchg    eax,ebx        //93         
        xchg    eax,edx        //92         
        xchg    eax,ecx        //91         
        xchg    eax,esp        //94         
        xchg    eax,ebp        //95         
        xchg    eax,esi        //96         
        xchg    eax,edi        //97         
        xchg    ebx,eax        //93         
        xchg    edx,eax        //92         
        xchg    ecx,eax        //91         
        xchg    esp,eax        //94         
        xchg    ebp,eax        //95         
        xchg    esi,eax        //96         
        xchg    edi,eax        //97         
        xchg    al,al          //86 C0          
        xchg    al,ah          //86 C4          
        xchg    al,bl          //86 C3          
        xchg    al,bh          //86 C7          
        xchg    al,cl          //86 C1          
        xchg    al,ch          //86 C5          
        xchg    al,dl          //86 C2          
        xchg    al,dh          //86 C6          
        xchg    ah,al          //86 E0          
        xchg    ah,ah          //86 E4          
        xchg    ah,bl          //86 E3          
        xchg    ah,bh          //86 E7          
        xchg    ah,cl          //86 E1          
        xchg    ah,ch          //86 E5          
        xchg    ah,dl          //86 E2          
        xchg    ah,dh          //86 E6          
        xchg    bl,al          //86 D8          
        xchg    bl,ah          //86 DC          
        xchg    bl,bl          //86 DB          
        xchg    bl,bh          //86 DF          
        xchg    bl,cl          //86 D9          
        xchg    bl,ch          //86 DD          
        xchg    bl,dl          //86 DA          
        xchg    bl,dh          //86 DE          
        xchg    bh,al          //86 F8          
        xchg    bh,ah          //86 FC          
        xchg    bh,bl          //86 FB          
        xchg    bh,bh          //86 FF          
        xchg    bh,cl          //86 F9          
        xchg    bh,ch          //86 FD          
        xchg    bh,dl          //86 FA          
        xchg    bh,dh          //86 FE          
        xchg    cl,al          //86 C8          
        xchg    cl,ah          //86 CC          
        xchg    cl,bl          //86 CB          
        xchg    cl,bh          //86 CF          
        xchg    cl,cl          //86 C9          
        xchg    cl,ch          //86 CD          
        xchg    cl,dl          //86 CA          
        xchg    cl,dh          //86 CE          
        xchg    ch,al          //86 E8          
        xchg    ch,ah          //86 EC          
        xchg    ch,bl          //86 EB          
        xchg    ch,bh          //86 EF          
        xchg    ch,cl          //86 E9          
        xchg    ch,ch          //86 ED          
        xchg    ch,dl          //86 EA          
        xchg    ch,dh          //86 EE          
        xchg    dl,al          //86 D0          
        xchg    dl,ah          //86 D4          
        xchg    dl,bl          //86 D3          
        xchg    dl,bh          //86 D7          
        xchg    dl,cl          //86 D1          
        xchg    dl,ch          //86 D5          
        xchg    dl,dl          //86 D2          
        xchg    dl,dh          //86 D6          
        xchg    dh,al          //86 F0          
        xchg    dh,ah          //86 F4          
        xchg    dh,bl          //86 F3          
        xchg    dh,bh          //86 F7          
        xchg    dh,cl          //86 F1          
        xchg    dh,ch          //86 F5          
        xchg    dh,dl          //86 F2          
        xchg    dh,dh          //86 F6          
        xchg    charTest,al          //86 45 FB       
        xchg    charTest,ah          //86 65 FB       
        xchg    charTest,bl          //86 5D FB       
        xchg    charTest,bh          //86 7D FB       
        xchg    charTest,cl          //86 4D FB       
        xchg    charTest,ch          //86 6D FB       
        xchg    charTest,dl          //86 55 FB       
        xchg    charTest,dh          //86 75 FB       
        xchg    al, charTest         //86 45 FB       
        xchg    ah, charTest         //86 65 FB       
        xchg    bl, charTest         //86 5D FB       
        xchg    bh, charTest         //86 7D FB       
        xchg    cl, charTest         //86 4D FB       
        xchg    ch, charTest         //86 6D FB       
        xchg    dl, charTest         //86 55 FB       
        xchg    dh, charTest         //86 75 FB       
        xchg    ax, shortIntTest     //66 87 45 EC    
        xchg    bx, shortIntTest     //66 87 5D EC    
        xchg    cx, shortIntTest     //66 87 4D EC    
        xchg    dx, shortIntTest     //66 87 55 EC    
        xchg    sp, shortIntTest     //66 87 65 EC    
        xchg    bp, shortIntTest     //66 87 6D EC    
        xchg    si, shortIntTest     //66 87 75 EC    
        xchg    di, shortIntTest     //66 87 7D EC    
        xchg    shortIntTest, ax     //66 87 45 EC    
        xchg    shortIntTest, bx     //66 87 5D EC    
        xchg    shortIntTest, cx     //66 87 4D EC    
        xchg    shortIntTest, dx     //66 87 55 EC    
        xchg    shortIntTest, sp     //66 87 65 EC    
        xchg    shortIntTest, bp     //66 87 6D EC    
        xchg    shortIntTest, si     //66 87 75 EC    
        xchg    shortIntTest, di     //66 87 7D EC    
        xchg    eax,  intTest      //87 45 E0       
        xchg    ebx,  intTest      //87 5D E0       
        xchg    edx,  intTest      //87 55 E0       
        xchg    ecx,  intTest      //87 4D E0       
        xchg    esp,  intTest      //87 65 E0       
        xchg    ebp,  intTest      //87 6D E0       
        xchg    esi,  intTest      //87 75 E0       
        xchg    edi,  intTest      //87 7D E0       
        xchg    intTest, eax       //87 45 E0       
        xchg    intTest, ebx       //87 5D E0       
        xchg    intTest, edx       //87 55 E0       
        xchg    intTest, ecx       //87 4D E0       
        xchg    intTest, esp       //87 65 E0       
        xchg    intTest, ebp       //87 6D E0       
        xchg    intTest, esi       //87 75 E0       
        xchg    intTest, edi       //87 7D E0       
        xchg    bx,ax          //66 93          
        xchg    bx,bx          //66 87 DB       
        xchg    bx,dx          //66 87 DA       
        xchg    bx,cx          //66 87 D9       
        xchg    bx,sp          //66 87 DC       
        xchg    bx,bp          //66 87 DD       
        xchg    bx,si          //66 87 DE       
        xchg    bx,di          //66 87 DF       
        xchg    cx,ax          //66 91          
        xchg    cx,bx          //66 87 CB       
        xchg    cx,dx          //66 87 CA       
        xchg    cx,cx          //66 87 C9       
        xchg    cx,sp          //66 87 CC       
        xchg    cx,bp          //66 87 CD       
        xchg    cx,si          //66 87 CE       
        xchg    cx,di          //66 87 CF       
        xchg    dx,ax          //66 92          
        xchg    dx,bx          //66 87 D3       
        xchg    dx,cx          //66 87 D1       
        xchg    dx,dx          //66 87 D2       
        xchg    dx,sp          //66 87 D4       
        xchg    dx,bp          //66 87 D5       
        xchg    dx,si          //66 87 D6       
        xchg    dx,di          //66 87 D7       
        xchg    sp,ax          //66 94          
        xchg    sp,bx          //66 87 E3       
        xchg    sp,dx          //66 87 E2       
        xchg    sp,cx          //66 87 E1       
        xchg    sp,sp          //66 87 E4       
        xchg    sp,bp          //66 87 E5       
        xchg    sp,si          //66 87 E6       
        xchg    sp,di          //66 87 E7       
        xchg    bp,ax          //66 95          
        xchg    bp,bx          //66 87 EB       
        xchg    bp,cx          //66 87 E9       
        xchg    bp,dx          //66 87 EA       
        xchg    bp,sp          //66 87 EC       
        xchg    bp,bp          //66 87 ED       
        xchg    bp,di          //66 87 EF       
        xchg    bp,si          //66 87 EE       
        xchg    si,ax          //66 96          
        xchg    si,bx          //66 87 F3       
        xchg    si,dx          //66 87 F2       
        xchg    si,cx          //66 87 F1       
        xchg    si,sp          //66 87 F4       
        xchg    si,bp          //66 87 F5       
        xchg    si,si          //66 87 F6       
        xchg    si,di          //66 87 F7       
        xchg    di,ax          //66 97          
        xchg    di,bx          //66 87 FB       
        xchg    di,cx          //66 87 F9       
        xchg    di,dx          //66 87 FA       
        xchg    di,sp          //66 87 FC       
        xchg    di,bp          //66 87 FD       
        xchg    di,si          //66 87 FE       
        xchg    di,di          //66 87 FF         
        xchg    ebx,ebx        //87 DB          
        xchg    ebx,edx        //87 DA          
        xchg    ebx,ecx        //87 D9          
        xchg    ebx,esp        //87 DC          
        xchg    ebx,ebp        //87 DD          
        xchg    ebx,esi        //87 DE          
        xchg    ebx,edi        //87 DF           
        xchg    ecx,ebx        //87 CB          
        xchg    ecx,edx        //87 CA          
        xchg    ecx,ecx        //87 C9          
        xchg    ecx,esp        //87 CC          
        xchg    ecx,ebp        //87 CD          
        xchg    ecx,esi        //87 CE          
        xchg    ecx,edi        //87 CF           
        xchg    edx,ebx        //87 D3          
        xchg    edx,ecx        //87 D1          
        xchg    edx,edx        //87 D2          
        xchg    edx,esp        //87 D4          
        xchg    edx,ebp        //87 D5          
        xchg    edx,esi        //87 D6          
        xchg    edx,edi        //87 D7          
        xchg    esp,ebx        //87 E3          
        xchg    esp,edx        //87 E2          
        xchg    esp,ecx        //87 E1          
        xchg    esp,esp        //87 E4          
        xchg    esp,ebp        //87 E5          
        xchg    esp,esi        //87 E6          
        xchg    esp,edi        //87 E7           
        xchg    ebp,ebx        //87 EB          
        xchg    ebp,ecx        //87 E9          
        xchg    ebp,edx        //87 EA          
        xchg    ebp,esp        //87 EC          
        xchg    ebp,ebp        //87 ED          
        xchg    ebp,edi        //87 EF          
        xchg    ebp,esi        //87 EE          
        xchg    esi,eax        //96         
        xchg    esi,ebx        //87 F3          
        xchg    esi,edx        //87 F2          
        xchg    esi,ecx        //87 F1          
        xchg    esi,esp        //87 F4          
        xchg    esi,ebp        //87 F5          
        xchg    esi,esi        //87 F6          
        xchg    esi,edi        //87 F7          
        xchg    edi,eax        //97         
        xchg    edi,ebx        //87 FB          
        xchg    edi,ecx        //87 F9          
        xchg    edi,edx        //87 FA          
        xchg    edi,esp        //87 FC          
        xchg    edi,ebp        //87 FD          
        xchg    edi,esi        //87 FE          
        xchg    edi,edi        //87 FF   

        //XOR
        xor    al, 0x22         // 34 22         
        xor    ax, 0x2222           // 66 35 22 22          
        xor    eax, 0x22222222       // 35 22 22 22 22           
        xor    charTest,0x22          // 80 75 FB 22          
        xor    shortIntTest,0x2222    // 66 81 75 EC 22 22      
        xor    intTest,0x22222222    // 81 75 E0 22 22 22 22   
        xor    ah, 0x22         // 80 F4 22           
        xor    bl, 0x22         // 80 F3 22           
        xor    bh, 0x22         // 80 F7 22           
        xor    cl, 0x22         // 80 F1 22           
        xor    ch, 0x22         // 80 F5 22           
        xor    dl, 0x22         // 80 F2 22           
        xor    dh, 0x22         // 80 F6 22           
        xor    ax, 0x2222           // 66 35 22 22        
        xor    bx, 0x2222           // 66 81 F3 22 22     
        xor    cx, 0x2222           // 66 81 F1 22 22     
        xor    dx, 0x2222           // 66 81 F2 22 22     
        xor    sp, 0x2222           // 66 81 F4 22 22     
        xor    bp, 0x2222           // 66 81 F5 22 22     
        xor    si, 0x2222           // 66 81 F6 22 22     
        xor    di, 0x2222           // 66 81 F7 22 22     
        xor    eax, 0x22222222      // 35 22 22 22 22     
        xor    ebx, 0x22222222      // 81 F3 22 22 22 22  
        xor    ecx, 0x22222222      // 81 F1 22 22 22 22  
        xor    edx, 0x22222222      // 81 F2 22 22 22 22  
        xor    esp, 0x22222222      // 81 F4 22 22 22 22  
        xor    ebp, 0x22222222      // 81 F5 22 22 22 22  
        xor    esi, 0x22222222      // 81 F6 22 22 22 22  
        xor    edi, 0x22222222      // 81 F7 22 22 22 22  
        xor    shortIntTest,0x22      // 66 83 75 EC 22     
        xor    ax, 0x22         // 66 35 22 00        
        xor    bx, 0x22         // 66 83 F3 22        
        xor    cx, 0x22         // 66 83 F1 22        
        xor    dx, 0x22         // 66 83 F2 22        
        xor    sp, 0x22         // 66 83 F4 22        
        xor    bp, 0x22         // 66 83 F5 22        
        xor    si, 0x22         // 66 83 F6 22        
        xor    di, 0x22         // 66 83 F7 22        
        xor    intTest,0x22          // 83 75 E0 22        
        xor    eax, 0x22         // 83 F0 22           
        xor    ebx, 0x22         // 83 F3 22           
        xor    ecx, 0x22         // 83 F1 22           
        xor    edx, 0x22         // 83 F2 22           
        xor    esp, 0x22         // 83 F4 22           
        xor    ebp, 0x22         // 83 F5 22           
        xor    esi, 0x22         // 83 F6 22           
        xor    edi, 0x22         // 83 F7 22           
        xor    ax,ax          // 66 33 C0           
        xor    ax,bx          // 66 33 C3           
        xor    ax,dx          // 66 33 C2           
        xor    ax,cx          // 66 33 C1           
        xor    ax,sp          // 66 33 C4           
        xor    ax,bp          // 66 33 C5           
        xor    ax,si          // 66 33 C6           
        xor    ax,di          // 66 33 C7           
        xor    bx,ax          // 66 33 D8           
        xor    dx,ax          // 66 33 D0           
        xor    cx,ax          // 66 33 C8           
        xor    sp,ax          // 66 33 E0           
        xor    bp,ax          // 66 33 E8           
        xor    si,ax          // 66 33 F0           
        xor    di,ax          // 66 33 F8           
        xor    eax,eax        // 33 C0          
        xor    eax,ebx        // 33 C3          
        xor    eax,edx        // 33 C2          
        xor    eax,ecx        // 33 C1          
        xor    eax,esp        // 33 C4          
        xor    eax,ebp        // 33 C5          
        xor    eax,esi        // 33 C6          
        xor    eax,edi        // 33 C7          
        xor    ebx,eax        // 33 D8          
        xor    edx,eax        // 33 D0          
        xor    ecx,eax        // 33 C8          
        xor    esp,eax        // 33 E0          
        xor    ebp,eax        // 33 E8          
        xor    esi,eax        // 33 F0          
        xor    edi,eax        // 33 F8          
        xor    al,al          // 32 C0          
        xor    al,ah          // 32 C4          
        xor    al,bl          // 32 C3          
        xor    al,bh          // 32 C7          
        xor    al,cl          // 32 C1          
        xor    al,ch          // 32 C5          
        xor    al,dl          // 32 C2          
        xor    al,dh          // 32 C6          
        xor    ah,al          // 32 E0          
        xor    ah,ah          // 32 E4          
        xor    ah,bl          // 32 E3          
        xor    ah,bh          // 32 E7          
        xor    ah,cl          // 32 E1          
        xor    ah,ch          // 32 E5          
        xor    ah,dl          // 32 E2          
        xor    ah,dh          // 32 E6          
        xor    bl,al          // 32 D8          
        xor    bl,ah          // 32 DC          
        xor    bl,bl          // 32 DB          
        xor    bl,bh          // 32 DF          
        xor    bl,cl          // 32 D9          
        xor    bl,ch          // 32 DD          
        xor    bl,dl          // 32 DA          
        xor    bl,dh          // 32 DE          
        xor    bh,al          // 32 F8          
        xor    bh,ah          // 32 FC          
        xor    bh,bl          // 32 FB          
        xor    bh,bh          // 32 FF          
        xor    bh,cl          // 32 F9          
        xor    bh,ch          // 32 FD          
        xor    bh,dl          // 32 FA          
        xor    bh,dh          // 32 FE          
        xor    cl,al          // 32 C8          
        xor    cl,ah          // 32 CC          
        xor    cl,bl          // 32 CB          
        xor    cl,bh          // 32 CF          
        xor    cl,cl          // 32 C9          
        xor    cl,ch          // 32 CD          
        xor    cl,dl          // 32 CA          
        xor    cl,dh          // 32 CE          
        xor    ch,al          // 32 E8          
        xor    ch,ah          // 32 EC          
        xor    ch,bl          // 32 EB          
        xor    ch,bh          // 32 EF          
        xor    ch,cl          // 32 E9          
        xor    ch,ch          // 32 ED          
        xor    ch,dl          // 32 EA          
        xor    ch,dh          // 32 EE          
        xor    dl,al          // 32 D0          
        xor    dl,ah          // 32 D4          
        xor    dl,bl          // 32 D3          
        xor    dl,bh          // 32 D7          
        xor    dl,cl          // 32 D1          
        xor    dl,ch          // 32 D5          
        xor    dl,dl          // 32 D2          
        xor    dl,dh          // 32 D6          
        xor    dh,al          // 32 F0          
        xor    dh,ah          // 32 F4          
        xor    dh,bl          // 32 F3          
        xor    dh,bh          // 32 F7          
        xor    dh,cl          // 32 F1          
        xor    dh,ch          // 32 F5          
        xor    dh,dl          // 32 F2          
        xor    dh,dh          // 32 F6          
        xor    charTest,al          // 30 45 FB           
        xor    charTest,ah          // 30 65 FB           
        xor    charTest,bl          // 30 5D FB           
        xor    charTest,bh          // 30 7D FB           
        xor    charTest,cl          // 30 4D FB           
        xor    charTest,ch          // 30 6D FB           
        xor    charTest,dl          // 30 55 FB           
        xor    charTest,dh          // 30 75 FB           
        xor    al, charTest         // 32 45 FB           
        xor    ah, charTest         // 32 65 FB           
        xor    bl, charTest         // 32 5D FB           
        xor    bh, charTest         // 32 7D FB           
        xor    cl, charTest         // 32 4D FB           
        xor    ch, charTest         // 32 6D FB           
        xor    dl, charTest         // 32 55 FB           
        xor    dh, charTest         // 32 75 FB           
        xor    ax, shortIntTest    // 66 33 45 EC        
        xor    bx, shortIntTest    // 66 33 5D EC        
        xor    cx, shortIntTest    // 66 33 4D EC        
        xor    dx, shortIntTest    // 66 33 55 EC        
        xor    sp, shortIntTest    // 66 33 65 EC        
        xor    bp, shortIntTest    // 66 33 6D EC        
        xor    si, shortIntTest    // 66 33 75 EC        
        xor    di, shortIntTest    // 66 33 7D EC        
        xor    shortIntTest, ax    // 66 31 45 EC        
        xor    shortIntTest, bx    // 66 31 5D EC        
        xor    shortIntTest, cx    // 66 31 4D EC        
        xor    shortIntTest, dx    // 66 31 55 EC        
        xor    shortIntTest, sp    // 66 31 65 EC        
        xor    shortIntTest, bp    // 66 31 6D EC        
        xor    shortIntTest, si    // 66 31 75 EC        
        xor    shortIntTest, di    // 66 31 7D EC        
        xor    eax,  intTest      // 33 45 E0           
        xor    ebx,  intTest      // 33 5D E0           
        xor    edx,  intTest      // 33 55 E0           
        xor    ecx,  intTest      // 33 4D E0           
        xor    esp,  intTest      // 33 65 E0           
        xor    ebp,  intTest      // 33 6D E0           
        xor    esi,  intTest      // 33 75 E0           
        xor    edi,  intTest      // 33 7D E0           
        xor    intTest, eax       // 31 45 E0           
        xor    intTest, ebx       // 31 5D E0           
        xor    intTest, edx       // 31 55 E0           
        xor    intTest, ecx       // 31 4D E0           
        xor    intTest, esp       // 31 65 E0           
        xor    intTest, ebp       // 31 6D E0           
        xor    intTest, esi       // 31 75 E0           
        xor    intTest, edi       // 31 7D E0           
        xor    bx,ax           // 66 33 D8           
        xor    bx,bx           // 66 33 DB           
        xor    bx,dx           // 66 33 DA           
        xor    bx,cx           // 66 33 D9           
        xor    bx,sp           // 66 33 DC           
        xor    bx,bp           // 66 33 DD           
        xor    bx,si           // 66 33 DE           
        xor    bx,di           // 66 33 DF           
        xor    cx,ax           // 66 33 C8           
        xor    cx,bx           // 66 33 CB           
        xor    cx,dx           // 66 33 CA           
        xor    cx,cx           // 66 33 C9           
        xor    cx,sp           // 66 33 CC           
        xor    cx,bp           // 66 33 CD           
        xor    cx,si           // 66 33 CE           
        xor    cx,di           // 66 33 CF           
        xor    dx,ax           // 66 33 D0           
        xor    dx,bx           // 66 33 D3           
        xor    dx,cx           // 66 33 D1           
        xor    dx,dx           // 66 33 D2           
        xor    dx,sp           // 66 33 D4           
        xor    dx,bp           // 66 33 D5           
        xor    dx,si           // 66 33 D6           
        xor    dx,di           // 66 33 D7           
        xor    sp,ax           // 66 33 E0           
        xor    sp,bx           // 66 33 E3           
        xor    sp,dx           // 66 33 E2           
        xor    sp,cx           // 66 33 E1           
        xor    sp,sp           // 66 33 E4           
        xor    sp,bp           // 66 33 E5           
        xor    sp,si           // 66 33 E6           
        xor    sp,di           // 66 33 E7           
        xor    bp,ax           // 66 33 E8           
        xor    bp,bx           // 66 33 EB           
        xor    bp,cx           // 66 33 E9           
        xor    bp,dx           // 66 33 EA           
        xor    bp,sp           // 66 33 EC           
        xor    bp,bp           // 66 33 ED           
        xor    bp,di           // 66 33 EF           
        xor    bp,si           // 66 33 EE           
        xor    si,ax           // 66 33 F0           
        xor    si,bx           // 66 33 F3           
        xor    si,dx           // 66 33 F2           
        xor    si,cx           // 66 33 F1           
        xor    si,sp           // 66 33 F4           
        xor    si,bp           // 66 33 F5           
        xor    si,si           // 66 33 F6           
        xor    si,di           // 66 33 F7           
        xor    di,ax           // 66 33 F8           
        xor    di,bx           // 66 33 FB           
        xor    di,cx           // 66 33 F9           
        xor    di,dx           // 66 33 FA           
        xor    di,sp           // 66 33 FC           
        xor    di,bp           // 66 33 FD           
        xor    di,si           // 66 33 FE           
        xor    di,di           // 66 33 FF           
        xor    ebx,ebx         // 33 DB          
        xor    ebx,edx         // 33 DA          
        xor    ebx,ecx         // 33 D9          
        xor    ebx,esp         // 33 DC          
        xor    ebx,ebp         // 33 DD          
        xor    ebx,esi         // 33 DE          
        xor    ebx,edi         // 33 DF          
        xor    ecx,ebx         // 33 CB          
        xor    ecx,edx         // 33 CA          
        xor    ecx,ecx         // 33 C9          
        xor    ecx,esp         // 33 CC          
        xor    ecx,ebp         // 33 CD          
        xor    ecx,esi         // 33 CE          
        xor    ecx,edi         // 33 CF          
        xor    edx,ebx         // 33 D3          
        xor    edx,ecx         // 33 D1          
        xor    edx,edx         // 33 D2          
        xor    edx,esp         // 33 D4          
        xor    edx,ebp         // 33 D5          
        xor    edx,esi         // 33 D6          
        xor    edx,edi         // 33 D7          
        xor    esp,ebx         // 33 E3          
        xor    esp,edx         // 33 E2          
        xor    esp,ecx         // 33 E1          
        xor    esp,esp         // 33 E4          
        xor    esp,ebp         // 33 E5          
        xor    esp,esi         // 33 E6          
        xor    esp,edi         // 33 E7          
        xor    ebp,ebx         // 33 EB          
        xor    ebp,ecx         // 33 E9          
        xor    ebp,edx         // 33 EA          
        xor    ebp,esp         // 33 EC          
        xor    ebp,ebp         // 33 ED          
        xor    ebp,edi         // 33 EF          
        xor    ebp,esi         // 33 EE          
        xor    esi,eax         // 33 F0          
        xor    esi,ebx         // 33 F3          
        xor    esi,edx         // 33 F2          
        xor    esi,ecx         // 33 F1          
        xor    esi,esp         // 33 F4          
        xor    esi,ebp         // 33 F5          
        xor    esi,esi         // 33 F6          
        xor    esi,edi         // 33 F7          
        xor    edi,eax         // 33 F8          
        xor    edi,ebx         // 33 FB          
        xor    edi,ecx         // 33 F9          
        xor    edi,edx         // 33 FA          
        xor    edi,esp         // 33 FC          
        xor    edi,ebp         // 33 FD          
        xor    edi,esi         // 33 FE          
        xor    edi,edi         // 33 FF  

        lea    ax , charTest         //66 8D 45 FB   
        lea    ax , shortIntTest         //66 8D 45 EC   
        lea    ax , intTest          //66 8D 45 E0   
        lea    ax , longLongIntTest      //66 8D 45 D0   
        lea    bx , intTest          //66 8D 5D E0   
        lea    cx , intTest          //66 8D 4D E0   
        lea    dx , intTest          //66 8D 55 E0   
        lea    bp , intTest          //66 8D 6D E0   
        lea    sp , intTest          //66 8D 65 E0   
        lea    di , intTest          //66 8D 7D E0   
        lea    si , intTest          //66 8D 75 E0   
        lea    eax , intTest         //8D 45 E0      
        lea    ebx , intTest         //8D 5D E0      
        lea    ecx , intTest         //8D 4D E0      
        lea    edx , intTest         //8D 55 E0      
        lea    ebp , intTest         //8D 6D E0      
        lea    esp , intTest         //8D 65 E0      
        lea    edi , intTest         //8D 7D E0      
        lea    esi , intTest         //8D 75 E0   

        cbw    //66 98 
        cwde   //98    

        cwd    //66 99  
        cdq    //99  

        cmc    //F5  
        clc    //F8
        stc    //F9
        cli    //FA
        sti    //FB
        cld    //FC
        std    //FD

        //LOOPcc
        //loop codestart     //E2 FE  
        //loope codestart    //E1 FC  
        //loopne codestart   //E0 FA 
/*
        ja  codestart         // 77 FE        
        jae codestart         // 73 FC        
        jb  codestart         // 72 FA        
        jbe codestart         // 76 F8        
        jc  codestart         // 72 F6        
        jcxz codestart        // 67 E3 F3         
        jecxz codestart       // E3 F1        
        je   codestart        // 74 EF        
        jg   codestart        // 7F ED        
        jge  codestart        // 7D EB        
        jl   codestart        // 7C E9        
        jle  codestart        // 7E E7        
        jna  codestart        // 76 E5        
        jnae codestart        // 72 E3        
        jnb  codestart        // 73 E1        
        jnbe codestart        // 77 DF        
        jnc  codestart        // 73 DD        
        jne  codestart        // 75 DB        
        jng  codestart        // 7E D9        
        jnge codestart        // 7C D7        
        jnl  codestart        // 7D D5        
        jnle codestart        // 7F D3        
        jno  codestart        // 71 D1        
        jnp  codestart        // 7B CF        
        jns  codestart        // 79 CD        
        jnz  codestart        // 75 CB        
        jo   codestart        // 70 C9        
        jp   codestart        // 7A C7        
        jpe  codestart        // 7A C5        
        jpo  codestart        // 7B C3        
        js   codestart        // 78 C1        
        jz   codestart        // 74 BF        
        //      ja   0x44         // 0F 87 00 00 00 00 
        //      ja   0x44444444       // 0F 87 00 00 00 00 
        //      jae  0x4444           // 0F 83 00 00 00 00 
        //      jae  0x44444444       // 0F 83 00 00 00 00 
        //     jb   0x4444           // 0F 82 00 00 00 00 
        //     jb   0x44444444       // 0F 82 00 00 00 00 
        //     jbe  0x4444           // 0F 86 00 00 00 00 
        //     jbe  0x44444444       // 0F 86 00 00 00 00 
        //     jc   0x4444           // 0F 82 00 00 00 00 
        //     jc   0x44444444       // 0F 82 00 00 00 00 
        //     je   0x4444           // 0F 84 00 00 00 00 
        //     je   0x44444444       // 0F 84 00 00 00 00 
        //     jz   0x4444           // 0F 84 00 00 00 00 
        //     jz   0x44444444       // 0F 84 00 00 00 00 
        //     jg   0x4444           // 0F 8F 00 00 00 00 
        //     jg   0x44444444       // 0F 8F 00 00 00 00 
        //     jge  0x4444           // 0F 8D 00 00 00 00 
        //     jge  0x44444444       // 0F 8D 00 00 00 00 
        //     jl   0x4444           // 0F 8C 00 00 00 00 
        //     jl   0x44444444       // 0F 8C 00 00 00 00 
        //     jle  0x4444           // 0F 8E 00 00 00 00 
        //     jle  0x44444444       // 0F 8E 00 00 00 00 
        //     jna  0x4444           // 0F 86 00 00 00 00 
        //     jna  0x44444444       // 0F 86 00 00 00 00 
        //     jnae 0x4444           // 0F 82 00 00 00 00 
        //     jnae 0x44444444       // 0F 82 00 00 00 00 
        //     jnb  0x4444           // 0F 83 00 00 00 00 
        //     jnb  0x44444444       // 0F 83 00 00 00 00 
        //     jnbe  0x4444          // 0F 87 00 00 00 00 
        //     jnbe  0x44444444      // 0F 87 00 00 00 00 
        //     jnc   0x4444          // 0F 83 00 00 00 00 
        //     jnc   0x44444444      // 0F 83 00 00 00 00 
        //     jne   0x4444          // 0F 85 00 00 00 00 
        //     jne   0x44444444      // 0F 85 00 00 00 00 
        //     jng   0x4444          // 0F 8E 00 00 00 00 
        //     jng   0x44444444      // 0F 8E 00 00 00 00 
        //     jnge  0x4444          // 0F 8C 00 00 00 00 
        //     jnge  0x44444444      // 0F 8C 00 00 00 00 
        //     jnl   0x4444          // 0F 8D 00 00 00 00 
        //     jnl   0x44444444      // 0F 8D 00 00 00 00 
        //     jnle  0x4444          // 0F 8F 00 00 00 00 
        //     jnle  0x44444444      // 0F 8F 00 00 00 00 
        //     jno   0x4444          // 0F 81 00 00 00 00 
        //     jno   0x44444444      // 0F 81 00 00 00 00 
        //     jnp   0x4444          // 0F 8B 00 00 00 00 
        //     jnp   0x44444444      // 0F 8B 00 00 00 00 
        //     jns   0x4444          // 0F 89 00 00 00 00 
        //     jns   0x44444444      // 0F 89 00 00 00 00 
        //     jnz   0x4444          // 0F 85 00 00 00 00 
        //     jnz   0x44444444      // 0F 85 00 00 00 00 
        //     jo    0x4444          // 0F 80 00 00 00 00 
        //     jo    0x44444444      // 0F 80 00 00 00 00 
        //     jp    0x4444          // 0F 8A 00 00 00 00 
        //     jp    0x44444444      // 0F 8A 00 00 00 00 
        //     jpe   0x4444          // 0F 8A 00 00 00 00 
        //     jpe   0x44444444      // 0F 8A 00 00 00 00 
        //     jpo   0x4444          // 0F 8B 00 00 00 00 
        //     jpo   0x44444444      // 0F 8B 00 00 00 00 
        //     js    0x4444          // 0F 88 00 00 00 00 
        //     js    0x44444444      // 0F 88 00 00 00 00 
        //     jz    0x4444          // 0F 84 00 00 00 00 
        //     jz    0x44444444      // 0F 84 00 00 00 00 
*/
        //mov         dword ptr ds:[0040A02Ch],eax//A3 2C A0 40 00
        _emit 0xa3
        _emit 0x2c
        _emit 0xa0
        _emit 0x40
        _emit 0x00
        mov         ecx,dword ptr [eax+edx*8+10h]//8B 4C D0 10
        //adc         eax,dword ptr [eax + 0X00]//13 40 00
        _emit 0x13
        _emit 0x40
        _emit 0x00
        //jmp         0x004015FD//E9 64 01 00 00
        _emit 0xe9
        _emit 0x64
        _emit 0x01
        _emit 0x00
        _emit 0x00
        //and esp, -8//83 E4 F8
        lea         eax,[eax+ecx+18h]//8D 44 08 18
        lea         edx,[edi+edi*2]//8D 14 7F
        mul edi//f7 e7
        
        
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
getpointer:
           mov ebx, codestart
           mov [pStart], ebx
           mov eax, getpointer
           mov [pEnd], eax
    }
    //for(i = 0; i < (size_t)(pEnd - pStart); i ++){
    //    printf("%02X ", *(pStart + i));
    //}
    //printf("\n");
    
    *pCodeSize = (size_t)(pEnd - pStart);
    pBinCode = pStart;//(PBYTE)malloc(*pCodeSize);

//    if(NULL != pBinCode){
//        memset(pBinCode, 0, *pCodeSize);
//        memcpy(pBinCode, pStart, *pCodeSize);
//    }

    return pBinCode;

}

void  Bubble_Sort_ASM(void)
{
    _asm{
        //冒泡法排序汇编代码 , 所有变量地址，手工改写
        mov   edi,0x50000000  
        mov   eax , 0         //eax i初始化,                           
        jmp   OUTERCMP        // 转到比较            
OUTERLOOP:  add   eax , 1         // i++             
OUTERCMP:   cmp   eax,0x6         //条件比较              
        jge   QUIT        //跳外循环            
        mov   ebx,0x6         //ebx ,j初始化               
        sub   ebx, 1                 
        jmp   INTERCMP                   
INERLOOP:   sub   ebx , 1         // j--             
INTERCMP:   cmp   eax ,ebx        //条件比较  i < j          
        jge   OUTER           //跳外循环体             
        mov   esi,ebx                              
        mov   ecx,[edi][esi*4]//ecx = arr[j]         
        sub   esi, 1                 
        mov   edx,[edi][esi*4]//edx = arr[j-1]          
        cmp   edx , ecx       //arr[j-1] < arr[j]       
        jge   INERLOOP                   
        add   esi, 1                 
        mov   [edi][esi*4],edx;//arr[j] = arr[j-1]         
        sub   esi, 1                 
        mov   [edi][esi*4],ecx //arr[j-1] = arr[j]        
        jmp   INERLOOP                  
OUTER:      jmp   OUTERLOOP                 
QUIT: 
    }

    return;
}

void  SimpleCallAndRetnTest(void)
{
    _asm{
        mov   ebx , 0x50000000
        mov   dx  , 0x5678
        mov   ecx , 4
HTOASCS1:rol   dx  , 1
         rol   dx  , 1
         rol   dx  , 1
         rol   dx  , 1
         mov   al  , dl
         call  HTOASC
         mov   [ebx],al
         inc   ebx
         loop  HTOASCS1
         jmp  QUIT

HTOASC:  and   al  , 0xf
         cmp   al  , 9
         jbe   HTOASC1
         add   al  , 37h
HTOASC2: ret
HTOASC1: add   al  , 0x30
         jmp  HTOASC2
QUIT:
    }
}


void RecurentFunction(void)
{
    _asm{
        //N!汇编函数， eax 存储 n 的值
        mov    eax   ,  10
        mov    bl    ,  0
        mov    ecx   ,  eax
        cmp    ecx   ,  0
        jl     short  FACT1
        call   _FACT
        cmp    bl    ,   1
        jnz    short  FACT2
FACT1:  mov    eax   ,   -1
FACT2:  jmp    QUIT


_FACT:  cmp    ecx   ,   0
        jz     SHORT   _FACT2
        push   ecx
        dec    ecx
        call   _FACT
        pop    ecx
        mul    ecx
        jno    SHORT _FACT1
        mov    bl   ,  1
_FACT1: ret
_FACT2: mov    eax  ,  1
        ret
QUIT:
    }
}

void  ADC_TEST()
{
    _asm{
        xor    eax , eax
        xor    edx , edx 
        xor    ecx , ecx
        stc
        mov    al , 0x7f
        mov    dl , 0x36
        adc    dl , al
        stc
        mov    al , 0xff
        mov    dl , 0x80
        adc    dl , al
        stc
        mov    al , 0x7e
        mov    dl , 0x1
        adc    dl , al

        mov    ebx , 0x50000000
        mov    dword ptr[ebx+22h] , 0x12345678
        mov    dword ptr[ebx+2222h] , 0x12345678  //0x004812CA
        adc    byte ptr [ebx],al         
        adc    word ptr [ebx+4],ax      
        adc    dword ptr [ebx+8],eax    
        adc    dl,byte ptr [ebx]        
        adc    dl,byte ptr [ebx]        
        adc    dl,byte ptr [ebx+22h]    
        adc    dl,byte ptr [ebx+2222h]        
        adc    cx,word ptr [ebx]        
        adc    cx,word ptr [ebx+22h]        
        adc    ecx,dword ptr [ebx]      
        adc    ecx,dword ptr [ebx+22h]  
        adc    ecx,dword ptr [ebx+2222h]
        adc    al,8h             
        adc    eax,8765h

        //80
        adc    bl,22h          
        adc    byte ptr [ebx],22h     
        //81
        adc    dx,2222h           
        adc    word ptr [ebx],2222h   
        adc    edx,2222h          
        adc    dword ptr [ebx],2222h  
        adc    cx,22h         
        adc    ecx,22h  

//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000000,0xa4);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000004,0x12);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000008,0x35);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x5000000c,0x1);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000010,0x18);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000014,0x99);
//         vm_err = VM_MM_WriteOneDWord(&pEmulator->Memory.DataSegment, 0x50000018,0x6);
//         VS 2005 , TEST 
//         int  temp[10000]={0xa4,0x12,0x35,0x1,0x18,0x99,0x6};
// 
//         _asm{
//         mov    ebx , // temp address
//         xor    eax , eax
//         xor    edx , edx 
//         xor    ecx , ecx
//         stc
//         mov    al , 0x7f
//         mov    dl , 0x36
//         adc    dl , al     //EDX = 000000B6  OV = 1 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 0 
//         stc
//         mov    al , 0xff   
//         mov    dl , 0x80
//         adc    dl , al     //EDX = 00000080  OV = 0 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 1
//         stc
//         mov    al , 0x7e
//         mov    dl , 0x1
//         adc    dl , al     //EDX = 00000080  OV = 1 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 0
// 
//         mov    dword ptr[ebx+22h] , 0x12345678       
//         mov    dword ptr[ebx+2222h] , 0x12345678 //0x00128546
//         adc    byte ptr [ebx],al     //22 00 00 00           //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 1           
//         adc    word ptr [ebx+4],ax   //91 00 00 00           //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0  
//         adc    dword ptr [ebx+8],eax //b3 00 00 00           //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0   
//         adc    dl,byte ptr [ebx]     //EDX = 000000A2        //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0   
//         adc    dl,byte ptr [ebx]     //EDX = 000000C4        //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0   
//         adc    dl,byte ptr [ebx+22h] //EDX = 0000003C        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 1    
//         adc    dl,byte ptr [ebx+2222h]   //EDX = 000000B5    //OV = 1 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 0       
//         adc    cx,word ptr [ebx]     //ECX = 00000022        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0      
//         adc    cx,word ptr [ebx+22h] //ECX = 0000569A        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0        
//         adc    ecx,dword ptr [ebx]   //ECX = 000056BC        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0    
//         adc    ecx,dword ptr [ebx+22h]  //ECX = 1234AD34     //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0  
//         adc    ecx,dword ptr [ebx+2222h]//ECX = 246903AC     //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         adc    al,8h       //EAX = 00000086          //OV = 1 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 0           
//         adc    eax,8765h   //EAX = 000087EB          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0
// 
//         //80
//         adc    bl,22h   //EBX = 50000346         //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0        
//         adc    byte ptr [ebx],22h   //9a 56 34 12        //OV = 1 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 0 
//         //81
//         adc    dx,2222h       //EDX = 000022D7           //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0        
//         adc    word ptr [ebx],2222h   //bc 78 34 12          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0 
//         adc    edx,2222h          //EDX = 000044F9       //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0         
//         adc    dword ptr [ebx],2222h  //de 9a 34 12          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         adc    cx,22h         //ECX = 246903CE       //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0          
//         adc    ecx,22h        //ECX = 246903F0       //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0
//         }


    }
}

void ADD_TEST(void)
{
    _asm{
       add    byte ptr [ebx],dl      // ebx = 0x5000 0000 , DataSegment     

        //01 --  05
        add    word ptr[ebx+4],dx          
        add    dword ptr[ebx+8],edx        
        add    al,dl           
        add    dl,byte ptr [ebx]           
        add    edx,edx         
        add    edx,dword ptr [ebx+8]       
        add    al,44h          
        add    ax,44h          
        add    eax,4444444h        

        //80、81、83
        add    bl,4h           
        add    byte ptr [ebx],28h          
        add    dx,4444h        
        add    word ptr [ebx+4],4571h      
        add    eax,25318961h           
        add    dword ptr [ebx+8],25318961h 
        add    dx,93h          
        add    word ptr [ebx+4],84h        
        add    ebx,14h         
        add    dword ptr [ebx+8],41h  
    }
//     int  temp[10000]={0xa4,0x12,0x35,0x1,0x18,0x99,0x6};
// 
//     _asm{
//         xor    eax , eax
//         mov    ebx , 0x50000324  // temp地址
//         mov    edx , 0x62e147ad
// 
//         add    byte ptr [ebx],dl        //51 00 00 00     //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 1
// 
//         //01 --  05
//         add    word ptr[ebx+4],dx           //bf 47 00 00     //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0  
//         add    dword ptr[ebx+8],edx         //e2 47 e1 62     //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0  
//         add    al,dl        //EAX = 000000AD  //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0 
//         add    dl,byte ptr [ebx]        //EDX = 62E147FE  //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0 
//         add    edx,edx          //EDX = C5C28FFC  //OV = 1 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 0 
//         add    edx,dword ptr [ebx+8]        //EDX = 28A3D7DE  //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 1 
//         add    al,44h           //EAX = 000000F1  //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 0
//         add    ax,44h           //EAX = 00000135  //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         add    eax,4444444h         //EAX = 04444579  //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
// 
//         //80、81、83
//         add    bl,4h        //EBX = 50000328   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0         
//         add    byte ptr [ebx],28h           //e7 47 00 00      //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 0     
//         add    dx,4444h         //EDX = 28A31C22   //OV = 0 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 1
//         add    word ptr [ebx+4],4571h       //53 8d e1 62      //OV = 1 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 0   
//         add    eax,25318961h        //EAX = 2975CEDA   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0           
//         add    dword ptr [ebx+8],25318961h  //62 89 31 25      //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0    
//         add    dx,93h           //EDX = 28A31CB5   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0           
//         add    word ptr [ebx+4],84h         //d7 8d e1 62      //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 0   
//         add    ebx,14h          //EBX = 5000033C   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0           
//         add    dword ptr [ebx+8],41h        //00 00 00 41      //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0  
//     }

}

void  AND_TEST(void)
{
    _asm{
        mov    ebx , 0x50000000

        mov    eax , 0x62e147ad
        mov    ecx , 0x62e147ad
        mov    edx , 0x62e147ad

        mov    [ebx+22h] , 0x12345678
        mov    [ebx+2222h] , 0x12345678

        //AND
        and    byte ptr [ebx],al         
        and    word ptr [ebx+4],ax       
        and    dword ptr [ebx+8],eax     
        and    dl,byte ptr [ebx]         
        and    dl,byte ptr [ebx+22h]     
        and    cx,word ptr [ebx+8]       
        and    cx,word ptr [ebx]         
        and    cx,word ptr [ebx+22h]     
        and    ecx,dword ptr [ebx+8]     
        and    al,42h        
        and    eax,0x62e147ad        
        and    dl,0xe2           
        and    byte ptr [ebx],22h        
        and    dx,0x62e147ad         
        and    word ptr [ebx+4],0x62e147ad
        and    edx,0x62e147ad         
        and    dword ptr [ebx+8],0x62e147ad
        and    ecx,0x62e147ad   
        and    dword ptr [ebx],0x01   
    }


//     int  temp[10000]={0xa4,0x12,0x35,0x1,0x18,0x99,0x6};
// 
//     _asm{
//         mov    eax , 0x62e147ad
//         mov    ecx , 0x62e147ad
//         mov    ebx , 0x50000324
//         mov    edx , 0x62e147ad
// 
//         mov    [ebx+22h] , 0x12345678
//         mov    [ebx+2222h] , 0x12345678
// 
//         //AND
//         and    byte ptr [ebx],al         //a4 00 00 00      //PL = 1 ZR = 0 AC = 0 PE = 0
//         and    word ptr [ebx+4],ax       //00 00 00 00      //PL = 0 ZR = 1 AC = 0 PE = 1 
//         and    dword ptr [ebx+8],eax     //25 00 00 00      //PL = 0 ZR = 0 AC = 0 PE = 0 
//         and    dl,byte ptr [ebx]         //EDX = 62E147A4   //PL = 1 ZR = 0 AC = 0 PE = 0           
//         and    dl,byte ptr [ebx+22h]     //EDX = 62E14720   //PL = 0 ZR = 0 AC = 0 PE = 0 
//         and    cx,word ptr [ebx+8]       //ECX = 62E10025   //PL = 0 ZR = 0 AC = 0 PE = 0
//         and    cx,word ptr [ebx]         //CX = 62E10024    //PL = 0 ZR = 0 AC = 0 PE = 1  
//         and    cx,word ptr [ebx+22h]     //ECX = 62E10020   //PL = 0 ZR = 0 AC = 0 PE = 0 
//         and    ecx,dword ptr [ebx+8]     //ECX = 00000020   //PL = 0 ZR = 0 AC = 0 PE = 0
//         and    al,42h        //EAX = 62E14700   //PL = 0 ZR = 1 AC = 0 PE = 1  
//         and    eax,0x62e147ad        //EAX = 62E14700   //PL = 0 ZR = 0 AC = 0 PE = 1      
//         and    dl,0xe2           //EDX = 62E14720   //PL = 0 ZR = 0 AC = 0 PE = 0 
//         and    byte ptr [ebx],22h        //20 00 00 00      //PL = 0 ZR = 0 AC = 0 PE = 0  
//         and    dx,0x47ad         //EDX = 62E14720   //PL = 0 ZR = 0 AC = 0 PE = 0       
//         and    word ptr [ebx+4],0x47ad   //00 00 00 00      //PL = 0 ZR = 1 AC = 0 PE = 1  
//         and    edx,0x62e147ad        //EDX = 62E14720   //PL = 0 ZR = 0 AC = 0 PE = 0      
//         and    dword ptr [ebx+8],0x62e147ad         //PL = 0 ZR = 0 AC = 0 PE = 0         
//         and    ecx,0x62e147ad               //PL = 0 ZR = 0 AC = 0 PE = 0  
//         and    dword ptr [ebx],0x01      //00 00 00 00      //PL = 0 ZR = 1 AC = 0 PE = 1
//     }
}


void CMP_TEST(void)
{
    _asm{
        mov    ebx , 0x50000000

        mov    eax , 0x62e147ad
        mov    ecx , 0x62e147ad
        mov    edx , 0x62e147ad

        mov    dword ptr[ebx+22h] , 0x12345678
        mov    dword ptr[ebx+2222h] , 0x12345678

        cmp    byte ptr [ebx],al        
        cmp    word ptr [ebx+4],ax      
        cmp    dword ptr [ebx+8],eax    
        cmp    dl,byte ptr [ebx]        
        cmp    dl,byte ptr [ebx+22h]    
        cmp    dl,byte ptr [ebx+2222h]  
        cmp    cx,word ptr [ebx+4]      
        cmp    cx,word ptr [ebx]        
        cmp    cx,word ptr [ebx+22h]    
        cmp    ecx,dword ptr [ebx+8]    
        cmp    ecx,dword ptr [ebx]      
        cmp    ecx,dword ptr [ebx+22h]  
        cmp    al,7fh           
        cmp    eax,0f0e1f3e3h           
        cmp    dl,0ffh          
        cmp    byte ptr [ebx],0ffh      
        cmp    dx,7ff3h         
        cmp    word ptr [ebx+4],2e14h   
        cmp    edx,0f2e2h           
        cmp    dword ptr [ebx+8],2e14h  
        cmp    cx,0xad          
        cmp    ecx,0x2d   
    }

//     int  temp[10000]={0xa4,0x12,0x35,0x1,0x18,0x99,0x6};
// 
//     _asm{
//         //CMP
//         mov    eax , 0x62e147ad
//         mov    ecx , 0x62e147ad
//         mov    ebx , 0x50000324
//         mov    edx , 0x62e147ad
// 
//         mov    dword ptr[ebx+22h] , 0x12345678
//         mov    dword ptr[ebx+2222h] , 0x12345678
// 
//         cmp    byte ptr [ebx],al         //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 1 
//         cmp    word ptr [ebx+4],ax       //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 1  
//         cmp    dword ptr [ebx+8],eax     //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 1  
//         cmp    dl,byte ptr [ebx]         //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         cmp    dl,byte ptr [ebx+22h]     //OV = 1 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         cmp    dl,byte ptr [ebx+2222h]   //OV = 1 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0
//         cmp    cx,word ptr [ebx+4]       //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0 
//         cmp    cx,word ptr [ebx]         //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0   
//         cmp    cx,word ptr [ebx+22h]     //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 1
//         cmp    ecx,dword ptr [ebx+8]     //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         cmp    ecx,dword ptr [ebx]       //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0   
//         cmp    ecx,dword ptr [ebx+22h]   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0 
//         cmp    al,7fh        //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0 
//         cmp    eax,0f0e1f3e3h        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 1  
//         cmp    dl,0ffh           //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 1    
//         cmp    byte ptr [ebx],0ffh       //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 1 
//         cmp    dx,7ff3h          //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 1 
//         cmp    word ptr [ebx+4],2e14h    //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 0 CY = 1  
//         cmp    edx,0f2e2h        //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0   
//         cmp    dword ptr [ebx+8],2e14h   //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 1
//         cmp    cx,0xad           //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 1 CY = 0         
//         cmp    ecx,0x2d          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0 
//     }

}

void TEST()
{
    _asm{
        mov    eax , 0x80000001
        mov    ebx , 0x80000001
        mov    ecx , 0x80000001
        mov    edx , 0x80000001
        mov    esp , 0x7fffffff
        mov    ebp , 0x7fffffff
        mov    esi , 0x00000000
        mov    edi , 0x00000000

        //DEC
        dec    ax           //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0          
        dec    eax          //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0         
        dec    cx           //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0         
        dec    ecx          //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0        
        dec    dx           //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0        
        dec    edx          //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0           
        dec    bx           //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0         
        dec    ebx          //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 1 CY = 0          
        dec    sp           //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0       
        dec    esp          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0        
        dec    bp           //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0         
        dec    ebp          //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0  
        dec    esi          //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 0  
        dec    si           //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0        
        dec    edi          //OV = 0 PL = 1 ZR = 0 AC = 1 PE = 1 CY = 0   
        dec    di           //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 0 CY = 0          


        mov    ax , 0x8001
        mov    bx , 0x8001
        mov    cx , 0x8001
        mov    dx , 0x8001
        dec    al           //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0      
        dec    cl           // FE C9   //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0      
        dec    dl           // FE CA   //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0        
        dec    bl           // FE CB   //OV = 0 PL = 0 ZR = 1 AC = 0 PE = 1 CY = 0     
        dec    ah           // FE CC   //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0     
        dec    bh           // FE CF   //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0     
        dec    dh           // FE CE   //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0     
        dec    ch           // FE CD   //OV = 1 PL = 0 ZR = 0 AC = 1 PE = 0 CY = 0

        mov    ebx ,  0x50000000
        dec    byte ptr[ebx]   //OV = 0 PL = 1 ZR = 0 AC = 0 PE = 1 CY = 0    
        dec    word ptr[ebx]   //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0 
        dec    dword ptr[ebx]  //OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0      
    }
}

void DIV_TEST(void)
{
    _asm{
        //DIV
        xor    ebx , ebx 
        xor    ecx , ecx 
        xor    edx , edx 

        mov    ax , 0x1511
        mov    dx , 0x2334
        mov    cx , 0x4724 
        div    cx        //EAX = 00001511 EBX = 00000000 ECX = 00004724 EDX = 00002334 

        mov    ax , 0x1511
        mov    dx , 0x24
        mov    cx  , 0x41 
        div    cx        //EAX = 00008E1B EBX = 00000000 ECX = 00000041 EDX = 00000036

        mov    eax , 0x41203311
        mov    edx , 0x51234352
        mov    ebx , 0x74114441
        div    ebx        //EAX = B2F563FF EBX = 74114441 ECX = 00000041 EDX = 72531352

        mov    eax , 0x23435df1
        mov    edx , 0x21234352
        mov    ecx , 0x741fea41
        div    ecx        //EAX = 490D95B0 EBX = 74114441 ECX = 741FEA41 EDX = 4BAD7C41

        mov    ax , 0x1251
        div    al         //EAX = 490D4839 

        mov    ax , 0x1251
        mov    bl , 0x61
        div    bl         //EAX = 490D2130 EBX = 74114461 ECX = 741FEA41 EDX = 4BAD7C41 ESI = 11710003 EDI = 0012FF68 

        mov    ax , 0x1251 
        mov    bh , 0x32
        div    bh         //EAX = 490D275D EBX = 74113261 ECX = 741FEA41 EDX = 4BAD7C41

        mov    ax , 0x1251 
        mov    cl , 0x54
        div    cl        //EAX = 490D4537 EBX = 74113261 ECX = 741FEA54 EDX = 4BAD7C41
        mov    ax , 0x1251 
        mov    ch , 0x7d
        div    ch        //EAX = 490D4025 EBX = 74113261 ECX = 741F7D54 EDX = 4BAD7C41

        mov    ax , 0x1251 
        mov    dh , 0x8d
        div    dh        //EAX = 490D2421 EBX = 74113261 ECX = 741F7D54 EDX = 4BAD8D41
        mov    ax , 0x1251 
        mov    dl , 0x38
        div    dl        //EAX = 490D2953 EBX = 74113261 ECX = 741F7D54 EDX = 4BAD8D38


        mov    ebx, 0x50000000

        mov    ax , 0x1011
        div    byte ptr[ebx]   //EAX = 490D0D19
        mov    ax , 0x5011
        mov    dx , 0x0
        div    word ptr[ebx]   //EAX = 490D007C  ECX = 741F7D54 EDX = 4BAD00A1 
        mov    edx , 0x0
        div    dword ptr[ebx]  //EAX = 007207CE  ECX = 741F7D54 EDX = 00000084
    }
}

void IDIV_TEST(void)
{
    _asm{
        xor    eax , eax 
        xor    ebx , ebx 
        xor    ecx , ecx 
        xor    edx , edx 

        mov    ax , 0x1511
        mov    dx , 0x2334
        mov    cx , 0x4724 
        idiv    cx        //idiv EAX = 00007EAE EBX = 00000000 ECX = 00004724 EDX = 00000299

        mov    ax , 0x1511
        mov    dx , 0x24
        mov    cx  , 0xe410 
        idiv   cx        //EAX = 0000FEB6 EBX = 00000000 ECX = 0000E410 EDX = 000011B1

        mov    eax , 0x41203311
        mov    edx , 0x01234352
        mov    ebx , 0xabeebbbf
        idiv    ebx        //EAX = FC890DB8 EBX = ABEEBBBF ECX = 0000E410 EDX = 10C98EC9
        //mov    ebx , 0x54114441  EAX = 0376F248 EBX = 54114441 ECX = 00000141 EDX = 10C98EC9 

        mov    eax , 0x23435df1
        mov    edx , 0x21234352
        mov    ecx , 0x741fea41
        idiv    ecx        //EAX = 490D95B0 EBX = 54114441 ECX = 741FEA41 EDX = 4BAD7C41

        mov    ax , 0x1251
        idiv    al         //EAX = 490D4839 

        mov    ax , 0x1251
        mov    bl , 0x61
        idiv    bl         //EAX = 490D2130 EBX = 54114461 ECX = 741FEA41 EDX = 4BAD7C41  

        mov    ax , 0x1251 
        mov    bh , 0x32
        idiv    bh         //EAX = 490D275D EBX = 54113261 ECX = 741FEA41 EDX = 4BAD7C41

        mov    ax , 0x1251 
        mov    cl , 0x54
        idiv    cl        //EAX = 490D4537 EBX = 54113261 ECX = 741FEA54 EDX = 4BAD7C41
        mov    ax , 0x1251 
        mov    ch , 0x7d
        idiv    ch        //EAX = 490D4025 EBX = 54113261 ECX = 741F7D54 EDX = 4BAD7C41

        xor   eax , eax 
        xor   ebx , ebx 
        xor   edx , edx 
        xor   ecx , ecx
        mov    ax , 0x1251 // 仿真器出错了
        mov    dh , 0x8d
        idiv    dh        //EAX = 490D59D8 EBX = 54113261 ECX = 741F7D54 EDX = 4BAD8D41
        mov    ax , 0x1251 
        mov    dl , 0x38
        idiv    dl        //EAX = 490D2953 EBX = 74113261 ECX = 741F7D54 EDX = 4BAD8D38

        mov    ebx, 0x50000000

        mov    ax , 0x1011
        idiv    byte ptr[ebx]   //EAX = 490D41D4 EBX = 50000324 ECX = 741F7D54 EDX = 4BAD8D38
        mov    ax , 0x5011
        mov    dx , 0x0
        idiv    word ptr[ebx]   //EAX = 490D007C EBX = 50000324 ECX = 741F7D54 EDX = 4BAD00A1
        mov    edx , 0x0
        idiv    dword ptr[ebx]  //EAX = 007207CE EBX = 50000324 ECX = 741F7D54 EDX = 00000084
    }
}

void IMUL_TEST(void)
{
    _asm{
        mov    eax , 0xf7ad             // EAX:0000F7AD    EBX:0006E147    ECX:0000075D    EDX:000014AD         
        mov    ecx , 0x75d              // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mov    edx , 0x14ad             // EIP:4000002B    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
        mov    ebx , 0x6e147            //     mul      al,eax
        mov    esi , 0x217a             // EAX:00004AE9    EBX:0006E147    ECX:0000075D    EDX:0000EF9F
        mov    edi , 0x2e17             // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mov    esp , 0x647              // EIP:4000002D    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mov    ebp , 0x5f1              //     mul      al,eax
                    // EAX:15EB8811    EBX:0006E147    ECX:0000075D    EDX:00000000
        mul        ax               // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul        eax              // EIP:4000002F    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
        mul        ebx              //     mul      al,ebx
                    // EAX:474FADB7    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    al                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    ah                   // EIP:40000031    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    bh                   //     mul      al,al
        mul    bl                   // EAX:474F82D1    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    dh                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    dl                   // EIP:40000033    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    ch                   //     mul      al,ah
        mul    cl                   // EAX:474F6A22    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    ax                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    bx                   // EIP:40000035    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    dx                   //     mul      al,bh
        mul    cx                   // EAX:474F1DE2    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    edx                  // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    ecx                  // EIP:40000037    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    dx                   //     mul      al,bl
        mul    dx                   // EAX:474F3EAE    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    sp                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
                    // EIP:40000039    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
                    //     mul      al,dh
        mul    di                   // EAX:474F65F4    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    eax                  // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    edi                  // EIP:4000003B    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    ax                   //     mul      al,dl
        mul    bx                   // EAX:474FC54C    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    dx                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    edi                  // EIP:4000003D    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    dx                   //     mul      al,ch
        mul    sp                   // EAX:474F0214    EBX:0006E147    ECX:0000075D    EDX:000096CF
                    // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    si                   // EIP:4000003F    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    di                   //     mul      al,cl
        mul    di                   // EAX:474F0744    EBX:0006E147    ECX:0000075D    EDX:000096CF
        mul    edi                  // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    ax                   // EIP:40000042    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    bx                   //     mul      al,eax
        mul    si                   // EAX:474FCA10    EBX:0006E147    ECX:0000075D    EDX:00000034
        mul    di                   // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mul    ebp                  // EIP:40000045    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    esi                  //     mul      al,ebx
                    // EAX:474F1A70    EBX:0006E147    ECX:0000075D    EDX:0000B1D0
        mov    ebx , 0x50000000             // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mov    dword ptr[ebx+22h] , 0x54768132          // EIP:40000048    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mov    dword ptr[ebx+2222h] , 0x32145786        //     mul      al,edx
                    // EAX:474FEB00    EBX:0006E147    ECX:0000075D    EDX:0000125C
        mul    byte ptr[ebx]            // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
        mov    edx , dword ptr[ebx]         // EIP:4000004B    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
        mul    dword ptr[ebx]               //     mul      al,ecx
    }                   // EAX:474F5F00    EBX:0006E147    ECX:0000075D    EDX:000006C2
//     _asm{                // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         mov    eax , 0xf7ad              // EIP:4000004D    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         mov    ecx , 0x75d           //     mul      al,edx
//         mov    edx , 0x14ad          // EAX:E65FFE00    EBX:0006E147    ECX:0000075D    EDX:000001E1
//         mov    ebx , 0x6e147         // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         mov    esi , 0x217a          // EIP:4000004F    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         mov    edi , 0x2e17          //     mul      al,ecx
//         mov    esp , 0x647           // EAX:50D14600    EBX:0006E147    ECX:0000075D    EDX:000006A0
//         mov    ebp , 0x5f1           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//                      // EIP:40000052    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//                      //     mul      al,edx
//         imul        ax,ax,3          // EAX:50D1C000    EBX:0006E147    ECX:0000075D    EDX:000001CF
//         imul        eax,ebx,3        // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul        ebx, ecx,4           // EIP:40000055    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//                      //     mul      al,edx
//         imul    al               // EAX:50D14000    EBX:0006E147    ECX:0000075D    EDX:0000015B
//         imul    ah               // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    bh               // EIP:40000058    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    bl               //     mul      al,esp
//         imul    dh               // EAX:50D1C000    EBX:0006E147    ECX:0000075D    EDX:00000191
//         imul    dl               // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    ch               // EIP:4000005B    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    cl               //     mul      al,edi
//         imul    ax               // EAX:50D14000    EBX:0006E147    ECX:0000075D    EDX:00002291
//         imul    bx               // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    dx               // EIP:4000005D    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    cx               //     mul      al,eax
//         imul    eax              // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:19837309
//         imul    ebx              // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    edx              // EIP:4000005F    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    ecx              //     mul      al,edi
//                      // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:000019EC
//         imul    ax,ax,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    ax,bx,0x3            // EIP:40000062    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    ax,dx,0x3            //     mul      al,eax
//         imul    ax,cx,0x3            // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    ax,sp,0x3            // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    ax,bp,0x3            // EIP:40000065    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    ax,si,0xe3           //     mul      al,ebx
//         imul    ax,di,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//                      // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    bx,ax,0xe3           // EIP:40000068    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    bx,bx,0xe3           //     mul      al,edx
//         imul    bx,dx,0x3            // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    bx,cx,0x3            // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    bx,sp,0x3            // EIP:4000006A    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    bx,bp,0xe3           //     mul      al,edi
//         imul    bx,si,0xe3           // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00002B35
//         imul    bx,di,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//                      // EIP:4000006D    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    cx,ax,0xe3           //     mul      al,edx
//         imul    cx,bx,0xe3           // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    cx,dx,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    cx,cx,0xe3           // EIP:40000070    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    cx,sp,0xe3           //     mul      al,esp
//         imul    cx,bp,0xe3           // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    cx,si,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    cx,di,0xe3           // EIP:40000073    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//                      //     mul      al,esi
//         imul    dx,ax,0xe3           // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    dx,bx,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    dx,cx,0xe3           // EIP:40000076    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    dx,dx,0xe3           //     mul      al,edi
//         imul    dx,sp,0xe3           // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    dx,bp,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    dx,si,0xe3           // EIP:40000079    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    dx,di,0xe3           //     mul      al,edi
//                      // EAX:90000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    sp,ax,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    sp,bx,0xe3           // EIP:4000007B    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    sp,dx,0xe3           //     mul      al,edi
//         imul    sp,cx,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:000019EC
//         imul    sp,sp,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    sp,bp,0xe3           // EIP:4000007E    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    sp,si,0xe3           //     mul      al,eax
//         imul    sp,di,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//                      // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    bp,ax,0xe3           // EIP:40000081    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    bp,bx,0xe3           //     mul      al,ebx
//         imul    bp,cx,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    bp,dx,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    bp,sp,0xe3           // EIP:40000084    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    bp,bp,0xe3           //     mul      al,esi
//         imul    bp,di,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    bp,si,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//                      // EIP:40000087    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    si,ax,0xe3           //     mul      al,edi
//         imul    si,bx,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000000
//         imul    si,dx,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    si,cx,0xe3           // EIP:40000089    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    si,sp,0xe3           //     mul      al,ebp
//         imul    si,bp,0xe3           // EAX:F0000000    EBX:0006E147    ECX:0000075D    EDX:00000591
//         imul    si,si,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    si,di,0x1            // EIP:4000008B    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//                      //     mul      al,esi
//         imul    di,ax,0xe3           // EAX:60000000    EBX:0006E147    ECX:0000075D    EDX:00001F62
//         imul    di,bx,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    di,cx,0xe3           // EIP:40000090    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    di,dx,0xe3           //     mov      ebx,0x50000000
//         imul    di,sp,0xe3           // EAX:60000000    EBX:50000000    ECX:0000075D    EDX:00001F62
//         imul    di,bp,0xe3           // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    di,si,0xe3           // EIP:40000097    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    di,di,0xe3           //     mov      dword ptr [ebx+0x22],0x54768132
//                      // EAX:60000000    EBX:50000000    ECX:0000075D    EDX:00001F62
//         imul    eax,eax,0xe3         // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    eax,ebx,0xe3         // EIP:400000A1    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    eax,edx,0xe3         //     mov      dword ptr [ebx+0x2222],0x32145786
//         imul    eax,ecx,0xe3         // EAX:60000000    EBX:50000000    ECX:0000075D    EDX:00001F62
//         imul    eax,esp,0xe3         // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    eax,ebp,0xe3         // EIP:400000A3    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    eax,esi,0xe3         //     mul      al,byte ptr [ebx[ebx]
//         imul    eax,edi,0xe3         // EAX:60000000    EBX:50000000    ECX:0000075D    EDX:00001F62
//                      // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    ebx,eax,0xe3         // EIP:400000A5    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    ebx,ebx,0xe3         //     mov      edx,dword ptr [ebx[ebx]
//         imul    ebx,edx,0xe3         // EAX:60000000    EBX:50000000    ECX:0000075D    EDX:000000A4
//         imul    ebx,ecx,0xe3         // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//         imul    ebx,esp,0xe3         // EIP:400000A7    OV = 0 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 0
//         imul    ebx,ebp,0xe3         //     mul      al,dword ptr [ebx[ebx]
//         imul    ebx,esi,0xe3         // EAX:80000000    EBX:50000000    ECX:0000075D    EDX:0000003D
//         imul    ebx,edi,0xe3         // ESI:0000217A    EDI:00002E17    EBP:000005F1    ESP:00000647
//                      // EIP:400000AB    OV = 1 PL = 0 ZR = 0 AC = 0 PE = 0 CY = 1
//         imul    ecx,eax,0xe3         //     mov      eax,0x11
//         imul    ecx,ebx,0xe3        
//         imul    ecx,edx,0xe3        
//         imul    ecx,ecx,0xe3        
//         imul    ecx,esp,0xe3        
//         imul    ecx,ebp,0xe3        
//         imul    ecx,esi,0xe3        
//         imul    ecx,edi,0xe3        
//                     
//         imul    edx,eax,0xe3        
//         imul    edx,ebx,0xe3        
//         imul    edx,ecx,0xe3        
//         imul    edx,edx,0xe3        
//         imul    edx,esp,0xe3        
//         imul    edx,ebp,0xe3        
//         imul    edx,esi,0xe3        
//         imul    edx,edi,0xe3        
//                     
//         imul    esp,eax,0xe3        
//         imul    esp,ebx,0xe3        
//         imul    esp,edx,0xe3        
//         imul    esp,ecx,0xe3        
//         imul    esp,esp,0xe3        
//         imul    esp,ebp,0xe3        
//         imul    esp,esi,0xe3        
//         imul    esp,edi,0xe3        
//                     
//         imul    ebp,eax,0xe3        
//         imul    ebp,ebx,0xe3        
//         imul    ebp,ecx,0xe3        
//         imul    ebp,edx,0xe3        
//         imul    ebp,esp,0xe3        
//         imul    ebp,ebp,0xe3        
//         imul    ebp,edi,0xe3        
//         imul    ebp,esi,0xe3          
// 
//         imul    esi,eax,0xe3          
//         imul    esi,ebx,0xe3          
//         imul    esi,edx,0xe3          
//         imul    esi,ecx,0xe3          
//         imul    esi,esp,0xe3          
//         imul    esi,ebp,0xe3          
//         imul    esi,esi,0xe3          
//         imul    esi,edi,0xe3          
// 
//         imul    edi,eax,0xe3          
//         imul    edi,ebx,0xe3          
//         imul    edi,ecx,0xe3          
//         imul    edi,edx,0xe3          
//         imul    edi,esp,0xe3          
//         imul    edi,ebp,0xe3          
//         imul    edi,esi,0xe3          
//         imul    edi,edi,0xe3          
// 
//         imul    ax,0xe3           
//         imul    bx,0xe3           
//         imul    dx,0xe3           
//         imul    cx,0xe3           
//         imul    sp,0xe3           
//         imul    bp,0xe3           
//         imul    si,0xe3           
//         imul    di,0xe3           
// 
//         imul    eax,0xe3          
//         imul    ebx,0xe3          
//         imul    ecx,0xe3          
//         imul    edx,0xe3          
//         imul    esp,0xe3          
//         imul    ebp,0xe3          
//         imul    esi,0xe3          
//         imul    edi,0xe3          
// 
//         imul    ax,ax,0x4f7d          
//         imul    ax,bx,0x4f7d          
//         imul    ax,dx,0x4f7d          
//         imul    ax,cx,0x4f7d          
//         imul    ax,sp,0x4f7d          
//         imul    ax,bp,0x4f7d          
//         imul    ax,si,0x4f7d          
//         imul    ax,di,0x4f7d          
// 
//         imul    bx,ax,0x4f7d          
//         imul    bx,bx,0x4f7d          
//         imul    bx,dx,0x4f7d          
//         imul    bx,cx,0x4f7d          
//         imul    bx,sp,0x4f7d          
//         imul    bx,bp,0x4f7d          
//         imul    bx,si,0x4f7d          
//         imul    bx,di,0x4f7d          
// 
//         imul    cx,ax,0x4f7d          
//         imul    cx,bx,0x4f7d          
//         imul    cx,dx,0x4f7d          
//         imul    cx,cx,0x4f7d          
//         imul    cx,sp,0x4f7d          
//         imul    cx,bp,0x4f7d          
//         imul    cx,si,0x4f7d          
//         imul    cx,di,0x4f7d          
// 
//         imul    dx,ax,0x4f7d          
//         imul    dx,bx,0x4f7d          
//         imul    dx,cx,0x4f7d          
//         imul    dx,dx,0x4f7d          
//         imul    dx,sp,0x4f7d          
//         imul    dx,bp,0x4f7d          
//         imul    dx,si,0x4f7d          
//         imul    dx,di,0x4f7d          
// 
//         imul    sp,ax,0x4f7d          
//         imul    sp,bx,0x4f7d          
//         imul    sp,dx,0x4f7d          
//         imul    sp,cx,0x4f7d          
//         imul    sp,sp,0x4f7d          
//         imul    sp,bp,0x4f7d          
//         imul    sp,si,0x4f7d          
//         imul    sp,di,0x4f7d          
// 
//         imul    bp,ax,0x4f7d          
//         imul    bp,bx,0x4f7d          
//         imul    bp,cx,0x4f7d          
//         imul    bp,dx,0x4f7d          
//         imul    bp,sp,0x4f7d          
//         imul    bp,bp,0x4f7d          
//         imul    bp,di,0x4f7d          
//         imul    bp,si,0x4f7d          
// 
//         imul    si,ax,0x4f7d          
//         imul    si,bx,0x4f7d          
//         imul    si,dx,0x4f7d          
//         imul    si,cx,0x4f7d          
//         imul    si,sp,0x4f7d          
//         imul    si,bp,0x4f7d          
//         imul    si,si,0x4f7d          
//         imul    si,di,0x4f7d          
// 
//         imul    di,ax,0x47d          
//         imul    di,bx,0x47d          
//         imul    di,cx,0x47d          
//         imul    di,dx,0x47d          
//         imul    di,sp,0x47d          
//         imul    di,bp,0x47d          
//         imul    di,si,0x47d          
//         imul    di,di,0x47d          
// 
//         imul    eax,eax,0x1a2b8f9c    
//         imul    eax,ebx,0x1a2b8f9c    
//         imul    eax,edx,0x1a2b8f9c    
//         imul    eax,ecx,0x1a2b8f9c    
//         imul    eax,esp,0x1a2b8f9c    
//         imul    eax,ebp,0x1a2b8f9c    
//         imul    eax,esi,0x1a2b8f9c    
//         imul    eax,edi,0x1a2b8f9c    
// 
//         imul    ebx,eax,0x1a2b8f9c    
//         imul    ebx,ebx,0x1a2b8f9c    
//         imul    ebx,edx,0x1a2b8f9c    
//         imul    ebx,ecx,0x1a2b8f9c    
//         imul    ebx,esp,0x1a2b8f9c    
//         imul    ebx,ebp,0x1a2b8f9c    
//         imul    ebx,esi,0x1a2b8f9c    
//         imul    ebx,edi,0x1a2b8f9c    
// 
//         imul    ecx,eax,0x1a2b8f9c    
//         imul    ecx,ebx,0x1a2b8f9c    
//         imul    ecx,edx,0x1a2b8f9c    
//         imul    ecx,ecx,0x1a2b8f9c    
//         imul    ecx,esp,0x1a2b8f9c    
//         imul    ecx,ebp,0x1a2b8f9c    
//         imul    ecx,esi,0x1a2b8f9c    
//         imul    ecx,edi,0x1a2b8f9c    
// 
//         imul    edx,eax,0x1a2b8f9c    
//         imul    edx,ebx,0x1a2b8f9c    
//         imul    edx,ecx,0x1a2b8f9c    
//         imul    edx,edx,0x1a2b8f9c    
//         imul    edx,esp,0x1a2b8f9c    
//         imul    edx,ebp,0x1a2b8f9c    
//         imul    edx,esi,0x1a2b8f9c    
//         imul    edx,edi,0x1a2b8f9c    
// 
//         imul    esp,eax,0x1a2b8f9c    
//         imul    esp,ebx,0x1a2b8f9c    
//         imul    esp,edx,0x1a2b8f9c    
//         imul    esp,ecx,0x1a2b8f9c    
//         imul    esp,esp,0x1a2b8f9c    
//         imul    esp,ebp,0x1a2b8f9c    
//         imul    esp,esi,0x1a2b8f9c    
//         imul    esp,edi,0x1a2b8f9c    
// 
//         imul    ebp,eax,0x1a2b8f9c    
//         imul    ebp,ebx,0x1a2b8f9c    
//         imul    ebp,ecx,0x1a2b8f9c    
//         imul    ebp,edx,0x1a2b8f9c    
//         imul    ebp,esp,0x1a2b8f9c    
//         imul    ebp,ebp,0x1a2b8f9c    
//         imul    ebp,edi,0x1a2b8f9c    
//         imul    ebp,esi,0x1a2b8f9c    
// 
//         imul    esi,eax,0x1a2b8f9c    
//         imul    esi,ebx,0x1a2b8f9c    
//         imul    esi,edx,0x1a2b8f9c    
//         imul    esi,ecx,0x1a2b8f9c    
//         imul    esi,esp,0x1a2b8f9c    
//         imul    esi,ebp,0x1a2b8f9c    
//         imul    esi,esi,0x1a2b8f9c    
//         imul    esi,edi,0x1a2b8f9c    
// 
//         imul    edi,eax,0x1a2b8f9c    
//         imul    edi,ebx,0x1a2b8f9c    
//         imul    edi,ecx,0x1a2b8f9c    
//         imul    edi,edx,0x1a2b8f9c    
//         imul    edi,esp,0x1a2b8f9c    
//         imul    edi,ebp,0x1a2b8f9c    
//         imul    edi,esi,0x1a2b8f9c    
//         imul    edi,edi,0x1a2b8f9c    
// 
//         imul    ax,0x4f7d         
//         imul    bx,0x4f7d         
//         imul    cx,0x4f7d         
//         imul    dx,0x4f7d         
//         imul    sp,0x4f7d         
//         imul    bp,0x4f7d         
//         imul    si,0x4f7d         
//         imul    di,0x4f7d         
// 
//         imul    eax,0x1a2b8f9c        
//         imul    ebx,0x1a2b8f9c        
//         imul    ecx,0x1a2b8f9c        
//         imul    edx,0x1a2b8f9c        
//         imul    esp,0x1a2b8f9c        
//         imul    ebp,0x1a2b8f9c        
//         imul    esi,0x1a2b8f9c        
//         imul    edi,0x1a2b8f9c        
// 
// 
//         mov    ebx , 0x50000000
//         mov    dword ptr[ebx+22h] , 0x54768132
//         mov    dword ptr[ebx+2222h] , 0x32145786
// 
//         imul    byte ptr[ebx]         
//         imul    word ptr[ebx]         
//         imul    dword ptr[ebx]
//     }
}

void INC_TEST(void)
{
    _asm{
        mov    eax , 0x80007fff
        mov    ecx , 0x7fff8000
        mov    edx , 0x62e147ad
        mov    ebx , 0x6e147
        mov    esi , 0xade14754
        mov    edi , 0x7fffffff
        mov    esp , 0x34dd2134
        mov    ebp , 0xfffffffe

        inc     ax 
        inc     eax 
        inc     bx 
        inc     ebx 
        inc     cx 
        inc     ecx
        inc     dx 
        inc     edx
        inc     si
        inc     esi
        inc     di
        inc     edi
        inc     bp
        inc     ebp
        inc     sp
        inc     esp

        mov    ebx , 0x50000000
        mov    dword ptr[ebx+22h] , 0x54768132
        mov    dword ptr[ebx+2222h] , 0x32145786

        inc    byte ptr[ebx]    
        inc    dword ptr[ebx]
    }
}


void Rotate(void)
{
    _asm{
        mov    eax , 0x80007fff
        mov    ecx , 0x7fff8000
        mov    edx , 0x62e147ad
        mov    ebx , 0x6e147
        mov    esi , 0xade14754
        mov    edi , 0x7fffffff
        mov    esp , 0x34dd2134
        mov    ebp , 0xfffffffe

        rcr    al, 1          //D0 D8       
        rcr    ah, 1          //D0 DC       
        rcr    bl, 1          //D0 DB       
        rcr    bh, 1          //D0 DF       
        rcr    cl, 1          //D0 D9       
        rcr    ch, 1          //D0 DD       
        rcr    dl, 1          //D0 DA       
        rcr    dh, 1          //D0 DE       
        rcr    ax, 1          //66 D1 D8    
        rcr    bx, 1          //66 D1 DB    
        rcr    cx, 1          //66 D1 D9    
        rcr    dx, 1          //66 D1 DA    
        rcr    sp, 1          //66 D1 DC    
        rcr    bp, 1          //66 D1 DD    
        rcr    si, 1          //66 D1 DE    
        rcr    di, 1          //66 D1 DF    
        rcr    eax, 1         //D1 D8       
        rcr    ebx, 1         //D1 DB       
        rcr    ecx, 1         //D1 D9       
        rcr    edx, 1         //D1 DA       
        rcr    esp, 1         //D1 DC       
        rcr    ebp, 1         //D1 DD       
        rcr    esi, 1         //D1 DE       
        rcr    edi, 1         //D1 DF  

        mov    cl , 2

        rcr    al, cl         //D2 D8        
        rcr    dh, cl         //D2 DE          
        rcr    di, cl         //66 D3 DF          
        rcr    edi, cl        //D3 DF   

        rcr    al, 0x22           //C0 D8 22      
        rcr    dl, 0x22           //C0 DA 22    
        rcr    dh, 0x22           //C0 DE 22    
        rcr    ax, 0x22           //66 C1 D8 22 
        rcr    si, 0x22           //66 C1 DE 22 
        rcr    di, 0x22           //66 C1 DF 22 
        rcr    eax, 0x22          //C1 D8 22    
        rcr    ebx, 0x22          //C1 DB 22    
        rcr    ecx, 0x22          //C1 D9 22    
        rcr    esi, 0x22          //C1 DE 22    
        rcr    edi, 0x22          //C1 DF 22    

        mov   ebx , 0x50000000
        rcr    byte ptr[ebx]    , 1    //D0 55 FB           
        rcr    word ptr[ebx], 1    //66 D1 55 EC         
        rcr    dword ptr[ebx]     , 1    //D1 55 E0 
        mov    cl , 0x3
        rcr    byte ptr[ebx]    , cl   //D2 55 FB           
        rcr    word ptr[ebx], cl   //66 D3 55 EC        
        rcr    dword ptr[ebx]     , cl   //D3 55 E0  


        rcl    al, 1         
        rcl    ah, 1         
        rcl    bl, 1         
        rcl    bh, 1         
        rcl    cl, 1         
        rcl    ch, 1         
        rcl    dl, 1         
        rcl    dh, 1         
        rcl    ax, 1         
        rcl    bx, 1         
        rcl    cx, 1         
        rcl    dx, 1         
        rcl    sp, 1         
        rcl    bp, 1         
        rcl    si, 1         
        rcl    di, 1         
        rcl    eax, 1        
        rcl    ebx, 1        
        rcl    ecx, 1        
        rcl    edx, 1        
        rcl    esp, 1        
        rcl    ebp, 1        
        rcl    esi, 1        
        rcl    edi, 1        

        mov    cl , 2

        rcl    al, cl         
        rcl    dh, cl        
        rcl    di, cl          
        rcl    edi, cl           

        rcl    al, 0x32          
        rcl    dl, 0x32          
        rcl    dh, 0x32          
        rcl    ax, 0x32          
        rcl    si, 0x32          
        rcl    di, 0x32          
        rcl    eax, 0x32         
        rcl    ebx, 0x32         
        rcl    ecx, 0x32         
        rcl    esi, 0x32         
        rcl    edi, 0x32         

        mov   ebx , 0x50000000
        rcl    byte ptr[ebx]    , 1         
        rcl    word ptr[ebx], 1          
        rcl    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        rcl    byte ptr[ebx]    , cl        
        rcl    word ptr[ebx], cl  
        rcl    dword ptr[ebx]     , cl  

        rol    al, 1         
        rol    ah, 1         
        rol    bl, 1         
        rol    bh, 1         
        rol    cl, 1         
        rol    ch, 1         
        rol    dl, 1         
        rol    dh, 1         
        rol    ax, 1         
        rol    bx, 1         
        rol    cx, 1         
        rol    dx, 1         
        rol    sp, 1         
        rol    bp, 1         
        rol    si, 1         
        rol    di, 1         
        rol    eax, 1        
        rol    ebx, 1        
        rol    ecx, 1        
        rol    edx, 1        
        rol    esp, 1        
        rol    ebp, 1        
        rol    esi, 1        
        rol    edi, 1        

        mov    cl , 2

        rol    al, cl         
        rol    dh, cl        
        rol    di, cl          
        rol    edi, cl           

        rol    al, 0x32          
        rol    dl, 0x32          
        rol    dh, 0x32          
        rol    ax, 0x32          
        rol    si, 0x32          
        rol    di, 0x32          
        rol    eax, 0x32         
        rol    ebx, 0x32         
        rol    ecx, 0x32         
        rol    esi, 0x32         
        rol    edi, 0x32         

        mov   ebx , 0x50000000
        rol    byte ptr[ebx]    , 1         
        rol    word ptr[ebx], 1          
        rol    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        rol    byte ptr[ebx]    , cl        
        rol    word ptr[ebx], cl  
        rol    dword ptr[ebx]     , cl   
        ror    al, 1         
        ror    ah, 1         
        ror    bl, 1         
        ror    bh, 1         
        ror    cl, 1         
        ror    ch, 1         
        ror    dl, 1         
        ror    dh, 1         
        ror    ax, 1         
        ror    bx, 1         
        ror    cx, 1         
        ror    dx, 1         
        ror    sp, 1         
        ror    bp, 1         
        ror    si, 1         
        ror    di, 1         
        ror    eax, 1        
        ror    ebx, 1        
        ror    ecx, 1        
        ror    edx, 1        
        ror    esp, 1        
        ror    ebp, 1        
        ror    esi, 1        
        ror    edi, 1        

        mov    cl , 2

        ror    al, cl         
        ror    dh, cl        
        ror    di, cl          
        ror    edi, cl           

        ror    al, 0x32          
        ror    dl, 0x32          
        ror    dh, 0x32          
        ror    ax, 0x32          
        ror    si, 0x32          
        ror    di, 0x32          
        ror    eax, 0x32         
        ror    ebx, 0x32         
        ror    ecx, 0x32         
        ror    esi, 0x32         
        ror    edi, 0x32         

        mov   ebx , 0x50000000
        ror    byte ptr[ebx]    , 1         
        ror    word ptr[ebx], 1          
        ror    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        ror    byte ptr[ebx]    , cl        
        ror    word ptr[ebx], cl  
        ror    dword ptr[ebx]     , cl   


        sal    al, 1         
        sal    ah, 1         
        sal    bl, 1         
        sal    bh, 1         
        sal    cl, 1         
        sal    ch, 1         
        sal    dl, 1         
        sal    dh, 1         
        sal    ax, 1         
        sal    bx, 1         
        sal    cx, 1         
        sal    dx, 1         
        sal    sp, 1         
        sal    bp, 1         
        sal    si, 1         
        sal    di, 1         
        sal    eax, 1        
        sal    ebx, 1        
        sal    ecx, 1        
        sal    edx, 1        
        sal    esp, 1        
        sal    ebp, 1        
        sal    esi, 1        
        sal    edi, 1        

        mov    cl , 2

        sal    al, cl         
        sal    dh, cl        
        sal    di, cl          
        sal    edi, cl           

        sal    al, 0x32          
        sal    dl, 0x32          
        sal    dh, 0x32          
        sal    ax, 0x32          
        sal    si, 0x32          
        sal    di, 0x32          
        sal    eax, 0x32         
        sal    ebx, 0x32         
        sal    ecx, 0x32         
        sal    esi, 0x32         
        sal    edi, 0x32         

        mov   ebx , 0x50000000
        sal    byte ptr[ebx]    , 1         
        sal    word ptr[ebx], 1          
        sal    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        sal    byte ptr[ebx]    , cl        
        sal    word ptr[ebx], cl  
        sal    dword ptr[ebx]     , cl   

        sar    al, 1         
        sar    ah, 1         
        sar    bl, 1         
        sar    bh, 1         
        sar    cl, 1         
        sar    ch, 1         
        sar    dl, 1         
        sar    dh, 1         
        sar    ax, 1         
        sar    bx, 1         
        sar    cx, 1         
        sar    dx, 1         
        sar    sp, 1         
        sar    bp, 1         
        sar    si, 1         
        sar    di, 1         
        sar    eax, 1        
        sar    ebx, 1        
        sar    ecx, 1        
        sar    edx, 1        
        sar    esp, 1        
        sar    ebp, 1        
        sar    esi, 1        
        sar    edi, 1        

        mov    cl , 2

        sar    al, cl         
        sar    dh, cl        
        sar    di, cl          
        sar    edi, cl           

        sar    al, 0x32          
        sar    dl, 0x32          
        sar    dh, 0x32          
        sar    ax, 0x32          
        sar    si, 0x32          
        sar    di, 0x32          
        sar    eax, 0x32         
        sar    ebx, 0x32         
        sar    ecx, 0x32         
        sar    esi, 0x32         
        sar    edi, 0x32         

        mov   ebx , 0x50000000
        sar    byte ptr[ebx]    , 1         
        sar    word ptr[ebx], 1          
        sar    dword ptr[ebx]     , 1 
        mov    cl , 0x4
        sar    byte ptr[ebx]    , cl        
        sar    word ptr[ebx], cl  
        sar    dword ptr[ebx]     , cl   
    }
}

void  CMPS_TEST()
{
    _asm{
        mov   ecx , 0x30
        mov   esi , 0x50000016
        mov   edi , 0x50000036
        std   
        repe cmpsb 
    }
}

void MOVS_TEST()
{
    _asm{
        mov   ecx , 0x8
        mov   esi , 0x50000000
        mov   edi , 0x50000020
        cld   
        repe movsw

        mov   ecx , 0x8
        mov   esi , 0x50000010
        mov   edi , 0x50000030
        std   
        repe movsw
    }
}

void ENTER_TEST(void)
{
    //Visual Studio 2005
    //         enter  1024,0      //     ESP = 0011C60C EBP = 0012FF68  
    //            // ->  ESP = 0011C208 EBP = 0011C608
    // 
    //         enter  1024,1      //     ESP = 0011C60C EBP = 0012FF68
    //            // ->  ESP = 0011C204 EBP = 0011C608
    //         enter  1024,2      //     ESP = 0011C60C EBP = 0012FF68
    //            //     ESP = 0011C200 EBP = 0011C608

    //         enter  1024,5     //     ESP = 0011C60C EBP = 0012FF68
    //           //     ESP = 0011C1F4  -4 - 4*4 -4 = 4*6  EBP = 0011C608
}

void TEST_TEST(void)
{
    _asm{
        mov    eax , 0x62e147a
        mov    ecx , 0x7fff8000
        mov    edx , 0x62e147ad
        mov    ebx , 0x6e147
        mov    esi , 0xade14754
        mov    edi , 0x7fffffff
        mov    esp , 0x34dd2134
        mov    ebp , 0xfffffffe

        test   al , 0x80        //PL = 0 ZR = 1 PE = 1
        test   ax , 0x8000      //PL = 0 ZR = 1 PE = 1
        test   eax, 0x80000000  //PL = 0 ZR = 1 PE = 1

        test   dh ,bl           //PL = 0 ZR = 0 PE = 1

        test   dx ,si           //PL = 0 ZR = 0 PE = 0
        test   bx , ax          //PL = 0 ZR = 0 PE = 1
        test   ebx, eax         //PL = 0 ZR = 0 PE = 0

        test   ch , 0x80        //PL = 1 ZR = 0 PE = 0
        test   bx , 0x8000      //PL = 1 ZR = 0 PE = 1
        test   edx, 0x80000000  //PL = 0 ZR = 1 PE = 1
    }
}

void BinaryTreeTra()
{
    //Figure
    //                 ①
    //　　　　　　　　　\
    //　　　　　　　　　②　
    //　　　　　　　　 /
    //                ③
    //               /  \
    //              ④  ⑤
    //
    //BinaryTreeNode Logical  Data Struct:
    //struct BinaryTreeNode{
    //    Date date;
    //    struct BinaryTreeNode * left;
    //    struct BinaryTreeNode * right;
    //};
    //
    //In Memory:
    //    Address     Context     Comment
    //  0x50000000       1        node_1 data
    //  0x00000004      NULL      left_point
    //  0x50000008    0x50000008  right pointer: point to node_2
    //  0x5000000C       2        node_2 data
    //  0x50000010    0x50000020  left pointer: point to node_3
    //  0x50000014      NULL      
    //  0x50000018      ...       otherdata
    //  0x5000001C      ...       otherdata
    //  0x50000020       3        node_3 data
    //  0x50000024    0x50000038  left pointer: point to node_4 
    //  0x50000028    0x50000050  left pointer: point to node_5
    //  0x5000002C      ...       otherdata
    //  0x50000030      ...       otherdata
    //  0x50000034      ...       otherdata
    //  0x50000038       4        
    //  0x5000003C      NULL
    //  0x50000040      NULL
    //  0x50000044      ...       otherdata
    //  0x50000048      ...       otherdata
    //  0x5000004C      ...       otherdata
    //  0x50000050      5
    //  0x50000054     NULL
    //  0x50000058     NULL

    _asm{
    mov    eax , 0x50000000        //node_1    address           //Figure            
    call   RecursiveInorder        //                                                       ①    0x50000000 
    jmp    QUIT                    //　　　　　　　                                      　　\           
RecursiveInorder:                  //                                                      　②　 0x5000000C 
    push   eax                     //　　　　　　　                                      　 /       
    cmp    eax , 0                 //                                                      ③     0x50000020  
    jz     RETURN                  //                                                     /  \           
    mov    eax , [eax+0x4]         //left  pointer     [eax+0x4]         //0x50000038    ④  ⑤   0x50000050  
    call   RecursiveInorder        //Inorder output  : 1. 4 . 3 . 5 . 2
    pop    eax                       
    push   eax
    mov    ebx , 0x50000060
    mov    edx, [eax]          //Node data
    mov    [ebx], edx
    mov    eax , [eax+0x8]         //right pointer 
    call   RecursiveInorder
RETURN: pop    eax
RET2:   ret
QUIT:   
    }
        // mov    eax , 0x50000000        //node_1    address            //Figure            
        //          call   Recursivepreorder                 //                 ①    0x50000000 
        //          jmp    QUIT                              //　　　　　　　　　\           
        // Recursivepreorder:          //                    //　　　　　　　　　②　 0x5000000C 
        //          push   eax                               //　　　　　　　　 /      
        //          cmp    eax , 0                           //                ③     0x50000020  
        //          jz     RETURN                            //               /  \           
        //          mov    ebx , 0x50000060                  //0x50000038    ④  ⑤   0x50000050  
        //          mov    edx, [eax]          //Node data           //Recursivepreorder output  : 1. 2 . 3 . 4 . 5
        //          mov    [ebx], edx                
        //           mov    eax , [eax+0x4]         //left  pointer     [eax+0x4]        
        //          call   Recursivepreorder                  
        //          pop    eax                       
        //          push   eax
        //          mov    eax , [eax+0x8]         //right pointer 
        //          call   Recursivepreorder
        // RETURN: pop    eax
        // RET2:   ret

        //          mov    eax , 0x50000000               
        //          call   Recursivepostorder     
        //          jmp    QUIT                   
        // Recursivepostorder:              
        //          push   eax              
        //          cmp    eax , 0          
        //          jz     RETURN                 
        //          mov    eax , [eax+0x4]         //left  pointer     [eax+0x4]          
        //          call   Recursivepostorder     
        //          pop    eax                       
        //          push   eax
        //          mov    eax , [eax+0x8]         //right pointer 
        //          call   Recursivepostorder
        //          pop    eax
        //          mov    ebx , 0x50000060                  
        //          mov    edx, [eax]          //Node data           
        //          mov    [ebx], edx   
        //          jmp    RET2
        // RETURN:  pop    eax
        // RET2:    ret

        //
        //      //Microsoft specific:  __cdecl 
        //      //Stack is cleaned up by caller ;Argument-passing order : Right to left 
        //          mov    eax , 0x50000000        //node_1    address          
        //          push   eax                      
        //          call   Recursivepostorder                   
        //          pop    eax                      
        //          jmp    QUIT                     
        // Recursivepostorder:                      
        //          push   ebp                       
        //          mov    ebp , esp                //Figure               
        //          push   esp                      //                                     ①    0x50000000     
        //          mov    eax , [ebp+0x8]          //取得压入栈中的数据          　　 　　 \           
        //          cmp    eax , 0                  //            //　　　　　　　　        ②　 0x5000000C        
        //          jz     RETURN                   //　　　　　　　　                      /      
        //          mov    eax , [eax+0x4]          //left  pointer     [eax+0x4]          ③     0x50000020        
        //          push   eax                      //给调用者传递参数        //          /  \        
        //          call   Recursivepostorder       //                      0x50000038   ④  ⑤   0x50000050         
        //          pop    eax                      //调用者清除传递的参数        //Recursivepostorder output  : 4. 5 . 3 . 2 . 1
        //          mov    eax , [ebp+0x8]
        //          mov    eax , [eax+0x8]         //right pointer 
        //          push   eax
        //          call   Recursivepostorder
        //          pop    eax
        //          mov    eax , [ebp+0x8]
        //          mov    ebx , 0x50000060                  
        //          mov    edx, [eax]          //Node data           
        //          mov    [ebx], edx   
        // RETURN:  pop    esp
        //          pop    ebp
        //          ret
        //
        //      //Microsoft specific:  __stdcall         //calling convention is used to call Win32 API functions 
        //      //The callee(被调用者) cleans the stack ;          Argument-passing order : Right to left 
        //          mov    eax , 0x50000000        //node_1    address          
        //          push   eax                      
        //          call   Recursivepostorder                                  
        //          jmp    QUIT                     
        // Recursivepostorder:                    
        //          push   ebp                       
        //          mov    ebp , esp                           
        //          push   esp                     
        //          mov    eax , [ebp+0x8]         //取得压入栈中的数据               
        //          cmp    eax , 0         　　　　　　
        //          jz     RETURN               
        //          mov    eax , [eax+0x4]         //left  pointer     [eax+0x4]      
        //          push   eax         //给调用者传递参数           
        //          call   Recursivepostorder      //ret n 时把上面传递的参数释放掉              
        //          mov    eax , [ebp+0x8]                   //Recursivepostorder output  : 4. 5 . 3 . 2 . 1
        //          mov    eax , [eax+0x8]         //right pointer 
        //          push   eax
        //          call   Recursivepostorder
        //          mov    eax , [ebp+0x8]
        //          mov    ebx , 0x50000060                  
        //          mov    edx, [eax]          //Node data           
        //          mov    [ebx], edx   
        // RETURN:  pop    esp
        //          pop    ebp
        //          ret    4  //把传递进来的参数从栈中释放掉  //ret 指令弹出N个字节的栈中数据


        //Microsoft specific:  The __fastcall calling convention specifies that arguments to functions are to be passed in registers, when possible. 
        //The first two DWORD or smaller arguments are passed in ECX and EDX registers; all other arguments are passed right to left. ;  
        //Called function pops the arguments from the stack.
        //         mov    ecx , 0x50000000          //node_1    address                        
        //         call   Recursivepostorder                                  
        //         jmp    QUIT                     
        // Recursivepostorder:                                    
        //         push   ecx         //本函数要使用的寄存器，故要push保存起来               
        //         cmp    ecx , 0                 //          
        //         jz     RETURN                  //　　　　　　
        //         mov    ecx , [ecx+0x4]         //left  pointer     [eax+0x4]           
        //         call   Recursivepostorder      //ret n 时把上面传递的参数释放掉       
        //         mov    ecx , [esp]             //               
        //         mov    ecx , [ecx+0x8]         //right pointer           
        //         call   Recursivepostorder               
        //         mov    ecx , [esp]             //Recursivepostorder output  : 4. 5 . 3 . 2 . 1
        //         mov    edx , [ecx]
        //         mov    ebx , 0x50000060                           
        //         mov    [ebx], edx   
        // RETURN:  pop    ecx
        //          ret    
}

//AVL tree
void AVL_TEST(void)
{
    //a, e, h, k, m, p, t, u, v
    //1, 2, 3, 4, 5, 6, 7, 8, 9

    //k, t, e, v, p, a, m, u, h
    //4, 7, 2, 9, 6, 1, 5, 8, 3

    //eax相当于一个指针，它的值是一个它所指向的数据的地址
    //eax本身没有地址

    //指针,指向指针的指针
    //avl_insert(Binary_node<Record> * & sub_root, const & new_dat , bool & taller)
    //数据的结点放在0x50000400开始内存中

    //nearly balanced binary search
    //
    //enum balance_factor{left_hight, equal_height, right_higher}
    //Balance_factor balance
    //left , right pointers of a Binary_node have this type Binary_node *.
    //insert(const Record & new_data)
    //Post: if the key of the new_data is already in the avl_tree ,a code of duplicate_error is returned.
    //Otherwise , a cod of success is returned and the Record new_data is inserted into the tree in such a way 
    //that the properties of an avl tree are preserved
    //{
    //    bool  taller;
    //    return avl_insert(root, new_data, taller);
    //}

    //avl_insert(Binary_node<Record> * & sub_root , const Record & new_data , bool &taller)
    //Pre : sub_root is either NULL or points to a subtree of the avl_tree
    //Post: if the key of new_data is already in the subtree , a code of duplicate_error is returned . Otherwise, a code of success is returned and the record 
    // new_data is inserted into the subtree in such a way that the properties of an AVL tree have been preserved . If the subtree is increased in height, the
    //parameter taller is set true; Otherwise it is set to false
    //Uses: Methods of struct AVL_node ; functions avl_insert recursively, left_balance, and right_balance
    // 
    //      {
    //          Error_code_result = success;
    //          if (sub_root == NULL){
    //          sub_root == new AVL_node<Record>(new_data);//递归调用的最后返回
    //          taller = true;
    //          }
    //          else if (new_data == sub_root->data){
    //          result = duplicate_error;
    //          taller = true;
    //          }
    //          else if (new_data < sub_root->data){   //  insert in left subtree
    //          result = avl_insert(sub_root->left , new_data, taller);
    //          if (taller == true){
    //          switch (sub_root->get_balance()){
    //              case left_higher:
    //              left_balance(sub_root);
    //              taller = false ;
    //              break;
    //              case equal_height:
    //              sub_root->set_balance(left_higher);
    //              break;
    //              case right_higher:
    //              sub_root->set_balance(equal_hight);
    //              taller = false ;
    //              break;
    //          }
    //          }
    //          }
    //          else{
    //          result = avl_insert(sub_root->right, new_data , taller);
    //          if ( taller == ture){
    //          switch (sub_root->get_balance()){
    //          case left_higher:
    //              sub_root->set_balance(equal_hight);
    //              taller = false;
    //              break;
    //          case equal_height:
    //              sub_root->set_balance(right_higher);
    //              break;
    //          case right_higher:
    //              right_balance(sub_root);
    //              taller = false;
    //              break;
    //          }
    //          }
    //          }
    // 
    //          return result;
    //      }

    //call stack
    //hight address   : parameter
    //          return 
    //          push ebp
    //          mov  ebp , esp
    //          sub  esp       //局部变量内存分配
    //input :

    //eax = points to the sub_root
    //ebx = new data
    //ecx = taller (bool)
    //rerutn 
    // -1  : left_higher;
    // 0   : equal
    // 1   : right_higher
    //          push  ebp
    //          mov   ebp, esp
    //0x500003f0   ; &sub_root
    //0x500003f4   ; &new_data
    //0x500003f8   : &taller
_asm{
    mov   ebx , 0x500003f4
        mov   edi , 0x50000000
        mov   edx , 0
READ_DATA:
    mov   eax, 0x500003f0     //eax = &sub_root
        mov   esi, [edi+edx*0x4]
    mov   [ebx],esi
        mov   ecx , 0x500003f8

        inc   edx
        call  avl_insert
        cmp   edx , 0x9
        jl    READ_DATA
        jmp   QUIT

avl_insert: 
    push  ebp  
        mov   ebp, esp
        sub   esp , 0x4        //result
        push  edi          //temp1
        push  esi
        mov   dword ptr[ebp-0x4],0 //result = success
        mov   edi, [eax]
    cmp   edi , 0           //if (sub_root == NULL)
        jnz   CMPNEWDATA 
        mov   edi , 0x500003FC      //tree node number   //New Node    at : 0x50000400
        mov   esi, [edi]
    inc   [edi]
    imul  esi,0x10          //4个域 , data, left ,right ,balance == 16bytes
        add   esi , edi
        add   esi , 0x4
        mov   edi ,  [ebx]
    mov   [esi], edi        //esi points to the new data
        mov   [eax],esi
        mov   [ecx] , 1           //taller = true;
        jmp   AVL_INSERT_RETURN
CMPNEWDATA:
    mov  edi,[eax]
    mov  edi,[edi]
    cmp  [ebx],edi        //new_data == sub_root->data
        jne   INSERT_LEFT_OR_RIGHT
        mov  [ebp-0x4], -1         //duplicate_error
        mov  ecx , 0           //taller = false
        jmp  AVL_INSERT_RETURN

INSERT_LEFT_OR_RIGHT:  
    mov  edi,[eax]
    mov  edi ,[edi]
    cmp  [ebx],edi        //new_data < sub_root->data
        jge  INSERT_RIGHT_TREE

        //below : Inert_left_tree
        mov   edi , [eax]
    lea   edi , [edi+0x4]
    push  eax
        mov   eax , edi          //avl_insert(sub_root->left, new_data, taller)
        call  avl_insert
        mov   [ebp-0x4],eax         //result == avl_insert()返回   
        pop   eax
        mov   edi , [eax]
    cmp   [ecx] , 1           //taller == ture  , 确认插入数据成功
        jne   AVL_INSERT_RETURN

        //Switch left higher
        cmp   [edi+0xC] , -1        //switch (sub_root->get_balance()) //dword ptr[eax+0xC]  = balance
        jne   SWITCH_CASE_EQUAL
        call  left_balance
        mov   [ecx] , 0           //taller = false
        jmp   AVL_INSERT_RETURN

SWITCH_CASE_EQUAL:
    cmp   [edi+0xC], 0
        jne   SWITCH_CASE_RIGH_HIGHER
        mov   [edi+0xC], -1           //sub_root->set_balance(left_higher)
        jmp   AVL_INSERT_RETURN

SWITCH_CASE_RIGH_HIGHER:
    cmp   [edi+0xC], 1
        jne   AVL_INSERT_RETURN
        mov   [edi+0xC], 0           //sub_root->set_balance(equal_height)
        mov   [ecx] , 0           //taller = false
        jmp   AVL_INSERT_RETURN

INSERT_RIGHT_TREE:
    //求内存的地址
    mov   edi , [eax]
    lea   edi , [edi+0x8]
    push  eax
        mov   eax , edi       //avl_insert(sub_root->right, new_data, taller)
        call  avl_insert
        mov   [ebp-0x4],eax         //result == avl_insert()返回
        pop   eax
        cmp   [ecx] , 1           //taller == ture  确认插入数据成功
        jne   AVL_INSERT_RETURN
        mov   edi , [eax]
    cmp   [edi+0xC] , -1        //switch (sub_root->get_balance()) //dword ptr[eax+0xC]  = balance
        jne   SWITCH_CASE_EQUAL1

        //SWITCH_CASE_LEFT_HIGHER
        //
        mov   [edi+0xC], 0         //sub_root->set_balance(equal_heigher)
        mov   [ecx] , 0           //taller = false
        jmp   AVL_INSERT_RETURN

SWITCH_CASE_EQUAL1:
    cmp   [edi+0xC], 0
        jne   SWITCH_CASE_RIGH_HIGHER2
        mov   [edi+0xC], 1           //sub_root->set_balance(right_higher)
        jmp   AVL_INSERT_RETURN

SWITCH_CASE_RIGH_HIGHER2:
    cmp   [edi+0xC], 1
        jne   AVL_INSERT_RETURN
        call  right_balance
        mov   [ecx] , 0           //taller = false
        jmp   AVL_INSERT_RETURN

AVL_INSERT_RETURN:
    mov  eax , [ebp-0x4]
    pop  esi
        pop  edi
        add  esp , 0x4
        pop  ebp
        ret

        //Rotations
left_balance:
    //          if(condition1 || condition2)
    //          cmp  条件1  
    //          j   //成立
    //          cmp  条件2
    //          j   //不立
    //          //执行语句块
    //          //if 结束
    push  ebx           //right_tree
        push  ecx           //temp
        cmp   eax , 0       //sbu_root == NULL
        je    LEFT_BALANCE_OUTPUT
        cmp   [eax+0x4],0   //sub_root->right == NULL
        jne   ELSE_LEFT_BALANCE
LEFT_BALANCE_OUTPUT:
    //printf("Warning : program error detected in rotate_left");
    jmp   LEFT_BALANCE_RET
ELSE_LEFT_BALANCE:
    mov   ebx , [eax+0x8]     //right_tree = sub_root->right
    mov   ecx , [ebx+0x4]     //right_tree->left
    mov   [eax+0x8],  ecx     //sub_root->right = right_tree->left
        mov   [ebx+0x4],  eax
        mov   eax , ebx           //sub_root = right_root
LEFT_BALANCE_RET:
    pop  ecx
        pop  ebx
        ret 

right_balance:
    //right_balance(Binary_node<Record> * & sub_root)
    //Pre:sub_root points to a subtree of an AVL_tree that is doubly unbalanced on the right
    //input eax = &sub_root
    push   ebx // right_tree
        push   ecx // sub_tree
        mov    ebx ,[eax+0x8]
    cmp    [ebx+0xC] ,  1    //right_higher
        jne    SWITCH_EQUAL_HEIGHT_RB
        mov    dword ptr[eax+0xC], 0     //set_root->set_balance(equal_height);
        mov    dword ptr[eax+0xC], 0     //right_tree->set_balance(equal_height);
        call rotate_left
        jmp    RETURN_RB   
SWITCH_EQUAL_HEIGHT_RB:
    cmp    [ebx+0xC] , 0
        jne    SWITCH_LEFT_HEIGHT_RB
        jmp    RETURN_RB  
SWITCH_LEFT_HEIGHT_RB:          //double rotation left
    cmp    [ebx+0xC] , -1
        jne    RETURN_RB
        //binary_node<Record> * sub_tree = right_tree->left
        mov    ecx ,[ebx+0x4]
    cmp    dword ptr[ecx+0xC], 0
        jne    SWITCH_SWITCH_LEFT_HIGHER
        mov    dword ptr[eax+0xC], 0
        mov    [ebx+0xC], 0
        jmp    SWITCH_LEFT_HIGHER_END

SWITCH_SWITCH_LEFT_HIGHER:
    cmp    dword ptr[ecx+0xC], -1
        jne    SWITCH_SWITCH_RIGHT_HIGHER
        mov    dword ptr[eax+0xC], 0
        mov    [ebx+0xC], 1
        jmp    SWITCH_LEFT_HIGHER_END


SWITCH_SWITCH_RIGHT_HIGHER:
    cmp   dword ptr[ecx+0xC], 1
        jne   SWITCH_LEFT_HIGHER_END
        mov   dword ptr[eax+0xC], -1
        mov   dword ptr[ebx+0xc], 0
SWITCH_LEFT_HIGHER_END:

    mov   dword ptr[ecx+0xC] , 0
        //          call  rotate_right(right_tree)
        call    rotate_right
        //          call  rotate_left(sub_root)
        call    rotate_left

RETURN_RB:
    pop   ecx
        pop   ebx
        ret 

        //input eax = &right_tree
rotate_right:
    push  ebx           //sub_tree
        push  ecx           //temp1
        push  edx           //temp2
        cmp   eax , 0       //right_tree == NULL
        je    RIGHT_BALANCE_OUTPUT
        cmp   [eax+0x8],0   //sub_root->left == NULL
        jne   ELSE_RIGHT_BALANCE
RIGHT_BALANCE_OUTPUT:
    //printf("Warning : program error detected in rotate_left");
    jmp   ROTATE_RETURN

ELSE_RIGHT_BALANCE:
    mov   ebx , [eax+0x4]     //sub_tree = right_tree->left
    mov   ecx , [eax]         //sub_tree , right_tree :data exchange
    mov   edx , [ebx]         //not use xchg
    mov   [eax],edx
        mov   [ebx], ecx          
        mov   ecx , dword ptr[eax+0xC]    //sub_tree , right_tree :balance exchange
    mov   edx , [ebx+0xC]
    mov   dword ptr[eax+0xC],edx
        mov   [ebx+0xC], ecx 

        mov   ecx , [eax+0x4]      //sub_tree->left and sub_tree->right exchange
    mov   edx , [eax+0x8]
    mov   [eax+0x4],edx
        mov   [eax+0x8],ecx 

        mov   ecx , [ebx+0x4]     //right_tree->left and right_tree->right exchange
    mov   edx , [ebx+0x8]
    mov   [ebx+0x4],edx
        mov   [ebx+0x8],ecx 

        mov   ecx , [eax+0x4]         //sub_tree->left and rihgt_tree->left exchange
    mov   edx , [ebx+0x4]
    mov   [eax+0x4],edx
        mov   [ebx+0x4],ecx 

ROTATE_RETURN:
    pop   edx
        pop   ecx
        pop   ebx
        ret

rotate_left:
    jmp   right_balance
QUIT:
    }
}

//Building a binary search tree
void  BuildTree(void)
{
//     0x50000320  01 00 00 00 00 00 00 00 00 00 00 00     
//     0x5000032C  02 00 00 00 20 03 00 50 38 03 00 50     2
//     0x50000338  03 00 00 00 00 00 00 00 00 00 00 00     
//     0x50000344  04 00 00 00 2c 03 00 50 5c 03 00 50     4
//     0x50000350  05 00 00 00 00 00 00 00 00 00 00 00     
//     0x5000035C  06 00 00 00 50 03 00 50 68 03 00 50     6
//     0x50000368  07 00 00 00 00 00 00 00 00 00 00 00      
//     0x50000374  08 00 00 00 44 03 00 50 a4 03 00 50     8
//     0x50000380  09 00 00 00 00 00 00 00 00 00 00 00     
//     0x5000038C  0a 00 00 00 80 03 00 50 98 03 00 50     10
//     0x50000398  0b 00 00 00 00 00 00 00 00 00 00 00     
//     0x500003A4  0c 00 00 00 8c 03 00 50 bc 03 00 50     12
//     0x500003B0  0d 00 00 00 00 00 00 00 00 00 00 00     
//     0x500003BC  0e 00 00 00 b0 03 00 50 c8 03 00 50     14
//     0x500003C8  0f 00 00 00 00 00 00 00 00 00 00 00     
//     0x500003D4  10 00 00 00 74 03 00 50 04 04 00 50     16
//     0x500003E0  11 00 00 00 00 00 00 00 00 00 00 00     
//     0x500003EC  12 00 00 00 e0 03 00 50 f8 03 00 50     18
//     0x500003F8  13 00 00 00 00 00 00 00 00 00 00 00       
//     0x50000404  14 00 00 00 ec 03 00 50 10 04 00 50     20
//     0x50000410  15 00 00 00 00 00 00 00 00 00 00 00     
// 
//     0x0047F3C8  01 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F3D4  02 00 00 00 20 03 00 50 38 03 00 50 
//     0x0047F3E0  03 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F3EC  04 00 00 00 2c 03 00 50 5c 03 00 50 
//     0x0047F3F8  05 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F404  06 00 00 00 50 03 00 50 68 03 00 50 
//     0x0047F410  07 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F41C  08 00 00 00 44 03 00 50 a4 03 00 50 
//     0x0047F428  09 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F434  0a 00 00 00 80 03 00 50 98 03 00 50 
//     0x0047F440  0b 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F44C  0c 00 00 00 8c 03 00 50 bc 03 00 50 
//     0x0047F458  0d 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F464  0e 00 00 00 b0 03 00 50 c8 03 00 50 
//     0x0047F470  0f 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F47C  10 00 00 00 74 03 00 50 04 04 00 50 
//     0x0047F488  11 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F494  12 00 00 00 e0 03 00 50 f8 03 00 50 
//     0x0047F4A0  13 00 00 00 00 00 00 00 00 00 00 00 
//     0x0047F4AC  14 00 00 00 ec 03 00 50 10 04 00 50 
//     0x0047F4B8  15 00 00 00 00 00 00 00 00 00 00 00 

    _asm{
        //Building A binary Search Tree
        //There is no doubt what to do with entry number 1 when it arrives. It will be placed in a  leaf node whose left and right pointers should both be set to NULL
        //Node number 2 goes above node 1. Since node2 links to need 1 , we obviously must keep some way to remember where node 1 is until entry 2 arrives.
        //Node3 is again a leaf ,but it is in the right subtree of node2,so we must remember a pointer to node 2

        //Does this mean that we must keep a list of pointers to all nodes previously processed , to determine how to link in the next one ?
        //The answer is no, since when node 2 is added , all connections for node 1 are complete . Node2 must be remembered until node4 is added , to establish the left link from node4 ,but then
        //a pointer to node 2 is no longer needed. Similarly, node 4 must be remembered until node8 has been processed. 

        //It should now be clear that to establish future links, we need only remember pointers to one node on each level, the last node processed on that level. 
        //For example, a tree with 20 levels(hence 20 entries)can accommodate 2^20 -1 > 1,000,000

        //                          ┍--
        //                          ④
        //　　　　　　　　　　　　 /
        //                        ②  
        //                       /  \　　　　　┍--
        //                      ①  ③　　　　 ⑤　　　　　　　　　　　 
        //　　　3层，所以 list_node[1] -> ⑤  , list_node[3] ->④   list_node[0] = NULL
        //
        //build_tree(const List<Record> &supply)
        //Post : if the entries of supply are in increasing order , 
        //       a code of success is returned and the Search_tree is built out of these entries as a balanced tree. 
        //       Otherwise, a code of fail is returned and a balanced is constructed from the longest increasing sequence of entries at the start of supply

        //pass List supply
        mov    eax , 0x50000000 //temp输入的数据
            mov    ebx , 0x15       //个数  
            call   BuildTree
            jmp    QUIT_AVL

            //Last_node.size= 0x5000018C                =  0
            //Last_node start Address after 100 numbers // 0x50000000 + 0x190(400 = 4 * 100)  = 0x50000190
            //Last_node[0] must be 0(NULL)    size = 1
            //Last_node[1] = 0x001264B8

            //Out put Memory address : = 0x50000000 + 0x320(800= 4 * 100) = 0x50000320
            //
            //struct BinaryTreeNode{
            //    Date date;
            //    struct BinaryTreeNode * left;
            //    struct BinaryTreeNode * right;
            //};    //12 Bytes
            //
            //temp node save
            //126AF4= 126644 + 4B0(12 Byte * 100)

            //int count = 0 // number of entries insert so far
            //Record  x , last_x ;
            //List  // pointers to last nodes on each level
            //while (supply.retrieve(count ,x)== success){
            //     if(count >0 && x <= last_x){   //以增序方式 the entries of supply are in increasing order ,
            //        ordered_data  = fail;
            //        break;
            //      }
            //      build_insert(++count , x , last_node); //last_node 保存one node on each level  , count 由0 -> max 自然数顺序
            //      last_x = x ;
            //}
            //root = find_root(last_node);
            //connect_trees(last_node);
BuildTree:  push eax 
            push ebx
            mov  ecx , 0x50000190
            mov  [ecx] , 0x0        //Last_node[0]为NULL， Last_node 仅是指针数组
            mov  [ecx - 0x4], 0x1   //Last_node.size 为0
            mov  ecx , ebx          //输入的函数个数
            mov  ebx , 0x0          //count
            mov  edi , 0x0           //last_x
ReadInput:  mov  edx , [eax+ebx*4]   //从输入的数据中读取一个数据
        cmp  edx , 0
            jz   EndReadInput        //读入完毕  ！= success
            cmp  edx , edi           //x <= last_x
            jle  ERROR_RETURN        //return error

            inc   ebx        //count ++

            push eax 
            push ebx
            push ecx
            mov  eax, ebx     //count
            mov  ebx, edx     //x
            mov  ecx, edi     //last_node
            call BuildInsert
            pop  ecx
            pop  ebx
            pop  eax
            mov  edi , edx
            loop  ReadInput
EndReadInput:mov  eax , 0x50000190   //last_node 指向每一层的指针
             call FindRoot        //返回值
             mov  eax , 0x50000190    //last_node 指向每一层的指针
             call ConnectTree
ERROR_RETURN:pop ebx
             pop eax
             ret

             //build_insert(int count, const Record &new_data , List<Binary_node<Record> *> &last_node)
             //Post : A new node ,containing the Record new_data,has been inserted as the rightmost node of a partially completed binary search tree. 
             //       The level of this new node is one more than the highest power of 2 that divides count.
             //int  level;
             //for(level = 1 ; count % 2 == 0 ; level ++ )    //level 求出层次从而找出 list_node 中的 index 
             //{
             //    count /= 2;
             //}
             //
             //Binary_node<Record> * next_node = new Binary_node<Record>(new_data), *parent ;// one level higher in last_node
             //
             //last_node.retrieve(level - 1, next_node->left);
             //
             //if (last_node.size() <= level){
             //    last_node.insert(level, next_node);
             //} 
             //else{
             //    last_node.replace(level, next_node);
             //}
             //
             //if ( last_node.retrieve(level + 1 ,parent) == success && parent -> right = NULL)){
             //    parent->right = next_node;
             //}

BuildInsert:push eax     //count    //form1 to n
            push ebx     //new_data 
            push ecx     //Last_node  ; We keep these pointers in a List called last_node
            push edx     //level
            push esi
            push edi

            xor  esi , esi
            mov  esi , eax        //The count Node
            dec  esi
            sal  esi , 0x2        //mult 4
            imul esi ,esi ,0x3    //定位BinaryNodeTree[] 的下标
            mov  edx, 1            //level initid
            //for 循(trfh)
FindLevel:  test eax, 0x1//模2不用算只要看二进制最后一位就行了.
            jnz  CT_NEXT1//%2 不成立，退出
            sar  eax ,1
            inc  edx          //level
            jmp FindLevel

CT_NEXT1:   //常数均为内存变量的地址。在编译的时候都已经知道
        //Begin new a Binary Node
        add  esi, 0x50000320 //new Node address
            mov  [esi],ebx   //new_data
            mov  [esi+0x4],0 //left = NULL
            mov  [esi+0x8],0 //right= NULL 
            //End   new a Binary Node

            //Last_node.size : 0x5000018C
            //Last_node area : 0x50000190   = Last_node[0] = NULL
            mov  edi , [0x5000018C + edx * 4]//leveln -1 : 指针的内容
        //mov  eax ,[edi]       //leveln -1 指向的 Binary_Node 内存地址
        mov  [esi+0x4] , edi  //last_node .retrieve(level -1, next_node_left)  next_node->left = Last_node[leveln-1] 指针的内容

            mov  eax ,0x5000018C
            cmp  [eax],edx     //Last_node.size() <= leve ?
            jg   NEXT          //Insert a new pointer
            mov  [0x50000190 + edx * 4] , esi //leveln point to next_node
            inc  [eax]         //Last_node.size ++
        jmp  FINAL1
NEXT:       mov  [0x50000190 + edx * 4] , esi //leveln point to next_node    
FINAL1:     mov  eax ,[0x50000190 + edx * 4 +4] //parent = level+1
        cmp  eax , 0        
            jz   RETRUN_BI               //last_node.retrieve(level + 1, parent) == success
            cmp  [eax+0x8] , 0           //parent->right == NULL
            jnz  RETRUN_BI
            mov [eax+0x8], esi
RETRUN_BI:  pop  edi    
            pop  esi
            pop  edx
            pop  ecx
            pop  ebx
            pop  eax
            ret 


            //Finishing the Task
            //Finding the root of the tree is easy: The root is the highest node in the tree, hence its pointer is the last entry the List last_node.
            //The pointers to the last node encountered on each level are stored in the list last_node

            //find_root(List<Binary_node<Record> *> &last_node)
            //pre: The list last_node contains pointers to the last node on each occupied(已占用的;在使用的;) level of the binary search tree
            //post: A pointer to the root of the newly created binary search trees is returned
            //
            //   list_node.retrieve(last_node.size()-1 , high_node);
            //
            //return high_node;
            //input eax = Last_node[0] address
            //return eax //Last_node[high] address
FindRoot:   push ebx
            mov ebx, [eax-0x4]   //Last_node.size
        mov eax, [eax + ebx * 0x4]
        pop  ebx
            ret

            //Connect_tree
            //Pre: The nearly-completed binary search tree has been initialized.The List Last_node has benn initialized and contains links to
            //the last node on each level of the tree
            //Post:The final links have been added to complete the binary search tree
            //input = eax = &last_node 
ConnectTree:push  ebx //high_node
            push  ecx //low_node
            push  edx //high_level
            push  edi //low_level
            push  esi 
            mov   edx ,[eax-0x4] 
        dec   edx     

            //while(high_level > 2)
CT_WHILE:   cmp   edx , 0x2
            jle   RETURN_CT
            mov   ebx , [eax+edx*0x4]   //last_node.retrieve(high_level, high_node)
        cmp   dword ptr [ebx+0x8] ,0
            jz    NEXT_CTELSE
            dec   ebx           //high_node --
            jmp   NEXT_CTEND_ELSE
NEXT_CTELSE:mov   edi , edx   // low_level = high_level
CT_DO:      dec   edi         //--low_level
            mov   ecx,[eax+edi*0x4]  //last_node(--low_level, low_node);
        cmp   ecx , 0
            jz    CT_END_DO_WHILE
            mov   esi , [ecx]      //low_data
        cmp   esi , [ebx]      //low_data < high_node->data
        jge   CT_END_DO_WHILE
            loop  CT_DO
CT_END_DO_WHILE:
        mov   [ebx+0x8], ecx   //high_node->right = low_node
            mov   edx , edi
            jmp   CT_WHILE
NEXT_CTEND_ELSE:
RETURN_CT:  pop  esi
                pop  edi
                pop  edx
                pop  ecx
                pop  ebx
                ret

QUIT_AVL :  mov    eax , 0x0    
    }
}

//Binary Tree Search 


void_BTSearch(void)
{
    //因为传进来的参数是root所以先检查 root
    //strategy : To search for the target , we first compare it with the entry at the root of the tree.
    //If their keys match, then we finished.Otherwise ...

    //This is clearly a recursive process , and therefore we shall implement it by calling an auxiliary recursive function.
    //while( sub_root != NULL && sub_root->data != target)
    //    if( sub_root->data < target ) sub_root = sub_root->right;
    //    else sub_root = sub_root->left;
    //return sub_root

    //input : eax = sub_root 
    //input : ebx = target
    //return eax;

    _asm{
    mov  eax ,0x500003D4              //root
        mov  ebx , 0x12
WHILE_BEGIN: cmp    eax , 0
             jz     WHILE_END
             cmp    [eax], ebx
             je     WHILE_END
             jge    LEFT
             mov    eax,[eax+0x8]    //sub_root = sub_root->right
            jmp    END_IF 
LEFT:        mov    eax,[eax+0x4]    //sub_root = sub_root->left
END_IF:      jmp  WHILE_BEGIN
WHILE_END:  

    }
}

void BTRemove(void)
{
//VS 2005 Other Test
// 0x00126644  01 00 00 00 00 00 00 00 00 00 00 00
// 0x00126650  02 00 00 00 44 66 12 00 5c 66 12 00
// 0x0012665C  03 00 00 00 00 00 00 00 00 00 00 00
// 0x00126668  04 00 00 00 50 66 12 00 80 66 12 00
// 0x00126674  05 00 00 00 00 00 00 00 00 00 00 00
// 0x00126680  06 00 00 00 74 66 12 00 8c 66 12 00
// 0x0012668C  07 00 00 00 00 00 00 00 00 00 00 00
// 0x00126698  08 00 00 00 68 66 12 00 c8 66 12 00
// 0x001266A4  09 00 00 00 00 00 00 00 00 00 00 00
// 0x001266B0  0a 00 00 00 a4 66 12 00 bc 66 12 00
// 0x001266BC  0b 00 00 00 00 00 00 00 00 00 00 00
// 0x001266C8  0c 00 00 00 b0 66 12 00 e0 66 12 00
// 0x001266D4  0d 00 00 00 00 00 00 00 00 00 00 00
// 0x001266E0  0e 00 00 00 d4 66 12 00 00 00 00 00
// 0x001266EC  00 00 00 00 00 00 00 00 00 00 00 00
// 0x001266F8  0f 00 00 00 98 66 12 00 28 67 12 00
// 0x00126704  11 00 00 00 00 00 00 00 00 00 00 00
// 0x00126710  12 00 00 00 04 67 12 00 1c 67 12 00
// 0x0012671C  13 00 00 00 00 00 00 00 00 00 00 00
// 0x00126728  14 00 00 00 10 67 12 00 34 67 12 00
// 0x00126734  15 00 00 00 00 00 00 00 00 00 00 00


// Result : (Address converted) 
// 0x50000320  01 00 00 00 00 00 00 00 00 00 00 00
// 0x5000032C  02 00 00 00 20 03 00 50 38 03 00 50
// 0x50000338  03 00 00 00 00 00 00 00 00 00 00 00
// 0x50000344  04 00 00 00 2c 03 00 50 5c 03 00 50
// 0x50000350  05 00 00 00 00 00 00 00 00 00 00 00
// 0x5000035C  06 00 00 00 50 03 00 50 68 03 00 50
// 0x50000368  07 00 00 00 00 00 00 00 00 00 00 00
// 0x50000374  08 00 00 00 44 03 00 50 a4 03 00 50
// 0x50000380  09 00 00 00 00 00 00 00 00 00 00 00
// 0x5000038C  0a 00 00 00 80 03 00 50 98 03 00 50
// 0x50000398  0b 00 00 00 00 00 00 00 00 00 00 00
// 0x500003A4  0c 00 00 00 8c 03 00 50 bc 03 00 50
// 0x500003B0  0d 00 00 00 00 00 00 00 00 00 00 00
// 0x500003BC  0e 00 00 00 b0 03 00 50 00 00 00 00
// 0x500003C8  00 00 00 00 00 00 00 00 00 00 00 00
// 0x500003D4  0f 00 00 00 74 03 00 50 04 04 00 50
// 0x500003E0  11 00 00 00 00 00 00 00 00 00 00 00
// 0x500003EC  12 00 00 00 e0 03 00 50 f8 03 00 50
// 0x500003F8  13 00 00 00 00 00 00 00 00 00 00 00
// 0x50000404  14 00 00 00 ec 03 00 50 10 04 00 50
// 0x50000410  15 00 00 00 00 00 00 00 00 00 00 00

// Result 
// 0x0047F3C8  01 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F3D4  02 00 00 00 20 03 00 50 38 03 00 50
// 0x0047F3E0  03 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F3EC  04 00 00 00 2c 03 00 50 5c 03 00 50
// 0x0047F3F8  05 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F404  06 00 00 00 50 03 00 50 68 03 00 50
// 0x0047F410  07 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F41C  08 00 00 00 44 03 00 50 a4 03 00 50
// 0x0047F428  09 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F434  0a 00 00 00 80 03 00 50 98 03 00 50
// 0x0047F440  0b 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F44C  0c 00 00 00 8c 03 00 50 bc 03 00 50
// 0x0047F458  0d 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F464  0e 00 00 00 b0 03 00 50 00 00 00 00
// 0x0047F470  00 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F47C  0f 00 00 00 74 03 00 50 04 04 00 50
// 0x0047F488  11 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F494  12 00 00 00 e0 03 00 50 f8 03 00 50
// 0x0047F4A0  13 00 00 00 00 00 00 00 00 00 00 00
// 0x0047F4AC  14 00 00 00 ec 03 00 50 10 04 00 50
// 0x0047F4B8  15 00 00 00 00 00 00 00 00 00 00 00


    //Binary tree Remove
    //remove_root (Binary_node &sub_root)
    //pre: sub_root is either NULL or points to a subtree if the Search_tree. 
    //post:if sub_root is NULL , a code of not_present is returned , Otherwise , the root of the subtree is removed in such a way that the properties of a binary
    //search tree are preserved. The parameter sub_root is reset as the root of the root of the modified subtree,and success is returned
    //if (sub_root == NULL) return not_present;
    //binary_node<Record> * to_delete = sub_root;
    //sub_root 相当于父结点的左(或右)指针
    //if (sub_root->right == NULL) sub_root = sub_root->left ;       //父结点的左(或右)指针指向下一个从而完成删除
    //else if (sub_root->left == NULL) sub_root = sub_root->right;
    //else{
    //     to_delete = sub_root->left ;
    //     Binary_node<Record> * parent = sub_root;
    //     while(to_delete->right != NULL){
    //        parent = to_delete ;
    //        to_delete = to_delete->right;
    //     }
    //     sub_root->data = to_delete->data ;
    //     if(parent == sub_root) sub_root->left = to_delete->left
    //     else  parent->right = to_delete->left;
    //}
    //delete to_delete;
    //return success

    //eax = &sub_root
    _asm{
        mov  eax ,0x500003D4    //root
        push ebx   //used to to_delete
        push ecx   //used to parent
        push edx
        cmp  eax , 0
        jz   REMOVE_ROOT_RETRUN
        mov  ebx , eax    // to_delete = sub_root;
        cmp  [eax+0x8] , 0   //right == NULL
        jne  LEFT_SR
        mov  eax, [eax+0x4]  //sub_root = sub_root->left;
LEFT_SR: cmp  [eax+0x4] , 0   //left == NULL
         jne  NOEMPTY
         mov  eax, [eax+0x8]  //sub_root = sub_root->right
NOEMPTY: mov  ebx, [eax+0x4]; //Move left to find predecessor
         mov  ecx , eax       //parent = sub_root;
FIND_RIGHT_MAX:               //while(to_delete->rgiht != NULL)
         cmp  [ebx+0x8] , 0                                             //while 条件判断语句
         jz   WHILE_END_SR                                              //不成立退出
         mov  ecx , ebx       //parent = to_delete;                     //循环体
         mov  ebx , [ebx+0x8] //to_delete = to_delete->right
         jmp  FIND_RIGHT_MAX                                            //jmp 判断
WHILE_END_SR:                 //end loop
         mov  edx, [ebx]      //edx = to_delete->data;
         mov  [eax],edx       //sub_root->data = to_delete->data;
         cmp  ecx , eax       //parent == sub_root
         jne  ELSE
         mov  edx, [ebx+0x4] //edx = to_delete->left
         mov  [eax+0x4],edx  //sub_root->left = to_delete_left
         jmp  DO_DELETE 
ELSE:    mov  edx ,[ebx+0x4] //edx = to_delete->left
         mov  [ecx+0x8],edx  //parent->right = to_delete->left
DO_DELETE:mov  dword ptr [ebx],0
          mov  dword ptr [ebx+0x4],0
          mov  dword ptr [ebx+0x8],0
REMOVE_ROOT_RETRUN:
         pop  edx
         pop  ecx
         pop  eax
    }
}