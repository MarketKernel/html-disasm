
//  .NET IL Disassembler.  Version 10.0.8


// warning : THIS IS A PARTIAL DISASSEMBLY, NOT SUITABLE FOR RE-ASSEMBLING



// Metadata version: v4.0.30319
.module extern libc
.assembly extern System.Runtime
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 10:0:0:0
}
.assembly extern System.Collections
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 10:0:0:0
}
.assembly extern System.Console
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 10:0:0:0
}
.assembly extern System.Threading
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 10:0:0:0
}
.assembly hello
{
  .permissionset reqmin
             = {[System.Runtime]System.Security.Permissions.SecurityPermissionAttribute = {property bool 'SkipVerification' = bool(true)}}
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module hello.dll
// MVID: {c98d18c9-0bff-4f95-95f2-0db564e26caa}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x0x100c5c000


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi sealed Hello.Kind
       extends [System.Runtime]System.Enum
{
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype Hello.Kind Small = int32(0x00000000)
  .field public static literal valuetype Hello.Kind Medium = int32(0x00000001)
  .field public static literal valuetype Hello.Kind Large = int32(0x00000002)
} // end of class Hello.Kind

.class public sequential ansi sealed beforefieldinit Hello.Point
       extends [System.Runtime]System.ValueType
{
  .field public int32 X
  .field public int32 Y
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(int32 x,
                               int32 y) cil managed
  // SIG: 20 02 01 08 08
  {
    // Method begins at RVA 0x2050
    // Code size       15 (0xf)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 7D   | (04)000005       */ stfld      int32 Hello.Point::X
    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 04   |                  */ ldarg.2
    IL_0009:  /* 7D   | (04)000006       */ stfld      int32 Hello.Point::Y
    IL_000e:  /* 2A   |                  */ ret
  } // end of method Point::.ctor

  .method public hidebysig specialname instance int64 
          get_Length2() cil managed
  // SIG: 20 00 0A
  {
    // Method begins at RVA 0x2060
    // Code size       32 (0x20)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 7B   | (04)000005       */ ldfld      int32 Hello.Point::X
    IL_0006:  /* 6A   |                  */ conv.i8
    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 7B   | (04)000005       */ ldfld      int32 Hello.Point::X
    IL_000d:  /* 6A   |                  */ conv.i8
    IL_000e:  /* 5A   |                  */ mul
    IL_000f:  /* 02   |                  */ ldarg.0
    IL_0010:  /* 7B   | (04)000006       */ ldfld      int32 Hello.Point::Y
    IL_0015:  /* 6A   |                  */ conv.i8
    IL_0016:  /* 02   |                  */ ldarg.0
    IL_0017:  /* 7B   | (04)000006       */ ldfld      int32 Hello.Point::Y
    IL_001c:  /* 6A   |                  */ conv.i8
    IL_001d:  /* 5A   |                  */ mul
    IL_001e:  /* 58   |                  */ add
    IL_001f:  /* 2A   |                  */ ret
  } // end of method Point::get_Length2

  .property instance callconv(8) int64 Length2()
  {
    .get instance int64 Hello.Point::get_Length2()
  } // end of property Point::Length2
} // end of class Hello.Point

.class public abstract auto ansi sealed beforefieldinit Hello.Program
       extends [System.Runtime]System.Object
{
  .class auto ansi serializable sealed nested private beforefieldinit '<>c'
         extends [System.Runtime]System.Object
  {
    .field public static initonly class Hello.Program/'<>c' '<>9'
    .field public static class [System.Runtime]System.Func`2<int32,int32> '<>9__6_0'
    .method private hidebysig specialname rtspecialname static 
            void  .cctor() cil managed
    // SIG: 00 00 01
    {
      // Method begins at RVA 0x29d1
      // Code size       11 (0xb)
      .maxstack  8
      IL_0000:  /* 73   | (06)000031       */ newobj     instance void Hello.Program/'<>c'::.ctor()
      IL_0005:  /* 80   | (04)00000D       */ stsfld     class Hello.Program/'<>c' Hello.Program/'<>c'::'<>9'
      IL_000a:  /* 2A   |                  */ ret
    } // end of method '<>c'::.cctor

    .method public hidebysig specialname rtspecialname 
            instance void  .ctor() cil managed
    // SIG: 20 00 01
    {
      // Method begins at RVA 0x29dd
      // Code size       7 (0x7)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 28   | (0A)00003E       */ call       instance void [System.Runtime]System.Object::.ctor()
      IL_0006:  /* 2A   |                  */ ret
    } // end of method '<>c'::.ctor

    .method assembly hidebysig instance int32 
            '<Main>b__6_0'(int32 x) cil managed
    // SIG: 20 01 08 08
    {
      // Method begins at RVA 0x29e5
      // Code size       4 (0x4)
      .maxstack  8
      IL_0000:  /* 03   |                  */ ldarg.1
      IL_0001:  /* 18   |                  */ ldc.i4.2
      IL_0002:  /* 5A   |                  */ mul
      IL_0003:  /* 2A   |                  */ ret
    } // end of method '<>c'::'<Main>b__6_0'

  } // end of class '<>c'

  .class auto ansi sealed nested private beforefieldinit '<CountAsync>d__5'
         extends [System.Runtime]System.ValueType
         implements [System.Runtime]System.Runtime.CompilerServices.IAsyncStateMachine
  {
    .field public int32 '<>1__state'
    .field public valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> '<>t__builder'
    .field public int32 n
    .field private valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter '<>u__1'
    .method private hidebysig newslot virtual final 
            instance void  MoveNext() cil managed
    // SIG: 20 00 01
    {
      .override [System.Runtime]System.Runtime.CompilerServices.IAsyncStateMachine::MoveNext
      // Method begins at RVA 0x29ec
      // Code size       157 (0x9d)
      .maxstack  3
      .locals init (int32 V_0,
               int32 V_1,
               valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter V_2,
               valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable V_3,
               class [System.Runtime]System.Exception V_4)
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7B   | (04)00000F       */ ldfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
      IL_0006:  /* 0A   |                  */ stloc.0
      .try
      {
        IL_0007:  /* 06   |                  */ ldloc.0
        IL_0008:  /* 2C   | 37               */ brfalse.s  IL_0041

        IL_000a:  /* 28   | (0A)000063       */ call       valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable [System.Runtime]System.Threading.Tasks.Task::Yield()
        IL_000f:  /* 0D   |                  */ stloc.3
        IL_0010:  /* 12   | 03               */ ldloca.s   V_3
        IL_0012:  /* 28   | (0A)000064       */ call       instance valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable::GetAwaiter()
        IL_0017:  /* 0C   |                  */ stloc.2
        IL_0018:  /* 12   | 02               */ ldloca.s   V_2
        IL_001a:  /* 28   | (0A)000065       */ call       instance bool [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter::get_IsCompleted()
        IL_001f:  /* 2D   | 3C               */ brtrue.s   IL_005d

        IL_0021:  /* 02   |                  */ ldarg.0
        IL_0022:  /* 16   |                  */ ldc.i4.0
        IL_0023:  /* 25   |                  */ dup
        IL_0024:  /* 0A   |                  */ stloc.0
        IL_0025:  /* 7D   | (04)00000F       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
        IL_002a:  /* 02   |                  */ ldarg.0
        IL_002b:  /* 08   |                  */ ldloc.2
        IL_002c:  /* 7D   | (04)000012       */ stfld      valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter Hello.Program/'<CountAsync>d__5'::'<>u__1'
        IL_0031:  /* 02   |                  */ ldarg.0
        IL_0032:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
        IL_0037:  /* 12   | 02               */ ldloca.s   V_2
        IL_0039:  /* 02   |                  */ ldarg.0
        IL_003a:  /* 28   | (2B)000006       */ call       instance void valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::AwaitUnsafeOnCompleted<valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter,valuetype Hello.Program/'<CountAsync>d__5'>(!!0&,
                                                                                                                                                                                                                                                                                                                             !!1&)
        IL_003f:  /* DE   | 5B               */ leave.s    IL_009c

        IL_0041:  /* 02   |                  */ ldarg.0
        IL_0042:  /* 7B   | (04)000012       */ ldfld      valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter Hello.Program/'<CountAsync>d__5'::'<>u__1'
        IL_0047:  /* 0C   |                  */ stloc.2
        IL_0048:  /* 02   |                  */ ldarg.0
        IL_0049:  /* 7C   | (04)000012       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter Hello.Program/'<CountAsync>d__5'::'<>u__1'
        IL_004e:  /* FE15 | (01)000023       */ initobj    [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter
        IL_0054:  /* 02   |                  */ ldarg.0
        IL_0055:  /* 15   |                  */ ldc.i4.m1
        IL_0056:  /* 25   |                  */ dup
        IL_0057:  /* 0A   |                  */ stloc.0
        IL_0058:  /* 7D   | (04)00000F       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
        IL_005d:  /* 12   | 02               */ ldloca.s   V_2
        IL_005f:  /* 28   | (0A)000067       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.YieldAwaitable/YieldAwaiter::GetResult()
        IL_0064:  /* 02   |                  */ ldarg.0
        IL_0065:  /* 7B   | (04)000011       */ ldfld      int32 Hello.Program/'<CountAsync>d__5'::n
        IL_006a:  /* 18   |                  */ ldc.i4.2
        IL_006b:  /* 5A   |                  */ mul
        IL_006c:  /* 0B   |                  */ stloc.1
        IL_006d:  /* DE   | 19               */ leave.s    IL_0088

      }  // end .try
      catch [System.Runtime]System.Exception 
      {
        IL_006f:  /* 13   | 04               */ stloc.s    V_4
        IL_0071:  /* 02   |                  */ ldarg.0
        IL_0072:  /* 1F   | FE               */ ldc.i4.s   -2
        IL_0074:  /* 7D   | (04)00000F       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
        IL_0079:  /* 02   |                  */ ldarg.0
        IL_007a:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
        IL_007f:  /* 11   | 04               */ ldloc.s    V_4
        IL_0081:  /* 28   | (0A)000068       */ call       instance void valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::SetException(class [System.Runtime]System.Exception)
        IL_0086:  /* DE   | 14               */ leave.s    IL_009c

      }  // end handler
      // HEX: 00 00 07 00 68 6F 00 19 24 00 00 01
      IL_0088:  /* 02   |                  */ ldarg.0
      IL_0089:  /* 1F   | FE               */ ldc.i4.s   -2
      IL_008b:  /* 7D   | (04)00000F       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
      IL_0090:  /* 02   |                  */ ldarg.0
      IL_0091:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
      IL_0096:  /* 07   |                  */ ldloc.1
      IL_0097:  /* 28   | (0A)000069       */ call       instance void valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::SetResult(!0)
      IL_009c:  /* 2A   |                  */ ret
    } // end of method '<CountAsync>d__5'::MoveNext

    .method private hidebysig newslot virtual final 
            instance void  SetStateMachine(class [System.Runtime]System.Runtime.CompilerServices.IAsyncStateMachine stateMachine) cil managed
    // SIG: 20 01 01 12 80 85
    {
      .override [System.Runtime]System.Runtime.CompilerServices.IAsyncStateMachine::SetStateMachine
      // Method begins at RVA 0x2aa8
      // Code size       13 (0xd)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
      IL_0006:  /* 03   |                  */ ldarg.1
      IL_0007:  /* 28   | (0A)00006A       */ call       instance void valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::SetStateMachine(class [System.Runtime]System.Runtime.CompilerServices.IAsyncStateMachine)
      IL_000c:  /* 2A   |                  */ ret
    } // end of method '<CountAsync>d__5'::SetStateMachine

  } // end of class '<CountAsync>d__5'

  .method private hidebysig static int64 
          Sum(int32[] values,
              int32 count) cil managed
  // SIG: 00 02 0A 1D 08 08
  {
    // Method begins at RVA 0x2084
    // Code size       24 (0x18)
    .maxstack  3
    .locals init (int64 V_0,
             int32 V_1)
    IL_0000:  /* 16   |                  */ ldc.i4.0
    IL_0001:  /* 6A   |                  */ conv.i8
    IL_0002:  /* 0A   |                  */ stloc.0
    IL_0003:  /* 16   |                  */ ldc.i4.0
    IL_0004:  /* 0B   |                  */ stloc.1
    IL_0005:  /* 2B   | 0B               */ br.s       IL_0012

    IL_0007:  /* 06   |                  */ ldloc.0
    IL_0008:  /* 02   |                  */ ldarg.0
    IL_0009:  /* 07   |                  */ ldloc.1
    IL_000a:  /* 94   |                  */ ldelem.i4
    IL_000b:  /* 6A   |                  */ conv.i8
    IL_000c:  /* 58   |                  */ add
    IL_000d:  /* 0A   |                  */ stloc.0
    IL_000e:  /* 07   |                  */ ldloc.1
    IL_000f:  /* 17   |                  */ ldc.i4.1
    IL_0010:  /* 58   |                  */ add
    IL_0011:  /* 0B   |                  */ stloc.1
    IL_0012:  /* 07   |                  */ ldloc.1
    IL_0013:  /* 03   |                  */ ldarg.1
    IL_0014:  /* 32   | F1               */ blt.s      IL_0007

    IL_0016:  /* 06   |                  */ ldloc.0
    IL_0017:  /* 2A   |                  */ ret
  } // end of method Program::Sum

  .method private hidebysig static string 
          KindOf(int64 sum) cil managed
  // SIG: 00 01 0E 0A
  {
    // Method begins at RVA 0x20a8
    // Code size       66 (0x42)
    .maxstack  3
    .locals init (string V_0,
             int64 V_1)
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 1A   |                  */ ldc.i4.4
    IL_0002:  /* 6A   |                  */ conv.i8
    IL_0003:  /* 5D   |                  */ rem
    IL_0004:  /* 0B   |                  */ stloc.1
    IL_0005:  /* 07   |                  */ ldloc.1
    IL_0006:  /* 25   |                  */ dup
    IL_0007:  /* 18   |                  */ ldc.i4.2
    IL_0008:  /* 6A   |                  */ conv.i8
    IL_0009:  /* 36   | 03               */ ble.un.s   IL_000e

    IL_000b:  /* 26   |                  */ pop
    IL_000c:  /* 2B   | 2C               */ br.s       IL_003a

    IL_000e:  /* 6D   |                  */ conv.u4
    IL_000f:  /* 45   | 00000003         */ switch     ( 
              /*      | 00000002         */             IL_0022,
              /*      | 0000000A         */             IL_002a,
              /*      | 00000012         */             IL_0032)
    IL_0020:  /* 2B   | 18               */ br.s       IL_003a

    IL_0022:  /* 72   | (70)000001       */ ldstr      "zero"
    IL_0027:  /* 0A   |                  */ stloc.0
    IL_0028:  /* 2B   | 16               */ br.s       IL_0040

    IL_002a:  /* 72   | (70)00000B       */ ldstr      "one"
    IL_002f:  /* 0A   |                  */ stloc.0
    IL_0030:  /* 2B   | 0E               */ br.s       IL_0040

    IL_0032:  /* 72   | (70)000013       */ ldstr      "two"
    IL_0037:  /* 0A   |                  */ stloc.0
    IL_0038:  /* 2B   | 06               */ br.s       IL_0040

    IL_003a:  /* 72   | (70)00001B       */ ldstr      "many"
    IL_003f:  /* 0A   |                  */ stloc.0
    IL_0040:  /* 06   |                  */ ldloc.0
    IL_0041:  /* 2A   |                  */ ret
  } // end of method Program::KindOf

  .method private hidebysig static valuetype Hello.Kind 
          Classify(float64 'value') cil managed
  // SIG: 00 01 11 08 0D
  {
    // Method begins at RVA 0x20f6
    // Code size       30 (0x1e)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 23   | 3FF8000000000000 */ ldc.r8     1.5
    IL_000a:  /* 34   | 02               */ bge.un.s   IL_000e

    IL_000c:  /* 16   |                  */ ldc.i4.0
    IL_000d:  /* 2A   |                  */ ret

    IL_000e:  /* 02   |                  */ ldarg.0
    IL_000f:  /* 23   | 4059100000000000 */ ldc.r8     100.25
    IL_0018:  /* 35   | 02               */ bgt.un.s   IL_001c

    IL_001a:  /* 17   |                  */ ldc.i4.1
    IL_001b:  /* 2A   |                  */ ret

    IL_001c:  /* 18   |                  */ ldc.i4.2
    IL_001d:  /* 2A   |                  */ ret
  } // end of method Program::Classify

  .method private hidebysig static int32 
          Checksum(uint8[] data) cil managed
  // SIG: 00 01 08 1D 05
  {
    // Method begins at RVA 0x2118
    // Code size       53 (0x35)
    .maxstack  3
    .locals init (int32 V_0,
             uint8* V_1,
             uint8[] pinned V_2,
             int32 V_3)
    IL_0000:  /* 16   |                  */ ldc.i4.0
    IL_0001:  /* 0A   |                  */ stloc.0
    IL_0002:  /* 02   |                  */ ldarg.0
    IL_0003:  /* 25   |                  */ dup
    IL_0004:  /* 0C   |                  */ stloc.2
    IL_0005:  /* 2C   | 05               */ brfalse.s  IL_000c

    IL_0007:  /* 08   |                  */ ldloc.2
    IL_0008:  /* 8E   |                  */ ldlen
    IL_0009:  /* 69   |                  */ conv.i4
    IL_000a:  /* 2D   | 05               */ brtrue.s   IL_0011

    IL_000c:  /* 16   |                  */ ldc.i4.0
    IL_000d:  /* E0   |                  */ conv.u
    IL_000e:  /* 0B   |                  */ stloc.1
    IL_000f:  /* 2B   | 09               */ br.s       IL_001a

    IL_0011:  /* 08   |                  */ ldloc.2
    IL_0012:  /* 16   |                  */ ldc.i4.0
    IL_0013:  /* 8F   | (01)000036       */ ldelema    [System.Runtime]System.Byte
    IL_0018:  /* E0   |                  */ conv.u
    IL_0019:  /* 0B   |                  */ stloc.1
    IL_001a:  /* 16   |                  */ ldc.i4.0
    IL_001b:  /* 0D   |                  */ stloc.3
    IL_001c:  /* 2B   | 0D               */ br.s       IL_002b

    IL_001e:  /* 06   |                  */ ldloc.0
    IL_001f:  /* 17   |                  */ ldc.i4.1
    IL_0020:  /* 62   |                  */ shl
    IL_0021:  /* 07   |                  */ ldloc.1
    IL_0022:  /* 09   |                  */ ldloc.3
    IL_0023:  /* 58   |                  */ add
    IL_0024:  /* 47   |                  */ ldind.u1
    IL_0025:  /* 61   |                  */ xor
    IL_0026:  /* 0A   |                  */ stloc.0
    IL_0027:  /* 09   |                  */ ldloc.3
    IL_0028:  /* 17   |                  */ ldc.i4.1
    IL_0029:  /* 58   |                  */ add
    IL_002a:  /* 0D   |                  */ stloc.3
    IL_002b:  /* 09   |                  */ ldloc.3
    IL_002c:  /* 02   |                  */ ldarg.0
    IL_002d:  /* 8E   |                  */ ldlen
    IL_002e:  /* 69   |                  */ conv.i4
    IL_002f:  /* 32   | ED               */ blt.s      IL_001e

    IL_0031:  /* 14   |                  */ ldnull
    IL_0032:  /* 0C   |                  */ stloc.2
    IL_0033:  /* 06   |                  */ ldloc.0
    IL_0034:  /* 2A   |                  */ ret
  } // end of method Program::Checksum

  .method private hidebysig static !!T  Largest<(class [System.Runtime]System.IComparable`1<!!T>) T>(class [System.Collections]System.Collections.Generic.List`1<!!T> items) cil managed
  // SIG: 10 01 01 1E 00 15 12 5D 01 1E 00
  {
    // Method begins at RVA 0x215c
    // Code size       71 (0x47)
    .maxstack  2
    .locals init (!!T V_0,
             valuetype [System.Collections]System.Collections.Generic.List`1/Enumerator<!!T> V_1,
             !!T V_2)
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 16   |                  */ ldc.i4.0
    IL_0002:  /* 6F   | (0A)00001F       */ callvirt   instance !0 class [System.Collections]System.Collections.Generic.List`1<!!T>::get_Item(int32)
    IL_0007:  /* 0A   |                  */ stloc.0
    IL_0008:  /* 02   |                  */ ldarg.0
    IL_0009:  /* 6F   | (0A)000020       */ callvirt   instance valuetype [System.Collections]System.Collections.Generic.List`1/Enumerator<!0> class [System.Collections]System.Collections.Generic.List`1<!!T>::GetEnumerator()
    IL_000e:  /* 0B   |                  */ stloc.1
    .try
    {
      IL_000f:  /* 2B   | 1B               */ br.s       IL_002c

      IL_0011:  /* 12   | 01               */ ldloca.s   V_1
      IL_0013:  /* 28   | (0A)000021       */ call       instance !0 valuetype [System.Collections]System.Collections.Generic.List`1/Enumerator<!!T>::get_Current()
      IL_0018:  /* 0C   |                  */ stloc.2
      IL_0019:  /* 12   | 02               */ ldloca.s   V_2
      IL_001b:  /* 06   |                  */ ldloc.0
      IL_001c:  /* FE16 | (1B)000007       */ constrained. !!T
      IL_0022:  /* 6F   | (0A)000022       */ callvirt   instance int32 class [System.Runtime]System.IComparable`1<!!T>::CompareTo(!0)
      IL_0027:  /* 16   |                  */ ldc.i4.0
      IL_0028:  /* 31   | 02               */ ble.s      IL_002c

      IL_002a:  /* 08   |                  */ ldloc.2
      IL_002b:  /* 0A   |                  */ stloc.0
      IL_002c:  /* 12   | 01               */ ldloca.s   V_1
      IL_002e:  /* 28   | (0A)000023       */ call       instance bool valuetype [System.Collections]System.Collections.Generic.List`1/Enumerator<!!T>::MoveNext()
      IL_0033:  /* 2D   | DC               */ brtrue.s   IL_0011

      IL_0035:  /* DE   | 0E               */ leave.s    IL_0045

    }  // end .try
    finally
    {
      IL_0037:  /* 12   | 01               */ ldloca.s   V_1
      IL_0039:  /* FE16 | (1B)000006       */ constrained. valuetype [System.Collections]System.Collections.Generic.List`1/Enumerator<!!T>
      IL_003f:  /* 6F   | (0A)000018       */ callvirt   instance void [System.Runtime]System.IDisposable::Dispose()
      IL_0044:  /* DC   |                  */ endfinally
    }  // end handler
    // HEX: 02 00 0F 00 28 37 00 0E 00 00 00 00
    IL_0045:  /* 06   |                  */ ldloc.0
    IL_0046:  /* 2A   |                  */ ret
  } // end of method Program::Largest

  .method private hidebysig static class [System.Runtime]System.Threading.Tasks.Task`1<int32> 
          CountAsync(int32 n) cil managed
  // SIG: 00 01 15 12 6D 01 08 08
  {
    // Method begins at RVA 0x21c0
    // Code size       55 (0x37)
    .maxstack  2
    .locals init (valuetype Hello.Program/'<CountAsync>d__5' V_0)
    IL_0000:  /* 12   | 00               */ ldloca.s   V_0
    IL_0002:  /* 28   | (0A)000024       */ call       valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<!0> valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::Create()
    IL_0007:  /* 7D   | (04)000010       */ stfld      valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
    IL_000c:  /* 12   | 00               */ ldloca.s   V_0
    IL_000e:  /* 02   |                  */ ldarg.0
    IL_000f:  /* 7D   | (04)000011       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::n
    IL_0014:  /* 12   | 00               */ ldloca.s   V_0
    IL_0016:  /* 15   |                  */ ldc.i4.m1
    IL_0017:  /* 7D   | (04)00000F       */ stfld      int32 Hello.Program/'<CountAsync>d__5'::'<>1__state'
    IL_001c:  /* 12   | 00               */ ldloca.s   V_0
    IL_001e:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
    IL_0023:  /* 12   | 00               */ ldloca.s   V_0
    IL_0025:  /* 28   | (2B)000001       */ call       instance void valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::Start<valuetype Hello.Program/'<CountAsync>d__5'>(!!0&)
    IL_002a:  /* 12   | 00               */ ldloca.s   V_0
    IL_002c:  /* 7C   | (04)000010       */ ldflda     valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32> Hello.Program/'<CountAsync>d__5'::'<>t__builder'
    IL_0031:  /* 28   | (0A)000026       */ call       instance class [System.Runtime]System.Threading.Tasks.Task`1<!0> valuetype [System.Runtime]System.Runtime.CompilerServices.AsyncTaskMethodBuilder`1<int32>::get_Task()
    IL_0036:  /* 2A   |                  */ ret
  } // end of method Program::CountAsync

  .method public hidebysig static int32  Main(string[] args) cil managed
  // SIG: 00 01 08 1D 0E
  {
    .entrypoint
    // Method begins at RVA 0x2204
    // Code size       443 (0x1bb)
    .maxstack  6
    .locals init (int32[] V_0,
             int64 V_1,
             float64 V_2,
             valuetype Hello.Point V_3,
             class [System.Runtime]System.Func`2<int32,int32> V_4,
             class [System.Collections]System.Collections.Generic.List`1<string> V_5,
             valuetype [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler V_6,
             class [System.Runtime]System.FormatException V_7,
             int64 V_8,
             int32 V_9,
             valuetype [System.Runtime]System.Runtime.CompilerServices.TaskAwaiter`1<int32> V_10)
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 8E   |                  */ ldlen
    IL_0002:  /* 2C   | 1B               */ brfalse.s  IL_001f

    IL_0004:  /* 02   |                  */ ldarg.0
    IL_0005:  /* 16   |                  */ ldc.i4.0
    IL_0006:  /* 9A   |                  */ ldelem.ref
    IL_0007:  /* 72   | (70)000025       */ ldstr      "--help"
    IL_000c:  /* 28   | (0A)000027       */ call       bool [System.Runtime]System.String::op_Equality(string,
                                                                                                       string)
    IL_0011:  /* 2C   | 0C               */ brfalse.s  IL_001f

    IL_0013:  /* 72   | (70)000033       */ ldstr      "usage: hello [numbers...]"
    IL_0018:  /* 28   | (0A)000028       */ call       void [System.Console]System.Console::WriteLine(string)
    IL_001d:  /* 16   |                  */ ldc.i4.0
    IL_001e:  /* 2A   |                  */ ret

    IL_001f:  /* 1E   |                  */ ldc.i4.8
    IL_0020:  /* 8D   | (01)000039       */ newarr     [System.Runtime]System.Int32
    IL_0025:  /* 25   |                  */ dup
    IL_0026:  /* D0   | (04)00000C       */ ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=32' '<PrivateImplementationDetails>'::'8B4B2444E57AED8C2D05A1293255DA1B048C63224317D4666230760935FA4A18'
    IL_002b:  /* 28   | (0A)000029       */ call       void [System.Runtime]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [System.Runtime]System.Array,
                                                                                                                                            valuetype [System.Runtime]System.RuntimeFieldHandle)
    IL_0030:  /* 0A   |                  */ stloc.0
    IL_0031:  /* 06   |                  */ ldloc.0
    IL_0032:  /* 06   |                  */ ldloc.0
    IL_0033:  /* 8E   |                  */ ldlen
    IL_0034:  /* 69   |                  */ conv.i4
    IL_0035:  /* 28   | (06)000003       */ call       int64 Hello.Program::Sum(int32[],
                                                                                int32)
    IL_003a:  /* 0B   |                  */ stloc.1
    IL_003b:  /* 07   |                  */ ldloc.1
    IL_003c:  /* 6C   |                  */ conv.r8
    IL_003d:  /* 06   |                  */ ldloc.0
    IL_003e:  /* 8E   |                  */ ldlen
    IL_003f:  /* 69   |                  */ conv.i4
    IL_0040:  /* 6C   |                  */ conv.r8
    IL_0041:  /* 5B   |                  */ div
    IL_0042:  /* 0C   |                  */ stloc.2
    IL_0043:  /* 12   | 06               */ ldloca.s   V_6
    IL_0045:  /* 1F   | 1D               */ ldc.i4.s   29
    IL_0047:  /* 19   |                  */ ldc.i4.3
    IL_0048:  /* 28   | (0A)00002A       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::.ctor(int32,
                                                                                                                                                             int32)
    IL_004d:  /* 12   | 06               */ ldloca.s   V_6
    IL_004f:  /* 72   | (70)000067       */ ldstr      "Hello, world! sum="
    IL_0054:  /* 28   | (0A)00002B       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendLiteral(string)
    IL_0059:  /* 12   | 06               */ ldloca.s   V_6
    IL_005b:  /* 07   |                  */ ldloc.1
    IL_005c:  /* 28   | (2B)000002       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendFormatted<int64>(!!0)
    IL_0061:  /* 12   | 06               */ ldloca.s   V_6
    IL_0063:  /* 72   | (70)00008D       */ ldstr      " avg="
    IL_0068:  /* 28   | (0A)00002B       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendLiteral(string)
    IL_006d:  /* 12   | 06               */ ldloca.s   V_6
    IL_006f:  /* 08   |                  */ ldloc.2
    IL_0070:  /* 72   | (70)000099       */ ldstr      "F2"
    IL_0075:  /* 28   | (2B)000003       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendFormatted<float64>(!!0,
                                                                                                                                                                                string)
    IL_007a:  /* 12   | 06               */ ldloca.s   V_6
    IL_007c:  /* 72   | (70)00009F       */ ldstr      " kind="
    IL_0081:  /* 28   | (0A)00002B       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendLiteral(string)
    IL_0086:  /* 12   | 06               */ ldloca.s   V_6
    IL_0088:  /* 07   |                  */ ldloc.1
    IL_0089:  /* 28   | (06)000004       */ call       string Hello.Program::KindOf(int64)
    IL_008e:  /* 28   | (0A)00002E       */ call       instance void [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendFormatted(string)
    IL_0093:  /* 12   | 06               */ ldloca.s   V_6
    IL_0095:  /* 28   | (0A)00002F       */ call       instance string [System.Runtime]System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::ToStringAndClear()
    IL_009a:  /* 28   | (0A)000028       */ call       void [System.Console]System.Console::WriteLine(string)
    IL_009f:  /* 12   | 03               */ ldloca.s   V_3
    IL_00a1:  /* 19   |                  */ ldc.i4.3
    IL_00a2:  /* 1A   |                  */ ldc.i4.4
    IL_00a3:  /* 28   | (06)000001       */ call       instance void Hello.Point::.ctor(int32,
                                                                                        int32)
    IL_00a8:  /* 7E   | (04)00000E       */ ldsfld     class [System.Runtime]System.Func`2<int32,int32> Hello.Program/'<>c'::'<>9__6_0'
    IL_00ad:  /* 25   |                  */ dup
    IL_00ae:  /* 2D   | 17               */ brtrue.s   IL_00c7

    IL_00b0:  /* 26   |                  */ pop
    IL_00b1:  /* 7E   | (04)00000D       */ ldsfld     class Hello.Program/'<>c' Hello.Program/'<>c'::'<>9'
    IL_00b6:  /* FE06 | (06)000032       */ ldftn      instance int32 Hello.Program/'<>c'::'<Main>b__6_0'(int32)
    IL_00bc:  /* 73   | (0A)000030       */ newobj     instance void class [System.Runtime]System.Func`2<int32,int32>::.ctor(object,
                                                                                                                             native int)
    IL_00c1:  /* 25   |                  */ dup
    IL_00c2:  /* 80   | (04)00000E       */ stsfld     class [System.Runtime]System.Func`2<int32,int32> Hello.Program/'<>c'::'<>9__6_0'
    IL_00c7:  /* 13   | 04               */ stloc.s    V_4
    .try
    {
      .try
      {
        IL_00c9:  /* 07   |                  */ ldloc.1
        IL_00ca:  /* 11   | 04               */ ldloc.s    V_4
        IL_00cc:  /* 09   |                  */ ldloc.3
        IL_00cd:  /* 7B   | (04)000005       */ ldfld      int32 Hello.Point::X
        IL_00d2:  /* 6F   | (0A)000031       */ callvirt   instance !1 class [System.Runtime]System.Func`2<int32,int32>::Invoke(!0)
        IL_00d7:  /* 02   |                  */ ldarg.0
        IL_00d8:  /* 8E   |                  */ ldlen
        IL_00d9:  /* 69   |                  */ conv.i4
        IL_00da:  /* 17   |                  */ ldc.i4.1
        IL_00db:  /* 30   | 07               */ bgt.s      IL_00e4

        IL_00dd:  /* 72   | (70)0000AD       */ ldstr      "7"
        IL_00e2:  /* 2B   | 03               */ br.s       IL_00e7

        IL_00e4:  /* 02   |                  */ ldarg.0
        IL_00e5:  /* 17   |                  */ ldc.i4.1
        IL_00e6:  /* 9A   |                  */ ldelem.ref
        IL_00e7:  /* 28   | (0A)000032       */ call       int32 [System.Runtime]System.Int32::Parse(string)
        IL_00ec:  /* D8   |                  */ mul.ovf
        IL_00ed:  /* 6A   |                  */ conv.i8
        IL_00ee:  /* D6   |                  */ add.ovf
        IL_00ef:  /* 0B   |                  */ stloc.1
        IL_00f0:  /* DE   | 26               */ leave.s    IL_0118

      }  // end .try
      catch [System.Runtime]System.FormatException 
      {
        IL_00f2:  /* 13   | 07               */ stloc.s    V_7
        IL_00f4:  /* 28   | (0A)000033       */ call       class [System.Runtime]System.IO.TextWriter [System.Console]System.Console::get_Error()
        IL_00f9:  /* 11   | 07               */ ldloc.s    V_7
        IL_00fb:  /* 6F   | (0A)000034       */ callvirt   instance string [System.Runtime]System.Exception::get_Message()
        IL_0100:  /* 6F   | (0A)000035       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::WriteLine(string)
        IL_0105:  /* DE   | 11               */ leave.s    IL_0118

      }  // end handler
      // HEX: 00 00 C9 00 29 F2 00 15 1E 00 00 01
    }  // end .try
    finally
    {
      IL_0107:  /* 08   |                  */ ldloc.2
      IL_0108:  /* 28   | (06)000005       */ call       valuetype Hello.Kind Hello.Program::Classify(float64)
      IL_010d:  /* 8C   | (02)000002       */ box        Hello.Kind
      IL_0112:  /* 28   | (0A)000036       */ call       void [System.Console]System.Console::WriteLine(object)
      IL_0117:  /* DC   |                  */ endfinally
    }  // end handler
    // HEX: 02 00 C9 00 3E 07 01 11 00 00 00 00
    IL_0118:  /* 73   | (0A)000037       */ newobj     instance void class [System.Collections]System.Collections.Generic.List`1<string>::.ctor()
    IL_011d:  /* 25   |                  */ dup
    IL_011e:  /* 72   | (70)0000B1       */ ldstr      "pear"
    IL_0123:  /* 6F   | (0A)000038       */ callvirt   instance void class [System.Collections]System.Collections.Generic.List`1<string>::Add(!0)
    IL_0128:  /* 25   |                  */ dup
    IL_0129:  /* 72   | (70)0000BB       */ ldstr      "apple"
    IL_012e:  /* 6F   | (0A)000038       */ callvirt   instance void class [System.Collections]System.Collections.Generic.List`1<string>::Add(!0)
    IL_0133:  /* 25   |                  */ dup
    IL_0134:  /* 72   | (70)0000C7       */ ldstr      "fig"
    IL_0139:  /* 6F   | (0A)000038       */ callvirt   instance void class [System.Collections]System.Collections.Generic.List`1<string>::Add(!0)
    IL_013e:  /* 13   | 05               */ stloc.s    V_5
    IL_0140:  /* 1B   |                  */ ldc.i4.5
    IL_0141:  /* 8D   | (01)000037       */ newarr     [System.Runtime]System.String
    IL_0146:  /* 25   |                  */ dup
    IL_0147:  /* 16   |                  */ ldc.i4.0
    IL_0148:  /* 11   | 05               */ ldloc.s    V_5
    IL_014a:  /* 28   | (2B)000004       */ call       !!0 Hello.Program::Largest<string>(class [System.Collections]System.Collections.Generic.List`1<!!0>)
    IL_014f:  /* A2   |                  */ stelem.ref
    IL_0150:  /* 25   |                  */ dup
    IL_0151:  /* 17   |                  */ ldc.i4.1
    IL_0152:  /* 72   | (70)0000CF       */ ldstr      " "
    IL_0157:  /* A2   |                  */ stelem.ref
    IL_0158:  /* 25   |                  */ dup
    IL_0159:  /* 18   |                  */ ldc.i4.2
    IL_015a:  /* 12   | 03               */ ldloca.s   V_3
    IL_015c:  /* 28   | (06)000002       */ call       instance int64 Hello.Point::get_Length2()
    IL_0161:  /* 13   | 08               */ stloc.s    V_8
    IL_0163:  /* 12   | 08               */ ldloca.s   V_8
    IL_0165:  /* 28   | (0A)000039       */ call       instance string [System.Runtime]System.Int64::ToString()
    IL_016a:  /* A2   |                  */ stelem.ref
    IL_016b:  /* 25   |                  */ dup
    IL_016c:  /* 19   |                  */ ldc.i4.3
    IL_016d:  /* 72   | (70)0000CF       */ ldstr      " "
    IL_0172:  /* A2   |                  */ stelem.ref
    IL_0173:  /* 25   |                  */ dup
    IL_0174:  /* 1A   |                  */ ldc.i4.4
    IL_0175:  /* 19   |                  */ ldc.i4.3
    IL_0176:  /* 8D   | (01)000036       */ newarr     [System.Runtime]System.Byte
    IL_017b:  /* 25   |                  */ dup
    IL_017c:  /* D0   | (04)00000B       */ ldtoken    field valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=3' '<PrivateImplementationDetails>'::'039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81'
    IL_0181:  /* 28   | (0A)000029       */ call       void [System.Runtime]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [System.Runtime]System.Array,
                                                                                                                                            valuetype [System.Runtime]System.RuntimeFieldHandle)
    IL_0186:  /* 28   | (06)000006       */ call       int32 Hello.Program::Checksum(uint8[])
    IL_018b:  /* 13   | 09               */ stloc.s    V_9
    IL_018d:  /* 12   | 09               */ ldloca.s   V_9
    IL_018f:  /* 28   | (0A)00003A       */ call       instance string [System.Runtime]System.Int32::ToString()
    IL_0194:  /* A2   |                  */ stelem.ref
    IL_0195:  /* 28   | (0A)00003B       */ call       string [System.Runtime]System.String::Concat(string[])
    IL_019a:  /* 28   | (0A)000028       */ call       void [System.Console]System.Console::WriteLine(string)
    IL_019f:  /* 07   |                  */ ldloc.1
    IL_01a0:  /* 69   |                  */ conv.i4
    IL_01a1:  /* 28   | (06)000008       */ call       class [System.Runtime]System.Threading.Tasks.Task`1<int32> Hello.Program::CountAsync(int32)
    IL_01a6:  /* 6F   | (0A)00003C       */ callvirt   instance valuetype [System.Runtime]System.Runtime.CompilerServices.TaskAwaiter`1<!0> class [System.Runtime]System.Threading.Tasks.Task`1<int32>::GetAwaiter()
    IL_01ab:  /* 13   | 0A               */ stloc.s    V_10
    IL_01ad:  /* 12   | 0A               */ ldloca.s   V_10
    IL_01af:  /* 28   | (0A)00003D       */ call       instance !0 valuetype [System.Runtime]System.Runtime.CompilerServices.TaskAwaiter`1<int32>::GetResult()
    IL_01b4:  /* 16   |                  */ ldc.i4.0
    IL_01b5:  /* FE02 |                  */ cgt
    IL_01b7:  /* 16   |                  */ ldc.i4.0
    IL_01b8:  /* FE01 |                  */ ceq
    IL_01ba:  /* 2A   |                  */ ret
  } // end of method Program::Main

} // end of class Hello.Program

.class public auto ansi sealed beforefieldinit Hello.More.Box`1<valuetype .ctor ([System.Runtime]System.ValueType) T>
       extends [System.Runtime]System.Object
{
  .field private !T 'value'
  .field private static int32 created
  .field public int32 modreq([System.Runtime]System.Runtime.CompilerServices.IsVolatile) Version
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(!T 'value') cil managed
  // SIG: 20 01 01 13 00
  {
    // Method begins at RVA 0x23e8
    // Code size       25 (0x19)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 28   | (0A)00003E       */ call       instance void [System.Runtime]System.Object::.ctor()
    IL_0006:  /* 02   |                  */ ldarg.0
    IL_0007:  /* 03   |                  */ ldarg.1
    IL_0008:  /* 7D   | (0A)00003F       */ stfld      !0 class Hello.More.Box`1<!T>::'value'
    IL_000d:  /* 7F   | (0A)000040       */ ldsflda    int32 class Hello.More.Box`1<!T>::created
    IL_0012:  /* 28   | (0A)000041       */ call       int32 [System.Threading]System.Threading.Interlocked::Increment(int32&)
    IL_0017:  /* 26   |                  */ pop
    IL_0018:  /* 2A   |                  */ ret
  } // end of method Box`1::.ctor

  .method public hidebysig specialname instance !T 
          get_Value() cil managed
  // SIG: 20 00 13 00
  {
    // Method begins at RVA 0x2402
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 7B   | (0A)00003F       */ ldfld      !0 class Hello.More.Box`1<!T>::'value'
    IL_0006:  /* 2A   |                  */ ret
  } // end of method Box`1::get_Value

  .method public hidebysig specialname instance void 
          set_Value(!T 'value') cil managed
  // SIG: 20 01 01 13 00
  {
    // Method begins at RVA 0x240a
    // Code size       26 (0x1a)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 7D   | (0A)00003F       */ stfld      !0 class Hello.More.Box`1<!T>::'value'
    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 02   |                  */ ldarg.0
    IL_0009:  /* FE13 |                  */ volatile.
    IL_000b:  /* 7B   | (0A)000042       */ ldfld      int32 modreq([System.Runtime]System.Runtime.CompilerServices.IsVolatile) class Hello.More.Box`1<!T>::Version
    IL_0010:  /* 17   |                  */ ldc.i4.1
    IL_0011:  /* 58   |                  */ add
    IL_0012:  /* FE13 |                  */ volatile.
    IL_0014:  /* 7D   | (0A)000042       */ stfld      int32 modreq([System.Runtime]System.Runtime.CompilerServices.IsVolatile) class Hello.More.Box`1<!T>::Version
    IL_0019:  /* 2A   |                  */ ret
  } // end of method Box`1::set_Value

  .method public hidebysig instance !!TOut 
          Map<TOut>(class [System.Runtime]System.Func`2<!T,!!TOut> f) cil managed
  // SIG: 30 01 01 1E 00 15 12 71 02 13 00 1E 00
  {
    // Method begins at RVA 0x2425
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  /* 03   |                  */ ldarg.1
    IL_0001:  /* 02   |                  */ ldarg.0
    IL_0002:  /* 7B   | (0A)00003F       */ ldfld      !0 class Hello.More.Box`1<!T>::'value'
    IL_0007:  /* 6F   | (0A)000043       */ callvirt   instance !1 class [System.Runtime]System.Func`2<!T,!!TOut>::Invoke(!0)
    IL_000c:  /* 2A   |                  */ ret
  } // end of method Box`1::Map

  .method public hidebysig virtual instance string 
          ToString() cil managed
  // SIG: 20 00 0E
  {
    // Method begins at RVA 0x2433
    // Code size       27 (0x1b)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 7C   | (0A)00003F       */ ldflda     !0 class Hello.More.Box`1<!T>::'value'
    IL_0006:  /* FE16 | (1B)00000F       */ constrained. !T
    IL_000c:  /* 6F   | (0A)000044       */ callvirt   instance string [System.Runtime]System.Object::ToString()
    IL_0011:  /* 25   |                  */ dup
    IL_0012:  /* 2D   | 06               */ brtrue.s   IL_001a

    IL_0014:  /* 26   |                  */ pop
    IL_0015:  /* 72   | (70)0000D3       */ ldstr      ""
    IL_001a:  /* 2A   |                  */ ret
  } // end of method Box`1::ToString

  .method public hidebysig static int32  Size() cil managed
  // SIG: 00 00 08
  {
    // Method begins at RVA 0x244f
    // Code size       6 (0x6)
    .maxstack  8
    IL_0000:  /* 28   | (2B)000005       */ call       int32 [System.Runtime]System.Runtime.CompilerServices.Unsafe::SizeOf<!T>()
    IL_0005:  /* 2A   |                  */ ret
  } // end of method Box`1::Size

  .property instance callconv(8) !T Value()
  {
    .get instance !T Hello.More.Box`1::get_Value()
    .set instance void Hello.More.Box`1::set_Value(!T)
  } // end of property Box`1::Value
} // end of class Hello.More.Box`1

.class interface public abstract auto ansi beforefieldinit Hello.More.IShape
{
  .method public hidebysig newslot abstract virtual 
          instance float64  Area() cil managed
  // SIG: 20 00 0D
  {
    // Method begins at RVA 0x0
  } // end of method IShape::Area

  .method public hidebysig newslot specialname virtual 
          instance string  get_Name() cil managed
  // SIG: 20 00 0E
  {
    // Method begins at RVA 0x2456
    // Code size       6 (0x6)
    .maxstack  8
    IL_0000:  /* 72   | (70)0000D5       */ ldstr      "shape"
    IL_0005:  /* 2A   |                  */ ret
  } // end of method IShape::get_Name

  .property instance callconv(8) string Name()
  {
    .get instance string Hello.More.IShape::get_Name()
  } // end of property IShape::Name
} // end of class Hello.More.IShape

.class public auto ansi beforefieldinit Hello.More.Circle
       extends [System.Runtime]System.Object
       implements Hello.More.IShape,
                  class [System.Runtime]System.IEquatable`1<class Hello.More.Circle>
{
  .field private initonly float64 '<R>k__BackingField'
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(float64 R) cil managed
  // SIG: 20 01 01 0D
  {
    // Method begins at RVA 0x245d
    // Code size       14 (0xe)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 7D   | (04)00000A       */ stfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 28   | (0A)00003E       */ call       instance void [System.Runtime]System.Object::.ctor()
    IL_000d:  /* 2A   |                  */ ret
  } // end of method Circle::.ctor

  .method family hidebysig newslot specialname virtual 
          instance class [System.Runtime]System.Type 
          get_EqualityContract() cil managed
  // SIG: 20 00 12 65
  {
    // Method begins at RVA 0x246c
    // Code size       11 (0xb)
    .maxstack  8
    IL_0000:  /* D0   | (02)000007       */ ldtoken    Hello.More.Circle
    IL_0005:  /* 28   | (0A)000046       */ call       class [System.Runtime]System.Type [System.Runtime]System.Type::GetTypeFromHandle(valuetype [System.Runtime]System.RuntimeTypeHandle)
    IL_000a:  /* 2A   |                  */ ret
  } // end of method Circle::get_EqualityContract

  .method public hidebysig specialname instance float64 
          get_R() cil managed
  // SIG: 20 00 0D
  {
    // Method begins at RVA 0x2478
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 7B   | (04)00000A       */ ldfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0006:  /* 2A   |                  */ ret
  } // end of method Circle::get_R

  .method public hidebysig specialname instance void modreq([System.Runtime]System.Runtime.CompilerServices.IsExternalInit) 
          set_R(float64 'value') cil managed
  // SIG: 20 01 1F 80 A5 01 0D
  {
    // Method begins at RVA 0x2480
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 7D   | (04)00000A       */ stfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0007:  /* 2A   |                  */ ret
  } // end of method Circle::set_R

  .method public hidebysig newslot virtual final 
          instance float64  Area() cil managed
  // SIG: 20 00 0D
  {
    // Method begins at RVA 0x2489
    // Code size       24 (0x18)
    .maxstack  8
    IL_0000:  /* 23   | 400921FB54442D18 */ ldc.r8     3.1415926535897931
    IL_0009:  /* 02   |                  */ ldarg.0
    IL_000a:  /* 28   | (06)000014       */ call       instance float64 Hello.More.Circle::get_R()
    IL_000f:  /* 5A   |                  */ mul
    IL_0010:  /* 02   |                  */ ldarg.0
    IL_0011:  /* 28   | (06)000014       */ call       instance float64 Hello.More.Circle::get_R()
    IL_0016:  /* 5A   |                  */ mul
    IL_0017:  /* 2A   |                  */ ret
  } // end of method Circle::Area

  .method public hidebysig virtual instance string 
          ToString() cil managed
  // SIG: 20 00 0E
  {
    // Method begins at RVA 0x24a4
    // Code size       64 (0x40)
    .maxstack  2
    .locals init (class [System.Runtime]System.Text.StringBuilder V_0)
    IL_0000:  /* 73   | (0A)000047       */ newobj     instance void [System.Runtime]System.Text.StringBuilder::.ctor()
    IL_0005:  /* 0A   |                  */ stloc.0
    IL_0006:  /* 06   |                  */ ldloc.0
    IL_0007:  /* 72   | (70)0000E1       */ ldstr      "Circle"
    IL_000c:  /* 6F   | (0A)000048       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(string)
    IL_0011:  /* 26   |                  */ pop
    IL_0012:  /* 06   |                  */ ldloc.0
    IL_0013:  /* 72   | (70)0000EF       */ ldstr      " { "
    IL_0018:  /* 6F   | (0A)000048       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(string)
    IL_001d:  /* 26   |                  */ pop
    IL_001e:  /* 02   |                  */ ldarg.0
    IL_001f:  /* 06   |                  */ ldloc.0
    IL_0020:  /* 6F   | (06)000018       */ callvirt   instance bool Hello.More.Circle::PrintMembers(class [System.Runtime]System.Text.StringBuilder)
    IL_0025:  /* 2C   | 09               */ brfalse.s  IL_0030

    IL_0027:  /* 06   |                  */ ldloc.0
    IL_0028:  /* 1F   | 20               */ ldc.i4.s   32
    IL_002a:  /* 6F   | (0A)000049       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(char)
    IL_002f:  /* 26   |                  */ pop
    IL_0030:  /* 06   |                  */ ldloc.0
    IL_0031:  /* 1F   | 7D               */ ldc.i4.s   125
    IL_0033:  /* 6F   | (0A)000049       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(char)
    IL_0038:  /* 26   |                  */ pop
    IL_0039:  /* 06   |                  */ ldloc.0
    IL_003a:  /* 6F   | (0A)000044       */ callvirt   instance string [System.Runtime]System.Object::ToString()
    IL_003f:  /* 2A   |                  */ ret
  } // end of method Circle::ToString

  .method family hidebysig newslot virtual 
          instance bool  PrintMembers(class [System.Runtime]System.Text.StringBuilder builder) cil managed
  // SIG: 20 01 02 12 80 A9
  {
    // Method begins at RVA 0x24f0
    // Code size       46 (0x2e)
    .maxstack  2
    .locals init (float64 V_0)
    IL_0000:  /* 28   | (0A)00004A       */ call       void [System.Runtime]System.Runtime.CompilerServices.RuntimeHelpers::EnsureSufficientExecutionStack()
    IL_0005:  /* 03   |                  */ ldarg.1
    IL_0006:  /* 72   | (70)0000F7       */ ldstr      "R = "
    IL_000b:  /* 6F   | (0A)000048       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(string)
    IL_0010:  /* 26   |                  */ pop
    IL_0011:  /* 03   |                  */ ldarg.1
    IL_0012:  /* 02   |                  */ ldarg.0
    IL_0013:  /* 28   | (06)000014       */ call       instance float64 Hello.More.Circle::get_R()
    IL_0018:  /* 0A   |                  */ stloc.0
    IL_0019:  /* 12   | 00               */ ldloca.s   V_0
    IL_001b:  /* FE16 | (01)000041       */ constrained. [System.Runtime]System.Double
    IL_0021:  /* 6F   | (0A)000044       */ callvirt   instance string [System.Runtime]System.Object::ToString()
    IL_0026:  /* 6F   | (0A)000048       */ callvirt   instance class [System.Runtime]System.Text.StringBuilder [System.Runtime]System.Text.StringBuilder::Append(string)
    IL_002b:  /* 26   |                  */ pop
    IL_002c:  /* 17   |                  */ ldc.i4.1
    IL_002d:  /* 2A   |                  */ ret
  } // end of method Circle::PrintMembers

  .method public hidebysig specialname static 
          bool  op_Inequality(class Hello.More.Circle left,
                              class Hello.More.Circle right) cil managed
  // SIG: 00 02 02 12 1C 12 1C
  {
    // Method begins at RVA 0x252a
    // Code size       11 (0xb)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 28   | (06)00001A       */ call       bool Hello.More.Circle::op_Equality(class Hello.More.Circle,
                                                                                           class Hello.More.Circle)
    IL_0007:  /* 16   |                  */ ldc.i4.0
    IL_0008:  /* FE01 |                  */ ceq
    IL_000a:  /* 2A   |                  */ ret
  } // end of method Circle::op_Inequality

  .method public hidebysig specialname static 
          bool  op_Equality(class Hello.More.Circle left,
                            class Hello.More.Circle right) cil managed
  // SIG: 00 02 02 12 1C 12 1C
  {
    // Method begins at RVA 0x2536
    // Code size       19 (0x13)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 2E   | 0D               */ beq.s      IL_0011

    IL_0004:  /* 02   |                  */ ldarg.0
    IL_0005:  /* 2C   | 08               */ brfalse.s  IL_000f

    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 03   |                  */ ldarg.1
    IL_0009:  /* 6F   | (06)00001D       */ callvirt   instance bool Hello.More.Circle::Equals(class Hello.More.Circle)
    IL_000e:  /* 2A   |                  */ ret

    IL_000f:  /* 16   |                  */ ldc.i4.0
    IL_0010:  /* 2A   |                  */ ret

    IL_0011:  /* 17   |                  */ ldc.i4.1
    IL_0012:  /* 2A   |                  */ ret
  } // end of method Circle::op_Equality

  .method public hidebysig virtual instance int32 
          GetHashCode() cil managed
  // SIG: 20 00 08
  {
    // Method begins at RVA 0x254a
    // Code size       40 (0x28)
    .maxstack  8
    IL_0000:  /* 28   | (0A)00004B       */ call       class [System.Collections]System.Collections.Generic.EqualityComparer`1<!0> class [System.Collections]System.Collections.Generic.EqualityComparer`1<class [System.Runtime]System.Type>::get_Default()
    IL_0005:  /* 02   |                  */ ldarg.0
    IL_0006:  /* 6F   | (06)000013       */ callvirt   instance class [System.Runtime]System.Type Hello.More.Circle::get_EqualityContract()
    IL_000b:  /* 6F   | (0A)00004C       */ callvirt   instance int32 class [System.Collections]System.Collections.Generic.EqualityComparer`1<class [System.Runtime]System.Type>::GetHashCode(!0)
    IL_0010:  /* 20   | A5555529         */ ldc.i4     0xa5555529
    IL_0015:  /* 5A   |                  */ mul
    IL_0016:  /* 28   | (0A)00004D       */ call       class [System.Collections]System.Collections.Generic.EqualityComparer`1<!0> class [System.Collections]System.Collections.Generic.EqualityComparer`1<float64>::get_Default()
    IL_001b:  /* 02   |                  */ ldarg.0
    IL_001c:  /* 7B   | (04)00000A       */ ldfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0021:  /* 6F   | (0A)00004E       */ callvirt   instance int32 class [System.Collections]System.Collections.Generic.EqualityComparer`1<float64>::GetHashCode(!0)
    IL_0026:  /* 58   |                  */ add
    IL_0027:  /* 2A   |                  */ ret
  } // end of method Circle::GetHashCode

  .method public hidebysig virtual instance bool 
          Equals(object obj) cil managed
  // SIG: 20 01 02 1C
  {
    // Method begins at RVA 0x2573
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 75   | (02)000007       */ isinst     Hello.More.Circle
    IL_0007:  /* 6F   | (06)00001D       */ callvirt   instance bool Hello.More.Circle::Equals(class Hello.More.Circle)
    IL_000c:  /* 2A   |                  */ ret
  } // end of method Circle::Equals

  .method public hidebysig newslot virtual 
          instance bool  Equals(class Hello.More.Circle other) cil managed
  // SIG: 20 01 02 12 1C
  {
    // Method begins at RVA 0x2581
    // Code size       53 (0x35)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 03   |                  */ ldarg.1
    IL_0002:  /* 2E   | 2F               */ beq.s      IL_0033

    IL_0004:  /* 03   |                  */ ldarg.1
    IL_0005:  /* 2C   | 2A               */ brfalse.s  IL_0031

    IL_0007:  /* 02   |                  */ ldarg.0
    IL_0008:  /* 6F   | (06)000013       */ callvirt   instance class [System.Runtime]System.Type Hello.More.Circle::get_EqualityContract()
    IL_000d:  /* 03   |                  */ ldarg.1
    IL_000e:  /* 6F   | (06)000013       */ callvirt   instance class [System.Runtime]System.Type Hello.More.Circle::get_EqualityContract()
    IL_0013:  /* 28   | (0A)00004F       */ call       bool [System.Runtime]System.Type::op_Equality(class [System.Runtime]System.Type,
                                                                                                     class [System.Runtime]System.Type)
    IL_0018:  /* 2C   | 17               */ brfalse.s  IL_0031

    IL_001a:  /* 28   | (0A)00004D       */ call       class [System.Collections]System.Collections.Generic.EqualityComparer`1<!0> class [System.Collections]System.Collections.Generic.EqualityComparer`1<float64>::get_Default()
    IL_001f:  /* 02   |                  */ ldarg.0
    IL_0020:  /* 7B   | (04)00000A       */ ldfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0025:  /* 03   |                  */ ldarg.1
    IL_0026:  /* 7B   | (04)00000A       */ ldfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_002b:  /* 6F   | (0A)000050       */ callvirt   instance bool class [System.Collections]System.Collections.Generic.EqualityComparer`1<float64>::Equals(!0,
                                                                                                                                                              !0)
    IL_0030:  /* 2A   |                  */ ret

    IL_0031:  /* 16   |                  */ ldc.i4.0
    IL_0032:  /* 2A   |                  */ ret

    IL_0033:  /* 17   |                  */ ldc.i4.1
    IL_0034:  /* 2A   |                  */ ret
  } // end of method Circle::Equals

  .method public hidebysig newslot virtual 
          instance class Hello.More.Circle 
          '<Clone>$'() cil managed
  // SIG: 20 00 12 1C
  {
    // Method begins at RVA 0x25b7
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 73   | (06)00001F       */ newobj     instance void Hello.More.Circle::.ctor(class Hello.More.Circle)
    IL_0006:  /* 2A   |                  */ ret
  } // end of method Circle::'<Clone>$'

  .method family hidebysig specialname rtspecialname 
          instance void  .ctor(class Hello.More.Circle original) cil managed
  // SIG: 20 01 01 12 1C
  {
    // Method begins at RVA 0x25bf
    // Code size       19 (0x13)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 28   | (0A)00003E       */ call       instance void [System.Runtime]System.Object::.ctor()
    IL_0006:  /* 02   |                  */ ldarg.0
    IL_0007:  /* 03   |                  */ ldarg.1
    IL_0008:  /* 7B   | (04)00000A       */ ldfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_000d:  /* 7D   | (04)00000A       */ stfld      float64 Hello.More.Circle::'<R>k__BackingField'
    IL_0012:  /* 2A   |                  */ ret
  } // end of method Circle::.ctor

  .method public hidebysig instance void 
          Deconstruct([out] float64& R) cil managed
  // SIG: 20 01 01 10 0D
  {
    // Method begins at RVA 0x25d3
    // Code size       9 (0x9)
    .maxstack  8
    IL_0000:  /* 03   |                  */ ldarg.1
    IL_0001:  /* 02   |                  */ ldarg.0
    IL_0002:  /* 28   | (06)000014       */ call       instance float64 Hello.More.Circle::get_R()
    IL_0007:  /* 57   |                  */ stind.r8
    IL_0008:  /* 2A   |                  */ ret
  } // end of method Circle::Deconstruct

  .property instance callconv(8) class [System.Runtime]System.Type
          EqualityContract()
  {
    .get instance class [System.Runtime]System.Type Hello.More.Circle::get_EqualityContract()
  } // end of property Circle::EqualityContract
  .property instance callconv(8) float64 R()
  {
    .get instance float64 Hello.More.Circle::get_R()
    .set instance void modreq([System.Runtime]System.Runtime.CompilerServices.IsExternalInit) Hello.More.Circle::set_R(float64)
  } // end of property Circle::R
} // end of class Hello.More.Circle

.class public abstract auto ansi sealed beforefieldinit Hello.More.Edge
       extends [System.Runtime]System.Object
{
  .class auto ansi sealed nested private beforefieldinit '<Count>d__5'
         extends [System.Runtime]System.Object
         implements class [System.Runtime]System.Collections.Generic.IEnumerable`1<int32>,
                    [System.Runtime]System.Collections.IEnumerable,
                    class [System.Runtime]System.Collections.Generic.IEnumerator`1<int32>,
                    [System.Runtime]System.Collections.IEnumerator,
                    [System.Runtime]System.IDisposable
  {
    .field private int32 '<>1__state'
    .field private int32 '<>2__current'
    .field private int32 '<>l__initialThreadId'
    .field private int32 n
    .field public int32 '<>3__n'
    .field private int32 '<i>5__2'
    .method public hidebysig specialname rtspecialname 
            instance void  .ctor(int32 '<>1__state') cil managed
    // SIG: 20 01 01 08
    {
      // Method begins at RVA 0x2ab6
      // Code size       25 (0x19)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 28   | (0A)00003E       */ call       instance void [System.Runtime]System.Object::.ctor()
      IL_0006:  /* 02   |                  */ ldarg.0
      IL_0007:  /* 03   |                  */ ldarg.1
      IL_0008:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_000d:  /* 02   |                  */ ldarg.0
      IL_000e:  /* 28   | (0A)00006B       */ call       int32 [System.Runtime]System.Environment::get_CurrentManagedThreadId()
      IL_0013:  /* 7D   | (04)000015       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>l__initialThreadId'
      IL_0018:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::.ctor

    .method private hidebysig newslot virtual final 
            instance void  System.IDisposable.Dispose() cil managed
    // SIG: 20 00 01
    {
      .override [System.Runtime]System.IDisposable::Dispose
      // Method begins at RVA 0x2ad0
      // Code size       35 (0x23)
      .maxstack  2
      .locals init (int32 V_0)
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7B   | (04)000013       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_0006:  /* 0A   |                  */ stloc.0
      IL_0007:  /* 06   |                  */ ldloc.0
      IL_0008:  /* 1F   | FD               */ ldc.i4.s   -3
      IL_000a:  /* 2E   | 04               */ beq.s      IL_0010

      IL_000c:  /* 06   |                  */ ldloc.0
      IL_000d:  /* 17   |                  */ ldc.i4.1
      IL_000e:  /* 33   | 0A               */ bne.un.s   IL_001a

      IL_0010:  /* 00   |                  */ nop
      .try
      {
        IL_0011:  /* DE   | 07               */ leave.s    IL_001a

      }  // end .try
      finally
      {
        IL_0013:  /* 02   |                  */ ldarg.0
        IL_0014:  /* 28   | (06)000038       */ call       instance void Hello.More.Edge/'<Count>d__5'::'<>m__Finally1'()
        IL_0019:  /* DC   |                  */ endfinally
      }  // end handler
      // HEX: 02 00 11 00 02 13 00 07 00 00 00 00
      IL_001a:  /* 02   |                  */ ldarg.0
      IL_001b:  /* 1F   | FE               */ ldc.i4.s   -2
      IL_001d:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_0022:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::System.IDisposable.Dispose

    .method private hidebysig newslot virtual final 
            instance bool  MoveNext() cil managed
    // SIG: 20 00 02
    {
      .override [System.Runtime]System.Collections.IEnumerator::MoveNext
      // Method begins at RVA 0x2b10
      // Code size       122 (0x7a)
      .maxstack  3
      .locals init (bool V_0,
               int32 V_1,
               int32 V_2)
      .try
      {
        IL_0000:  /* 02   |                  */ ldarg.0
        IL_0001:  /* 7B   | (04)000013       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
        IL_0006:  /* 0B   |                  */ stloc.1
        IL_0007:  /* 07   |                  */ ldloc.1
        IL_0008:  /* 2C   | 08               */ brfalse.s  IL_0012

        IL_000a:  /* 07   |                  */ ldloc.1
        IL_000b:  /* 17   |                  */ ldc.i4.1
        IL_000c:  /* 2E   | 33               */ beq.s      IL_0041

        IL_000e:  /* 16   |                  */ ldc.i4.0
        IL_000f:  /* 0A   |                  */ stloc.0
        IL_0010:  /* DE   | 66               */ leave.s    IL_0078

        IL_0012:  /* 02   |                  */ ldarg.0
        IL_0013:  /* 15   |                  */ ldc.i4.m1
        IL_0014:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
        IL_0019:  /* 02   |                  */ ldarg.0
        IL_001a:  /* 1F   | FD               */ ldc.i4.s   -3
        IL_001c:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
        IL_0021:  /* 02   |                  */ ldarg.0
        IL_0022:  /* 16   |                  */ ldc.i4.0
        IL_0023:  /* 7D   | (04)000018       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<i>5__2'
        IL_0028:  /* 2B   | 2F               */ br.s       IL_0059

        IL_002a:  /* 02   |                  */ ldarg.0
        IL_002b:  /* 02   |                  */ ldarg.0
        IL_002c:  /* 7B   | (04)000018       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<i>5__2'
        IL_0031:  /* 7D   | (04)000014       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>2__current'
        IL_0036:  /* 02   |                  */ ldarg.0
        IL_0037:  /* 17   |                  */ ldc.i4.1
        IL_0038:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
        IL_003d:  /* 17   |                  */ ldc.i4.1
        IL_003e:  /* 0A   |                  */ stloc.0
        IL_003f:  /* DE   | 37               */ leave.s    IL_0078

        IL_0041:  /* 02   |                  */ ldarg.0
        IL_0042:  /* 1F   | FD               */ ldc.i4.s   -3
        IL_0044:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
        IL_0049:  /* 02   |                  */ ldarg.0
        IL_004a:  /* 7B   | (04)000018       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<i>5__2'
        IL_004f:  /* 0C   |                  */ stloc.2
        IL_0050:  /* 02   |                  */ ldarg.0
        IL_0051:  /* 08   |                  */ ldloc.2
        IL_0052:  /* 17   |                  */ ldc.i4.1
        IL_0053:  /* 58   |                  */ add
        IL_0054:  /* 7D   | (04)000018       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<i>5__2'
        IL_0059:  /* 02   |                  */ ldarg.0
        IL_005a:  /* 7B   | (04)000018       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<i>5__2'
        IL_005f:  /* 02   |                  */ ldarg.0
        IL_0060:  /* 7B   | (04)000016       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::n
        IL_0065:  /* 32   | C3               */ blt.s      IL_002a

        IL_0067:  /* 02   |                  */ ldarg.0
        IL_0068:  /* 28   | (06)000038       */ call       instance void Hello.More.Edge/'<Count>d__5'::'<>m__Finally1'()
        IL_006d:  /* 16   |                  */ ldc.i4.0
        IL_006e:  /* 0A   |                  */ stloc.0
        IL_006f:  /* DE   | 07               */ leave.s    IL_0078

      }  // end .try
      fault
      {
        IL_0071:  /* 02   |                  */ ldarg.0
        IL_0072:  /* 28   | (06)000036       */ call       instance void Hello.More.Edge/'<Count>d__5'::System.IDisposable.Dispose()
        IL_0077:  /* DC   |                  */ endfinally
      }  // end handler
      // HEX: 04 00 00 00 71 71 00 07 00 00 00 00
      IL_0078:  /* 06   |                  */ ldloc.0
      IL_0079:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::MoveNext

    .method private hidebysig instance void 
            '<>m__Finally1'() cil managed
    // SIG: 20 00 01
    {
      // Method begins at RVA 0x2ba8
      // Code size       18 (0x12)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 15   |                  */ ldc.i4.m1
      IL_0002:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_0007:  /* 72   | (70)00035A       */ ldstr      "done"
      IL_000c:  /* 28   | (0A)000028       */ call       void [System.Console]System.Console::WriteLine(string)
      IL_0011:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::'<>m__Finally1'

    .method private hidebysig newslot specialname virtual final 
            instance int32  'System.Collections.Generic.IEnumerator<System.Int32>.get_Current'() cil managed
    // SIG: 20 00 08
    {
      .override  method instance !0 class [System.Runtime]System.Collections.Generic.IEnumerator`1<int32>::get_Current()
      // Method begins at RVA 0x2bbb
      // Code size       7 (0x7)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7B   | (04)000014       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>2__current'
      IL_0006:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::'System.Collections.Generic.IEnumerator<System.Int32>.get_Current'

    .method private hidebysig newslot virtual final 
            instance void  System.Collections.IEnumerator.Reset() cil managed
    // SIG: 20 00 01
    {
      .override [System.Runtime]System.Collections.IEnumerator::Reset
      // Method begins at RVA 0x2bc3
      // Code size       6 (0x6)
      .maxstack  8
      IL_0000:  /* 73   | (0A)00006C       */ newobj     instance void [System.Runtime]System.NotSupportedException::.ctor()
      IL_0005:  /* 7A   |                  */ throw
    } // end of method '<Count>d__5'::System.Collections.IEnumerator.Reset

    .method private hidebysig newslot specialname virtual final 
            instance object  System.Collections.IEnumerator.get_Current() cil managed
    // SIG: 20 00 1C
    {
      .override [System.Runtime]System.Collections.IEnumerator::get_Current
      // Method begins at RVA 0x2bca
      // Code size       12 (0xc)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7B   | (04)000014       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>2__current'
      IL_0006:  /* 8C   | (01)000039       */ box        [System.Runtime]System.Int32
      IL_000b:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::System.Collections.IEnumerator.get_Current

    .method private hidebysig newslot virtual final 
            instance class [System.Runtime]System.Collections.Generic.IEnumerator`1<int32> 
            'System.Collections.Generic.IEnumerable<System.Int32>.GetEnumerator'() cil managed
    // SIG: 20 00 15 12 80 D1 01 08
    {
      .override  method instance class [System.Runtime]System.Collections.Generic.IEnumerator`1<!0> class [System.Runtime]System.Collections.Generic.IEnumerable`1<int32>::GetEnumerator()
      // Method begins at RVA 0x2bd8
      // Code size       55 (0x37)
      .maxstack  2
      .locals init (class Hello.More.Edge/'<Count>d__5' V_0)
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 7B   | (04)000013       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_0006:  /* 1F   | FE               */ ldc.i4.s   -2
      IL_0008:  /* 33   | 18               */ bne.un.s   IL_0022

      IL_000a:  /* 02   |                  */ ldarg.0
      IL_000b:  /* 7B   | (04)000015       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>l__initialThreadId'
      IL_0010:  /* 28   | (0A)00006B       */ call       int32 [System.Runtime]System.Environment::get_CurrentManagedThreadId()
      IL_0015:  /* 33   | 0B               */ bne.un.s   IL_0022

      IL_0017:  /* 02   |                  */ ldarg.0
      IL_0018:  /* 16   |                  */ ldc.i4.0
      IL_0019:  /* 7D   | (04)000013       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>1__state'
      IL_001e:  /* 02   |                  */ ldarg.0
      IL_001f:  /* 0A   |                  */ stloc.0
      IL_0020:  /* 2B   | 07               */ br.s       IL_0029

      IL_0022:  /* 16   |                  */ ldc.i4.0
      IL_0023:  /* 73   | (06)000035       */ newobj     instance void Hello.More.Edge/'<Count>d__5'::.ctor(int32)
      IL_0028:  /* 0A   |                  */ stloc.0
      IL_0029:  /* 06   |                  */ ldloc.0
      IL_002a:  /* 02   |                  */ ldarg.0
      IL_002b:  /* 7B   | (04)000017       */ ldfld      int32 Hello.More.Edge/'<Count>d__5'::'<>3__n'
      IL_0030:  /* 7D   | (04)000016       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::n
      IL_0035:  /* 06   |                  */ ldloc.0
      IL_0036:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::'System.Collections.Generic.IEnumerable<System.Int32>.GetEnumerator'

    .method private hidebysig newslot virtual final 
            instance class [System.Runtime]System.Collections.IEnumerator 
            System.Collections.IEnumerable.GetEnumerator() cil managed
    // SIG: 20 00 12 80 CD
    {
      .override [System.Runtime]System.Collections.IEnumerable::GetEnumerator
      // Method begins at RVA 0x2c1b
      // Code size       7 (0x7)
      .maxstack  8
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 28   | (06)00003C       */ call       instance class [System.Runtime]System.Collections.Generic.IEnumerator`1<int32> Hello.More.Edge/'<Count>d__5'::'System.Collections.Generic.IEnumerable<System.Int32>.GetEnumerator'()
      IL_0006:  /* 2A   |                  */ ret
    } // end of method '<Count>d__5'::System.Collections.IEnumerable.GetEnumerator

    .property instance callconv(8) int32 'System.Collections.Generic.IEnumerator<System.Int32>.Current'()
    {
      .get instance int32 Hello.More.Edge/'<Count>d__5'::'System.Collections.Generic.IEnumerator<System.Int32>.get_Current'()
    } // end of property '<Count>d__5'::'System.Collections.Generic.IEnumerator<System.Int32>.Current'
    .property instance callconv(8) object
            System.Collections.IEnumerator.Current()
    {
      .get instance object Hello.More.Edge/'<Count>d__5'::System.Collections.IEnumerator.get_Current()
    } // end of property '<Count>d__5'::System.Collections.IEnumerator.Current
  } // end of class '<Count>d__5'

  .method private hidebysig static pinvokeimpl("libc" as "abs" winapi) 
          int32  Abs(int32 'value') cil managed preservesig
  // SIG: 00 01 08 08
  {
  }
  .method public hidebysig static int64  Constants() cil managed
  // SIG: 00 00 0A
  {
    // Method begins at RVA 0x25e0
    // Code size       223 (0xdf)
    .maxstack  3
    .locals init (int32 V_0,
             int32 V_1,
             int32 V_2,
             int32 V_3,
             int64 V_4,
             int64 V_5,
             int64 V_6,
             float32 V_7,
             float32 V_8,
             float32 V_9,
             float32 V_10,
             float32 V_11,
             float32 V_12,
             float32 V_13,
             float64 V_14,
             float64 V_15,
             float64 V_16,
             float64 V_17,
             float64 V_18,
             float64 V_19)
    IL_0000:  /* 20   | 000F4240         */ ldc.i4     0xf4240
    IL_0005:  /* 20   | FFFFFF7F         */ ldc.i4     0xffffff7f
    IL_000a:  /* 0A   |                  */ stloc.0
    IL_000b:  /* 1F   | 7F               */ ldc.i4.s   127
    IL_000d:  /* 0B   |                  */ stloc.1
    IL_000e:  /* 15   |                  */ ldc.i4.m1
    IL_000f:  /* 0C   |                  */ stloc.2
    IL_0010:  /* 20   | 80000000         */ ldc.i4     0x80000000
    IL_0015:  /* 0D   |                  */ stloc.3
    IL_0016:  /* 21   | 0123456789ABCDEF */ ldc.i8     0x123456789abcdef
    IL_001f:  /* 13   | 04               */ stloc.s    V_4
    IL_0021:  /* 15   |                  */ ldc.i4.m1
    IL_0022:  /* 6A   |                  */ conv.i8
    IL_0023:  /* 13   | 05               */ stloc.s    V_5
    IL_0025:  /* 21   | 7FFFFFFFFFFFFFFF */ ldc.i8     0x7fffffffffffffff
    IL_002e:  /* 13   | 06               */ stloc.s    V_6
    IL_0030:  /* 22   | 3F800000         */ ldc.r4     1
    IL_0035:  /* 13   | 07               */ stloc.s    V_7
    IL_0037:  /* 22   | 3DCCCCCD         */ ldc.r4     0.1
    IL_003c:  /* 13   | 08               */ stloc.s    V_8
    IL_003e:  /* 22   | FFC00000         */ ldc.r4     (00 00 C0 FF)
    IL_0043:  /* 13   | 09               */ stloc.s    V_9
    IL_0045:  /* 22   | 7F800000         */ ldc.r4     (00 00 80 7F)
    IL_004a:  /* 13   | 0A               */ stloc.s    V_10
    IL_004c:  /* 22   | 80000000         */ ldc.r4     -0.0
    IL_0051:  /* 13   | 0B               */ stloc.s    V_11
    IL_0053:  /* 22   | 7F7FC99E         */ ldc.r4     3.4e+38
    IL_0058:  /* 13   | 0C               */ stloc.s    V_12
    IL_005a:  /* 22   | 33D6BF95         */ ldc.r4     1e-07
    IL_005f:  /* 13   | 0D               */ stloc.s    V_13
    IL_0061:  /* 23   | 4000000000000000 */ ldc.r8     2
    IL_006a:  /* 13   | 0E               */ stloc.s    V_14
    IL_006c:  /* 23   | 3FB999999999999A */ ldc.r8     0.10000000000000001
    IL_0075:  /* 13   | 0F               */ stloc.s    V_15
    IL_0077:  /* 23   | FFF0000000000000 */ ldc.r8     (00 00 00 00 00 00 F0 FF)
    IL_0080:  /* 13   | 10               */ stloc.s    V_16
    IL_0082:  /* 23   | 7E37E43C8800759C */ ldc.r8     1.0000000000000001e+300
    IL_008b:  /* 13   | 11               */ stloc.s    V_17
    IL_008d:  /* 23   | 419D6F3454800000 */ ldc.r8     123456789.125
    IL_0096:  /* 13   | 12               */ stloc.s    V_18
    IL_0098:  /* 23   | 0000000000000001 */ ldc.r8     4.9406564584124654e-324
    IL_00a1:  /* 13   | 13               */ stloc.s    V_19
    IL_00a3:  /* 06   |                  */ ldloc.0
    IL_00a4:  /* 58   |                  */ add
    IL_00a5:  /* 07   |                  */ ldloc.1
    IL_00a6:  /* 58   |                  */ add
    IL_00a7:  /* 08   |                  */ ldloc.2
    IL_00a8:  /* 58   |                  */ add
    IL_00a9:  /* 09   |                  */ ldloc.3
    IL_00aa:  /* 58   |                  */ add
    IL_00ab:  /* 6A   |                  */ conv.i8
    IL_00ac:  /* 11   | 04               */ ldloc.s    V_4
    IL_00ae:  /* 58   |                  */ add
    IL_00af:  /* 11   | 05               */ ldloc.s    V_5
    IL_00b1:  /* 58   |                  */ add
    IL_00b2:  /* 11   | 06               */ ldloc.s    V_6
    IL_00b4:  /* 58   |                  */ add
    IL_00b5:  /* 11   | 07               */ ldloc.s    V_7
    IL_00b7:  /* 11   | 08               */ ldloc.s    V_8
    IL_00b9:  /* 58   |                  */ add
    IL_00ba:  /* 11   | 09               */ ldloc.s    V_9
    IL_00bc:  /* 58   |                  */ add
    IL_00bd:  /* 11   | 0A               */ ldloc.s    V_10
    IL_00bf:  /* 58   |                  */ add
    IL_00c0:  /* 11   | 0B               */ ldloc.s    V_11
    IL_00c2:  /* 58   |                  */ add
    IL_00c3:  /* 11   | 0C               */ ldloc.s    V_12
    IL_00c5:  /* 58   |                  */ add
    IL_00c6:  /* 11   | 0D               */ ldloc.s    V_13
    IL_00c8:  /* 58   |                  */ add
    IL_00c9:  /* 6C   |                  */ conv.r8
    IL_00ca:  /* 11   | 0E               */ ldloc.s    V_14
    IL_00cc:  /* 58   |                  */ add
    IL_00cd:  /* 11   | 0F               */ ldloc.s    V_15
    IL_00cf:  /* 58   |                  */ add
    IL_00d0:  /* 11   | 10               */ ldloc.s    V_16
    IL_00d2:  /* 58   |                  */ add
    IL_00d3:  /* 11   | 11               */ ldloc.s    V_17
    IL_00d5:  /* 58   |                  */ add
    IL_00d6:  /* 11   | 12               */ ldloc.s    V_18
    IL_00d8:  /* 58   |                  */ add
    IL_00d9:  /* 11   | 13               */ ldloc.s    V_19
    IL_00db:  /* 58   |                  */ add
    IL_00dc:  /* 6A   |                  */ conv.i8
    IL_00dd:  /* 58   |                  */ add
    IL_00de:  /* 2A   |                  */ ret
  } // end of method Edge::Constants

  .method public hidebysig static void  Strings(class [System.Runtime]System.IO.TextWriter w) cil managed
  // SIG: 00 01 01 12 80 AD
  {
    // Method begins at RVA 0x26cc
    // Code size       78 (0x4e)
    .maxstack  2
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 72   | (70)000101       */ ldstr      "tab\there \"quoted\" back\\slash\r\nnew line"
    IL_0006:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_000b:  /* 02   |                  */ ldarg.0
    IL_000c:  /* 72   | (70)00014F       */ ldstr      bytearray (1F 04 40 04 38 04 32 04 35 04 42 04 2C 00 20 00   // ..@.8.2.5.B.,. .
                                                                  3C 04 38 04 40 04 )                               // <.8.@.
    IL_0011:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_0016:  /* 02   |                  */ ldarg.0
    IL_0017:  /* 72   | (70)000167       */ ldstr      bytearray (00 00 6E 00 75 00 6C 00 01 00 07 00 08 00 0C 00   // ..n.u.l.........
                                                                  0B 00 ) 
    IL_001c:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_0021:  /* 02   |                  */ ldarg.0
    IL_0022:  /* 72   | (70)00017B       */ ldstr      bytearray (65 00 6D 00 6F 00 6A 00 69 00 20 00 3D D8 00 DE ) // e.m.o.j.i. .=...
    IL_0027:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_002c:  /* 02   |                  */ ldarg.0
    IL_002d:  /* 72   | (70)00018D       */ ldstr      bytearray (3F 00 71 00 75 00 65 00 73 00 74 00 69 00 6F 00   // ?.q.u.e.s.t.i.o.
                                                                  6E 00 3F 00 3F 00 20 00 27 00 73 00 69 00 6E 00   // n.?.?. .'.s.i.n.
                                                                  67 00 6C 00 65 00 27 00 20 00 7F 00 20 00 64 00   // g.l.e.'. ... .d.
                                                                  65 00 6C 00 )                                     // e.l.
    IL_0032:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_0037:  /* 02   |                  */ ldarg.0
    IL_0038:  /* 72   | (70)0000D3       */ ldstr      ""
    IL_003d:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_0042:  /* 02   |                  */ ldarg.0
    IL_0043:  /* 72   | (70)0001C3       */ ldstr      "a very long string that goes on and on, longer tha"
    + "n any line ildasm likes to print in one piece, so that it has to be cut into parts joined with a plus"
    + " sign, and then some more words to be sure of it"
    IL_0048:  /* 6F   | (0A)000051       */ callvirt   instance void [System.Runtime]System.IO.TextWriter::Write(string)
    IL_004d:  /* 2A   |                  */ ret
  } // end of method Edge::Strings

  .method public hidebysig static int32  Switch(int32 n) cil managed
  // SIG: 00 01 08 08
  {
    // Method begins at RVA 0x2726
    // Code size       56 (0x38)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 45   | 00000007         */ switch     ( 
              /*      | 00000002         */             IL_0024,
              /*      | 00000005         */             IL_0027,
              /*      | 00000008         */             IL_002a,
              /*      | 0000000B         */             IL_002d,
              /*      | 00000014         */             IL_0036,
              /*      | 0000000E         */             IL_0030,
              /*      | 00000011         */             IL_0033)
    IL_0022:  /* 2B   | 12               */ br.s       IL_0036

    IL_0024:  /* 1F   | 0A               */ ldc.i4.s   10
    IL_0026:  /* 2A   |                  */ ret

    IL_0027:  /* 1F   | 0B               */ ldc.i4.s   11
    IL_0029:  /* 2A   |                  */ ret

    IL_002a:  /* 1F   | 0C               */ ldc.i4.s   12
    IL_002c:  /* 2A   |                  */ ret

    IL_002d:  /* 1F   | 0D               */ ldc.i4.s   13
    IL_002f:  /* 2A   |                  */ ret

    IL_0030:  /* 1F   | 0F               */ ldc.i4.s   15
    IL_0032:  /* 2A   |                  */ ret

    IL_0033:  /* 1F   | 10               */ ldc.i4.s   16
    IL_0035:  /* 2A   |                  */ ret

    IL_0036:  /* 15   |                  */ ldc.i4.m1
    IL_0037:  /* 2A   |                  */ ret
  } // end of method Edge::Switch

  .method public hidebysig static int32  Filter(string s) cil managed
  // SIG: 00 01 08 0E
  {
    // Method begins at RVA 0x2760
    // Code size       52 (0x34)
    .maxstack  2
    .locals init (int32 V_0)
    .try
    {
      IL_0000:  /* 02   |                  */ ldarg.0
      IL_0001:  /* 28   | (0A)000032       */ call       int32 [System.Runtime]System.Int32::Parse(string)
      IL_0006:  /* 0A   |                  */ stloc.0
      IL_0007:  /* DE   | 29               */ leave.s    IL_0032

    }  // end .try
    filter
    {
      IL_0009:  /* 75   | (01)00001E       */ isinst     [System.Runtime]System.FormatException
      IL_000e:  /* 25   |                  */ dup
      IL_000f:  /* 2D   | 04               */ brtrue.s   IL_0015

      IL_0011:  /* 26   |                  */ pop
      IL_0012:  /* 16   |                  */ ldc.i4.0
      IL_0013:  /* 2B   | 10               */ br.s       IL_0025

      IL_0015:  /* 6F   | (0A)000034       */ callvirt   instance string [System.Runtime]System.Exception::get_Message()
      IL_001a:  /* 6F   | (0A)000052       */ callvirt   instance int32 [System.Runtime]System.String::get_Length()
      IL_001f:  /* 19   |                  */ ldc.i4.3
      IL_0020:  /* FE02 |                  */ cgt
      IL_0022:  /* 16   |                  */ ldc.i4.0
      IL_0023:  /* FE03 |                  */ cgt.un
      IL_0025:  /* FE11 |                  */ endfilter
    }  // end filter
    {  // handler
      IL_0027:  /* 26   |                  */ pop
      IL_0028:  /* 15   |                  */ ldc.i4.m1
      IL_0029:  /* 0A   |                  */ stloc.0
      IL_002a:  /* DE   | 06               */ leave.s    IL_0032

    }  // end handler
    // HEX: 01 00 00 00 09 27 00 05 09 00 00 00
    catch [System.Runtime]System.OverflowException 
    {
      IL_002c:  /* 26   |                  */ pop
      IL_002d:  /* 1F   | FE               */ ldc.i4.s   -2
      IL_002f:  /* 0A   |                  */ stloc.0
      IL_0030:  /* DE   | 00               */ leave.s    IL_0032

    }  // end handler
    // HEX: 00 00 00 00 09 2C 00 06 2C 00 00 01
    IL_0032:  /* 06   |                  */ ldloc.0
    IL_0033:  /* 2A   |                  */ ret
  } // end of method Edge::Filter

  .method public hidebysig static class [System.Runtime]System.Collections.Generic.IEnumerable`1<int32> 
          Count(int32 n) cil managed
  // SIG: 00 01 15 12 80 B9 01 08 08
  {
    // Method begins at RVA 0x27bc
    // Code size       15 (0xf)
    .maxstack  8
    IL_0000:  /* 1F   | FE               */ ldc.i4.s   -2
    IL_0002:  /* 73   | (06)000035       */ newobj     instance void Hello.More.Edge/'<Count>d__5'::.ctor(int32)
    IL_0007:  /* 25   |                  */ dup
    IL_0008:  /* 02   |                  */ ldarg.0
    IL_0009:  /* 7D   | (04)000017       */ stfld      int32 Hello.More.Edge/'<Count>d__5'::'<>3__n'
    IL_000e:  /* 2A   |                  */ ret
  } // end of method Edge::Count

  .method private hidebysig static int32 
          Twice(int32 x) cil managed
  // SIG: 00 01 08 08
  {
    // Method begins at RVA 0x27cc
    // Code size       4 (0x4)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 18   |                  */ ldc.i4.2
    IL_0002:  /* 5A   |                  */ mul
    IL_0003:  /* 2A   |                  */ ret
  } // end of method Edge::Twice

  .method public hidebysig static int32  Pointers(int32 x) cil managed
  // SIG: 00 01 08 08
  {
    // Method begins at RVA 0x27d4
    // Code size       99 (0x63)
    .maxstack  3
    .locals init (method int32 *(int32) V_0,
             method unmanaged cdecl int32 *(int32) V_1,
             int32* V_2,
             native int V_3,
             valuetype [System.Runtime]System.Span`1<uint8> V_4,
             method int32 *(int32) V_5,
             method unmanaged cdecl int32 *(int32) V_6)
    IL_0000:  /* FE06 | (06)000027       */ ldftn      int32 Hello.More.Edge::Twice(int32)
    IL_0006:  /* 0A   |                  */ stloc.0
    IL_0007:  /* 16   |                  */ ldc.i4.0
    IL_0008:  /* D3   |                  */ conv.i
    IL_0009:  /* 0B   |                  */ stloc.1
    IL_000a:  /* 1F   | 40               */ ldc.i4.s   64
    IL_000c:  /* E0   |                  */ conv.u
    IL_000d:  /* FE0F |                  */ localloc
    IL_000f:  /* 0C   |                  */ stloc.2
    IL_0010:  /* 08   |                  */ ldloc.2
    IL_0011:  /* 19   |                  */ ldc.i4.3
    IL_0012:  /* D3   |                  */ conv.i
    IL_0013:  /* 1A   |                  */ ldc.i4.4
    IL_0014:  /* 5A   |                  */ mul
    IL_0015:  /* 58   |                  */ add
    IL_0016:  /* 06   |                  */ ldloc.0
    IL_0017:  /* 13   | 05               */ stloc.s    V_5
    IL_0019:  /* 02   |                  */ ldarg.0
    IL_001a:  /* 11   | 05               */ ldloc.s    V_5
    IL_001c:  /* 29   | 1100000C         */ calli      int32(int32)
    IL_0021:  /* 54   |                  */ stind.i4
    IL_0022:  /* FE1C | (1B)000012       */ sizeof     class Hello.More.Circle*
    IL_0028:  /* D3   |                  */ conv.i
    IL_0029:  /* 0D   |                  */ stloc.3
    IL_002a:  /* 1E   |                  */ ldc.i4.8
    IL_002b:  /* E0   |                  */ conv.u
    IL_002c:  /* FE0F |                  */ localloc
    IL_002e:  /* 1E   |                  */ ldc.i4.8
    IL_002f:  /* 73   | (0A)000053       */ newobj     instance void valuetype [System.Runtime]System.Span`1<uint8>::.ctor(void*,
                                                                                                                           int32)
    IL_0034:  /* 13   | 04               */ stloc.s    V_4
    IL_0036:  /* 08   |                  */ ldloc.2
    IL_0037:  /* 19   |                  */ ldc.i4.3
    IL_0038:  /* D3   |                  */ conv.i
    IL_0039:  /* 1A   |                  */ ldc.i4.4
    IL_003a:  /* 5A   |                  */ mul
    IL_003b:  /* 58   |                  */ add
    IL_003c:  /* 4A   |                  */ ldind.i4
    IL_003d:  /* 09   |                  */ ldloc.3
    IL_003e:  /* 69   |                  */ conv.i4
    IL_003f:  /* 58   |                  */ add
    IL_0040:  /* 12   | 04               */ ldloca.s   V_4
    IL_0042:  /* 28   | (0A)000054       */ call       instance int32 valuetype [System.Runtime]System.Span`1<uint8>::get_Length()
    IL_0047:  /* 58   |                  */ add
    IL_0048:  /* 07   |                  */ ldloc.1
    IL_0049:  /* 16   |                  */ ldc.i4.0
    IL_004a:  /* E0   |                  */ conv.u
    IL_004b:  /* 2E   | 0D               */ beq.s      IL_005a

    IL_004d:  /* 07   |                  */ ldloc.1
    IL_004e:  /* 13   | 06               */ stloc.s    V_6
    IL_0050:  /* 02   |                  */ ldarg.0
    IL_0051:  /* 11   | 06               */ ldloc.s    V_6
    IL_0053:  /* 29   | 1100000D         */ calli      unmanaged cdecl int32(int32)
    IL_0058:  /* 2B   | 07               */ br.s       IL_0061

    IL_005a:  /* 02   |                  */ ldarg.0
    IL_005b:  /* 65   |                  */ neg
    IL_005c:  /* 28   | (06)000021       */ call       int32 Hello.More.Edge::Abs(int32)
    IL_0061:  /* 58   |                  */ add
    IL_0062:  /* 2A   |                  */ ret
  } // end of method Edge::Pointers

  .method public hidebysig static int32  Arrays() cil managed
  // SIG: 00 00 08
  {
    // Method begins at RVA 0x2844
    // Code size       126 (0x7e)
    .maxstack  6
    .locals init (int32[0...,0...] V_0,
             int32[][] V_1,
             object V_2,
             class [System.Runtime]System.Type V_3,
             int32[0...,0...] V_4)
    IL_0000:  /* 19   |                  */ ldc.i4.3
    IL_0001:  /* 1A   |                  */ ldc.i4.4
    IL_0002:  /* 73   | (0A)000055       */ newobj     instance void int32[0...,0...]::.ctor(int32,
                                                                                             int32)
    IL_0007:  /* 0A   |                  */ stloc.0
    IL_0008:  /* 06   |                  */ ldloc.0
    IL_0009:  /* 17   |                  */ ldc.i4.1
    IL_000a:  /* 18   |                  */ ldc.i4.2
    IL_000b:  /* 1D   |                  */ ldc.i4.7
    IL_000c:  /* 28   | (0A)000056       */ call       instance void int32[0...,0...]::Set(int32,
                                                                                           int32,
                                                                                           int32)
    IL_0011:  /* 18   |                  */ ldc.i4.2
    IL_0012:  /* 8D   | (1B)000015       */ newarr     int32[]
    IL_0017:  /* 0B   |                  */ stloc.1
    IL_0018:  /* 07   |                  */ ldloc.1
    IL_0019:  /* 16   |                  */ ldc.i4.0
    IL_001a:  /* 18   |                  */ ldc.i4.2
    IL_001b:  /* 8D   | (01)000039       */ newarr     [System.Runtime]System.Int32
    IL_0020:  /* 25   |                  */ dup
    IL_0021:  /* 16   |                  */ ldc.i4.0
    IL_0022:  /* 17   |                  */ ldc.i4.1
    IL_0023:  /* 9E   |                  */ stelem.i4
    IL_0024:  /* 25   |                  */ dup
    IL_0025:  /* 17   |                  */ ldc.i4.1
    IL_0026:  /* 18   |                  */ ldc.i4.2
    IL_0027:  /* 9E   |                  */ stelem.i4
    IL_0028:  /* A2   |                  */ stelem.ref
    IL_0029:  /* 06   |                  */ ldloc.0
    IL_002a:  /* 0C   |                  */ stloc.2
    IL_002b:  /* D0   | (1B)000016       */ ldtoken    class [System.Collections]System.Collections.Generic.Dictionary`2<string,class [System.Collections]System.Collections.Generic.List`1<int32>>
    IL_0030:  /* 28   | (0A)000046       */ call       class [System.Runtime]System.Type [System.Runtime]System.Type::GetTypeFromHandle(valuetype [System.Runtime]System.RuntimeTypeHandle)
    IL_0035:  /* 0D   |                  */ stloc.3
    IL_0036:  /* 08   |                  */ ldloc.2
    IL_0037:  /* 75   | (1B)000014       */ isinst     int32[0...,0...]
    IL_003c:  /* 13   | 04               */ stloc.s    V_4
    IL_003e:  /* 11   | 04               */ ldloc.s    V_4
    IL_0040:  /* 2C   | 30               */ brfalse.s  IL_0072

    IL_0042:  /* 08   |                  */ ldloc.2
    IL_0043:  /* 75   | (01)000037       */ isinst     [System.Runtime]System.String
    IL_0048:  /* 2D   | 28               */ brtrue.s   IL_0072

    IL_004a:  /* 11   | 04               */ ldloc.s    V_4
    IL_004c:  /* 17   |                  */ ldc.i4.1
    IL_004d:  /* 18   |                  */ ldc.i4.2
    IL_004e:  /* 28   | (0A)000057       */ call       instance int32 int32[0...,0...]::Get(int32,
                                                                                            int32)
    IL_0053:  /* 07   |                  */ ldloc.1
    IL_0054:  /* 16   |                  */ ldc.i4.0
    IL_0055:  /* 9A   |                  */ ldelem.ref
    IL_0056:  /* 17   |                  */ ldc.i4.1
    IL_0057:  /* 94   |                  */ ldelem.i4
    IL_0058:  /* 58   |                  */ add
    IL_0059:  /* 09   |                  */ ldloc.3
    IL_005a:  /* 6F   | (0A)000058       */ callvirt   instance string [System.Runtime]System.Reflection.MemberInfo::get_Name()
    IL_005f:  /* 6F   | (0A)000052       */ callvirt   instance int32 [System.Runtime]System.String::get_Length()
    IL_0064:  /* 58   |                  */ add
    IL_0065:  /* 1B   |                  */ ldc.i4.5
    IL_0066:  /* 8C   | (01)000039       */ box        [System.Runtime]System.Int32
    IL_006b:  /* A5   | (01)000039       */ unbox.any  [System.Runtime]System.Int32
    IL_0070:  /* 58   |                  */ add
    IL_0071:  /* 2A   |                  */ ret

    IL_0072:  /* 08   |                  */ ldloc.2
    IL_0073:  /* 74   | (1B)000014       */ castclass  int32[0...,0...]
    IL_0078:  /* 6F   | (0A)000059       */ callvirt   instance int32 [System.Runtime]System.Array::get_Length()
    IL_007d:  /* 2A   |                  */ ret
  } // end of method Edge::Arrays

  .method public hidebysig static int32  Five(int32 a,
                                              int32 b,
                                              int32 c,
                                              int32 d,
                                              int32 'value',
                                              int32 'object',
                                              int32& 'method',
                                              [out] int32& 'field') cil managed
  // SIG: 00 08 08 08 08 08 08 08 08 10 08 10 08
  {
    // Method begins at RVA 0x28ce
    // Code size       27 (0x1b)
    .maxstack  8
    IL_0000:  /* 0E   | 07               */ ldarg.s    'field'
    IL_0002:  /* 0E   | 04               */ ldarg.s    'value'
    IL_0004:  /* 0E   | 05               */ ldarg.s    'object'
    IL_0006:  /* 58   |                  */ add
    IL_0007:  /* 54   |                  */ stind.i4
    IL_0008:  /* 0E   | 06               */ ldarg.s    'method'
    IL_000a:  /* 0E   | 06               */ ldarg.s    'method'
    IL_000c:  /* 4A   |                  */ ldind.i4
    IL_000d:  /* 17   |                  */ ldc.i4.1
    IL_000e:  /* 58   |                  */ add
    IL_000f:  /* 54   |                  */ stind.i4
    IL_0010:  /* 02   |                  */ ldarg.0
    IL_0011:  /* 03   |                  */ ldarg.1
    IL_0012:  /* 58   |                  */ add
    IL_0013:  /* 04   |                  */ ldarg.2
    IL_0014:  /* 58   |                  */ add
    IL_0015:  /* 05   |                  */ ldarg.3
    IL_0016:  /* 58   |                  */ add
    IL_0017:  /* 0E   | 04               */ ldarg.s    'value'
    IL_0019:  /* 58   |                  */ add
    IL_001a:  /* 2A   |                  */ ret
  } // end of method Edge::Five

  .method public hidebysig static string 
          Generic<(Hello.More.IShape) T>(!!T item) cil managed
  // SIG: 10 01 01 0E 1E 00
  {
    // Method begins at RVA 0x28ec
    // Code size       98 (0x62)
    .maxstack  4
    .locals init (float64 V_0,
             !!T V_1,
             int32 V_2)
    IL_0000:  /* 0F   | 00               */ ldarga.s   item
    IL_0002:  /* FE16 | (1B)000007       */ constrained. !!T
    IL_0008:  /* 6F   | (06)000011       */ callvirt   instance string Hello.More.IShape::get_Name()
    IL_000d:  /* 0F   | 00               */ ldarga.s   item
    IL_000f:  /* FE16 | (1B)000007       */ constrained. !!T
    IL_0015:  /* 6F   | (06)000010       */ callvirt   instance float64 Hello.More.IShape::Area()
    IL_001a:  /* 0A   |                  */ stloc.0
    IL_001b:  /* 12   | 00               */ ldloca.s   V_0
    IL_001d:  /* 72   | (70)000354       */ ldstr      "F1"
    IL_0022:  /* 28   | (0A)00005A       */ call       instance string [System.Runtime]System.Double::ToString(string)
    IL_0027:  /* 12   | 01               */ ldloca.s   V_1
    IL_0029:  /* FE15 | (1B)000007       */ initobj    !!T
    IL_002f:  /* 07   |                  */ ldloc.1
    IL_0030:  /* 8C   | (1B)000007       */ box        !!T
    IL_0035:  /* 2D   | 03               */ brtrue.s   IL_003a

    IL_0037:  /* 14   |                  */ ldnull
    IL_0038:  /* 2B   | 14               */ br.s       IL_004e

    IL_003a:  /* 12   | 01               */ ldloca.s   V_1
    IL_003c:  /* 25   |                  */ dup
    IL_003d:  /* FE15 | (1B)000007       */ initobj    !!T
    IL_0043:  /* FE16 | (1B)000007       */ constrained. !!T
    IL_0049:  /* 6F   | (0A)000044       */ callvirt   instance string [System.Runtime]System.Object::ToString()
    IL_004e:  /* FE1C | (02)000003       */ sizeof     Hello.Point
    IL_0054:  /* 0C   |                  */ stloc.2
    IL_0055:  /* 12   | 02               */ ldloca.s   V_2
    IL_0057:  /* 28   | (0A)00003A       */ call       instance string [System.Runtime]System.Int32::ToString()
    IL_005c:  /* 28   | (0A)00005B       */ call       string [System.Runtime]System.String::Concat(string,
                                                                                                    string,
                                                                                                    string,
                                                                                                    string)
    IL_0061:  /* 2A   |                  */ ret
  } // end of method Edge::Generic

  .method public hidebysig static valuetype [System.Runtime]System.Decimal 
          Money(valuetype [System.Runtime]System.Decimal m) cil managed
  // SIG: 00 01 11 80 C1 11 80 C1
  {
    // Method begins at RVA 0x295a
    // Code size       18 (0x12)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 1F   | 0F               */ ldc.i4.s   15
    IL_0003:  /* 16   |                  */ ldc.i4.0
    IL_0004:  /* 16   |                  */ ldc.i4.0
    IL_0005:  /* 16   |                  */ ldc.i4.0
    IL_0006:  /* 17   |                  */ ldc.i4.1
    IL_0007:  /* 73   | (0A)00005C       */ newobj     instance void [System.Runtime]System.Decimal::.ctor(int32,
                                                                                                           int32,
                                                                                                           int32,
                                                                                                           bool,
                                                                                                           uint8)
    IL_000c:  /* 28   | (0A)00005D       */ call       valuetype [System.Runtime]System.Decimal [System.Runtime]System.Decimal::op_Multiply(valuetype [System.Runtime]System.Decimal,
                                                                                                                                            valuetype [System.Runtime]System.Decimal)
    IL_0011:  /* 2A   |                  */ ret
  } // end of method Edge::Money

  .method public hidebysig static uint64 
          Unsigned(uint32 a,
                   uint64 b,
                   uint8 c,
                   uint16 d) cil managed
  // SIG: 00 04 0B 09 0B 05 07
  {
    // Method begins at RVA 0x296d
    // Code size       22 (0x16)
    .maxstack  8
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 6E   |                  */ conv.u8
    IL_0002:  /* 03   |                  */ ldarg.1
    IL_0003:  /* D7   |                  */ add.ovf.un
    IL_0004:  /* 04   |                  */ ldarg.2
    IL_0005:  /* 6E   |                  */ conv.u8
    IL_0006:  /* D7   |                  */ add.ovf.un
    IL_0007:  /* 05   |                  */ ldarg.3
    IL_0008:  /* 6E   |                  */ conv.u8
    IL_0009:  /* D7   |                  */ add.ovf.un
    IL_000a:  /* 03   |                  */ ldarg.1
    IL_000b:  /* 2C   | 03               */ brfalse.s  IL_0010

    IL_000d:  /* 03   |                  */ ldarg.1
    IL_000e:  /* 2B   | 02               */ br.s       IL_0012

    IL_0010:  /* 17   |                  */ ldc.i4.1
    IL_0011:  /* 6A   |                  */ conv.i8
    IL_0012:  /* 5C   |                  */ div.un
    IL_0013:  /* 19   |                  */ ldc.i4.3
    IL_0014:  /* 64   |                  */ shr.un
    IL_0015:  /* 2A   |                  */ ret
  } // end of method Edge::Unsigned

  .method public hidebysig static void  Locks(object gate) cil managed
  // SIG: 00 01 01 1C
  {
    // Method begins at RVA 0x2984
    // Code size       35 (0x23)
    .maxstack  2
    .locals init (object V_0,
             bool V_1)
    IL_0000:  /* 02   |                  */ ldarg.0
    IL_0001:  /* 0A   |                  */ stloc.0
    IL_0002:  /* 16   |                  */ ldc.i4.0
    IL_0003:  /* 0B   |                  */ stloc.1
    .try
    {
      IL_0004:  /* 06   |                  */ ldloc.0
      IL_0005:  /* 12   | 01               */ ldloca.s   V_1
      IL_0007:  /* 28   | (0A)00005E       */ call       void [System.Threading]System.Threading.Monitor::Enter(object,
                                                                                                                bool&)
      IL_000c:  /* 28   | (0A)00005F       */ call       int32 [System.Runtime]System.Environment::get_TickCount()
      IL_0011:  /* 28   | (0A)000060       */ call       void [System.Console]System.Console::WriteLine(int32)
      IL_0016:  /* DE   | 0A               */ leave.s    IL_0022

    }  // end .try
    finally
    {
      IL_0018:  /* 07   |                  */ ldloc.1
      IL_0019:  /* 2C   | 06               */ brfalse.s  IL_0021

      IL_001b:  /* 06   |                  */ ldloc.0
      IL_001c:  /* 28   | (0A)000061       */ call       void [System.Threading]System.Threading.Monitor::Exit(object)
      IL_0021:  /* DC   |                  */ endfinally
    }  // end handler
    // HEX: 02 00 04 00 14 18 00 0A 00 00 00 00
    IL_0022:  /* 2A   |                  */ ret
  } // end of method Edge::Locks

  .method public hidebysig static valuetype [System.Runtime]System.ValueTuple`2<int32,string> 
          Tuple() cil managed
  // SIG: 00 00 15 11 80 C5 02 08 0E
  {
    // Method begins at RVA 0x29c4
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  /* 17   |                  */ ldc.i4.1
    IL_0001:  /* 72   | (70)00000B       */ ldstr      "one"
    IL_0006:  /* 73   | (0A)000062       */ newobj     instance void valuetype [System.Runtime]System.ValueTuple`2<int32,string>::.ctor(!0,
                                                                                                                                        !1)
    IL_000b:  /* 2A   |                  */ ret
  } // end of method Edge::Tuple

} // end of class Hello.More.Edge

.class private auto ansi sealed '<PrivateImplementationDetails>'
       extends [System.Runtime]System.Object
{
  .class explicit ansi sealed nested assembly '__StaticArrayInitTypeSize=3'
         extends [System.Runtime]System.ValueType
  {
    .pack 1
    .size 3
  } // end of class '__StaticArrayInitTypeSize=3'

  .class explicit ansi sealed nested assembly '__StaticArrayInitTypeSize=32'
         extends [System.Runtime]System.ValueType
  {
    .pack 1
    .size 32
  } // end of class '__StaticArrayInitTypeSize=32'

  .field static assembly initonly valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=3' '039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81' at I_000051B8
  .field static assembly initonly valuetype '<PrivateImplementationDetails>'/'__StaticArrayInitTypeSize=32' '8B4B2444E57AED8C2D05A1293255DA1B048C63224317D4666230760935FA4A18' at I_000051C0
} // end of class '<PrivateImplementationDetails>'


// =============================================================

.data cil I_000051B8 = bytearray (
                 01 02 03) 
.data cil I_000051BB = int8[5]
.data cil I_000051C0 = bytearray (
                 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00
                 05 00 00 00 06 00 00 00 07 00 00 00 08 00 00 00) 
// *********** DISASSEMBLY COMPLETE ***********************
