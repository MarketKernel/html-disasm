// Writes the classes javac cannot make, with the ClassFile API of Java 24+:
// hello/Old.class, a Java 5 class file with subroutines (jsr, ret and their
// wide forms) and goto_w; hello/Odd.class, with the stack operations javac
// never uses as they come (swap, dup_x2, dup2_x2…), constants javac never
// loads (method handles, method types, a dynamic constant, ldc_w where ldc
// would do), switches with no cases or one, and names javap quotes.
//
//   java Odd.java <output directory>
import java.lang.classfile.*;
import java.lang.classfile.constantpool.*;
import java.lang.classfile.instruction.*;
import java.lang.constant.*;
import java.nio.file.*;
import java.util.List;
import static java.lang.classfile.ClassFile.*;
import static java.lang.constant.ConstantDescs.*;

public class Odd {
    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0], "hello");
        Files.createDirectories(out);
        var cf = ClassFile.of(StackMapsOption.DROP_STACK_MAPS, DeadCodeOption.KEEP_DEAD_CODE, ShortJumpsOption.FAIL_ON_SHORT_JUMPS);

        byte[] old = cf.build(ClassDesc.of("hello.Old"), cb -> {
            cb.withVersion(49, 0).withFlags(ACC_PUBLIC | ACC_SUPER).withSuperclass(CD_Object);
            cb.withMethodBody("subroutines", MethodTypeDesc.of(CD_int, CD_int), ACC_PUBLIC | ACC_STATIC, code -> {
                Label sub = code.newLabel(), far = code.newLabel(), end = code.newLabel(), wideSub = code.newLabel();
                code.with(DiscontinuedInstruction.JsrInstruction.of(Opcode.JSR, sub));
                code.with(DiscontinuedInstruction.JsrInstruction.of(Opcode.JSR_W, wideSub));
                code.branch(Opcode.GOTO_W, far);
                code.labelBinding(sub);
                code.astore(1);
                code.iinc(0, 1);
                code.with(DiscontinuedInstruction.RetInstruction.of(1));
                code.labelBinding(wideSub);
                code.astore(300);
                code.iinc(0, 2);
                code.with(DiscontinuedInstruction.RetInstruction.of(Opcode.RET_W, 300));
                code.labelBinding(far);
                code.iload(0);
                code.ifeq(end);
                code.iinc(0, -1);
                code.labelBinding(end);
                code.iload(0);
                code.ireturn();
            });
        });
        Files.write(out.resolve("Old.class"), old);

        ClassDesc odd = ClassDesc.of("hello.Odd");
        byte[] oddBytes = cf.build(odd, cb -> {
            cb.withVersion(69, 0).withFlags(ACC_PUBLIC | ACC_SUPER).withSuperclass(CD_Object);
            cb.withField("1st", CD_int, ACC_STATIC);
            cb.withField("with space", CD_long, ACC_STATIC);
            cb.withField("emoji😀", CD_String, ACC_STATIC);
            cb.withField("имя", CD_double, ACC_STATIC);
            cb.withMethodBody("stack", MethodTypeDesc.of(CD_long, CD_int, CD_long), ACC_PUBLIC | ACC_STATIC, code -> {
                code.iconst_1().iconst_2().swap().pop2();
                code.iload(0).iconst_3().iconst_4().dup_x2().pop2().pop2();
                code.lload(1).iconst_5().dup2_x1().pop2().pop().pop2();
                code.lload(1).lload(1).dup2_x2().pop2().pop2().pop2();
                code.iconst_0().iconst_1().iconst_2().iconst_3().dup2_x2().pop2().pop2().pop2();
                code.iload(0).iconst_1().dup2().pop2().pop2();
                code.iload(0).dup_x1().pop2();
                code.lload(1).lreturn();
            });
            cb.withMethodBody("weird-name", MethodTypeDesc.of(CD_void), ACC_PUBLIC | ACC_STATIC, code -> {
                code.getstatic(odd, "1st", CD_int).putstatic(odd, "1st", CD_int);
                code.getstatic(odd, "with space", CD_long).putstatic(odd, "with space", CD_long);
                code.getstatic(odd, "emoji😀", CD_String).putstatic(odd, "emoji😀", CD_String);
                code.getstatic(odd, "имя", CD_double).putstatic(odd, "имя", CD_double);
                code.getstatic(ClassDesc.ofInternalName("hello/weird-class"), "x", CD_int).pop();
                code.invokestatic(ClassDesc.ofInternalName("hello/weird-class"), "do it", MethodTypeDesc.of(CD_void));
                code.ldc(ClassDesc.ofDescriptor("[[Ljava/lang/String;")).pop();
                code.ldc(ClassDesc.ofDescriptor("[I")).pop();
                code.anewarray(ClassDesc.ofDescriptor("[I")).pop();
                code.return_();
            });
            cb.withMethodBody("constants", MethodTypeDesc.of(CD_Object), ACC_PUBLIC | ACC_STATIC, code -> {
                ConstantPoolBuilder cp = cb.constantPool();
                code.with(ConstantInstruction.ofLoad(Opcode.LDC_W, cp.stringEntry("wide ldc"))).pop();
                code.with(ConstantInstruction.ofLoad(Opcode.LDC_W, cp.intEntry(70000))).pop();
                code.with(ConstantInstruction.ofLoad(Opcode.LDC_W, cp.floatEntry(Float.NaN))).pop();
                code.ldc(cp.floatEntry(Float.intBitsToFloat(0x7fc00001))).pop();
                code.ldc(cp.doubleEntry(Double.longBitsToDouble(0x7ff0000000000001L))).pop2();
                code.ldc(cp.floatEntry(Float.NEGATIVE_INFINITY)).pop();
                code.ldc(cp.longEntry(Long.MIN_VALUE)).pop2();
                code.ldc(MethodTypeDesc.of(CD_int, CD_String, CD_long.arrayType())).pop();
                code.ldc(MethodHandleDesc.ofMethod(DirectMethodHandleDesc.Kind.STATIC, CD_Integer, "parseInt", MethodTypeDesc.of(CD_int, CD_String))).pop();
                code.ldc(MethodHandleDesc.ofMethod(DirectMethodHandleDesc.Kind.VIRTUAL, CD_String, "length", MethodTypeDesc.of(CD_int))).pop();
                code.ldc(MethodHandleDesc.ofMethod(DirectMethodHandleDesc.Kind.INTERFACE_VIRTUAL, CD_List, "size", MethodTypeDesc.of(CD_int))).pop();
                code.ldc(MethodHandleDesc.ofMethod(DirectMethodHandleDesc.Kind.CONSTRUCTOR, ClassDesc.of("java.lang.StringBuilder"), "<init>", MethodTypeDesc.of(CD_void))).pop();
                code.ldc(MethodHandleDesc.ofField(DirectMethodHandleDesc.Kind.STATIC_GETTER, odd, "1st", CD_int)).pop();
                code.ldc(MethodHandleDesc.ofField(DirectMethodHandleDesc.Kind.SETTER, ClassDesc.of("java.awt.Point"), "x", CD_int)).pop();
                code.ldc(DynamicConstantDesc.ofNamed(BSM_GET_STATIC_FINAL, "MAX_VALUE", CD_int, CD_Integer)).pop();
                code.ldc(DynamicConstantDesc.ofNamed(BSM_PRIMITIVE_CLASS, "I", CD_Class)).pop();
                code.ldc("\uD800 lone,   separator, ­ soft hyphen, \u0000 nul, ﻿ bom").pop();
                code.invokedynamic(DynamicCallSiteDesc.of(
                    MethodHandleDesc.ofMethod(DirectMethodHandleDesc.Kind.STATIC, ClassDesc.of("java.lang.invoke.StringConcatFactory"), "makeConcatWithConstants",
                        MethodTypeDesc.of(CD_CallSite, CD_MethodHandles_Lookup, CD_String, CD_MethodType, CD_String, CD_Object.arrayType())),
                    "makeConcatWithConstants", MethodTypeDesc.of(CD_String, CD_int), "n=\u0001!")).pop();
                code.aconst_null().areturn();
            });
            cb.withMethodBody("switches", MethodTypeDesc.of(CD_int, CD_int), ACC_PUBLIC | ACC_STATIC, code -> {
                Label a = code.newLabel(), b = code.newLabel(), c = code.newLabel(), d = code.newLabel();
                code.iload(0).lookupswitch(a, List.of());
                code.labelBinding(a);
                code.iload(0).tableswitch(5, 5, b, List.of(SwitchCase.of(5, c)));
                code.labelBinding(b);
                code.iload(0).tableswitch(-2, 1, c, List.of(SwitchCase.of(-2, d), SwitchCase.of(0, d)));
                code.labelBinding(c);
                code.iconst_0().ireturn();
                code.labelBinding(d);
                code.iconst_1().ireturn();
            });
            cb.withMethodBody("monitors", MethodTypeDesc.of(CD_void, CD_Object), ACC_PUBLIC | ACC_STATIC, code -> {
                code.aload(0).monitorenter().aload(0).monitorexit();
                code.aload(0).checkcast(CD_String).instanceOf(CD_String).pop();
                code.ldc(3).ldc(4).multianewarray(ClassDesc.ofDescriptor("[[[J"), 2).arraylength().pop();
                code.aload(0).athrow();
            });
        });
        Files.write(out.resolve("Odd.class"), oddBytes);
    }
}
