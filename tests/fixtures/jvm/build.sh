#!/bin/sh
# Builds what the JVM tests open: src/hello/Hello.java (the same program as hello.c, in Java) with
# its local variables' names (-g), src/hello/More.java (every kind of operand, and the constants
# javap writes in its own ways) without them, and the classes javac cannot make, written by
# Odd.java with the ClassFile API — subroutines in a Java 5 class, method handle constants,
# names javap quotes — into one JAR, hello.jar, with Main-Class hello.Hello; and hello.javap,
# javap's text of it, which tests/jvm.mjs compares the decoder with. Needs JDK 25 (javac, java,
# jar and javap on the PATH).
set -e
cd "$(dirname "$0")"
rm -rf out && mkdir out
javac --release 25 -g -d out src/hello/Hello.java
javac --release 25 -d out -cp out src/hello/More.java
java Odd.java out
# The same time for every entry, so the JAR is the same from one build to the next.
jar --create --file hello.jar --main-class hello.Hello --date 2026-01-01T00:00:00Z -C out .
rm -rf out
node ../../../tools/verify-jvm.mjs hello.jar --reference hello.javap
