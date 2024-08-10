cmd_/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o := gcc -Wp,-MMD,/home/lanto/Documents/linux-kernel-antivirus/kernel/.av_char_dev.o.d -nostdinc -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h -D__KERNEL__ -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu11 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -mfunction-return=thunk-extern -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fstack-protector-strong -Wno-main -Wno-unused-but-set-variable -Wno-unused-const-variable -fomit-frame-pointer -Wvla -Wno-pointer-sign -Wno-maybe-uninitialized -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -g -gdwarf-5 -DAV_NETLINK  -DMODULE  -DKBUILD_BASENAME='"av_char_dev"' -DKBUILD_MODNAME='"av"' -D__KBUILD_MODNAME=kmod_av -c -o /home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o /home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.c   ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --orc --retpoline --rethunk --static-call --uaccess   --module /home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o

source_/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o := /home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.c

deps_/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o := \
  include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  include/linux/compiler_attributes.h \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/RETPOLINE) \
    $(wildcard include/config/GCC_ASM_GOTO_OUTPUT_WORKAROUND) \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/SHADOW_CALL_STACK) \
    $(wildcard include/config/KCOV) \

/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o: $(deps_/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o)

$(deps_/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o):

/home/lanto/Documents/linux-kernel-antivirus/kernel/av_char_dev.o: $(wildcard ./tools/objtool/objtool)
