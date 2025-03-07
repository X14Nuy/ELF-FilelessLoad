# # make ARCH=i386 SMALL=1 DEBUG=1

# ARCH ?= amd64

# # 支持架构i386 amd64 aarch64
# ARCHS32 := i386
# ARCHS64 := amd64 aarch64
# ARCHS := $(ARCHS32) $(ARCHS64)

# # 编译选项
# # 禁用栈保护
# CFLAGS += -pipe -Wall -Wextra -fPIC -fno-ident -fno-stack-protector -U _FORTIFY_SOURCE
# LDFLAGS += -nostartfiles #-nodefaultlibs -nostdlib 
# LDFLAGS += -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none
# TARGET := loader

# ifeq "$(filter $(ARCH),$(ARCHS))" ""
#   $(error ARCH='$(ARCH)' is not supported)
# endif

# ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
#   CFLAGS += -m32 -DELFCLASS=ELFCLASS32
#   ASFLAGS += -m32
#   LDFLAGS += -m32
# else
#   CFLAGS += -DELFCLASS=ELFCLASS64
# endif

# ifdef DEBUG
#   CFLAGS += -O0 -g
#   ASFLAGS += -g
# else
#   CFLAGS += -fvisibility=hidden
#   # Disable unwind info to make prog smaller.
#   CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables
#   LDFLAGS += -s
# endif

# OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
# OBJS += $(patsubst %.S,%.o, $(wildcard $(ARCH)/*.S))

# ifdef SMALL
#   OBJS := $(filter-out z_printf.%,$(OBJS))
#   OBJS := $(filter-out z_err.%,$(OBJS))
#   CFLAGS += -DZ_SMALL
# endif

# .PHONY: clean all

# all: $(TARGET)

# loader: $(OBJS)

# clean:
# 	rm -rf *.o $(TARGET) */*.o


# 默认架构为 amd64
ARCH ?= amd64

# 支持的架构
ARCHS32 := i386 arm
ARCHS64 := amd64 aarch64
ARCHS := $(ARCHS32) $(ARCHS64)

# 编译器选择：根据架构选择不同的交叉编译器
ifeq ($(ARCH), amd64)
    CC = x86_64-linux-gnu-gcc
    AS = x86_64-linux-gnu-as
    LD = x86_64-linux-gnu-ld
endif

ifeq ($(ARCH), aarch64)
    CC = aarch64-linux-gnu-gcc
    AS = aarch64-linux-gnu-as
    LD = aarch64-linux-gnu-ld
endif

ifeq ($(ARCH), arm)
    CC = arm-linux-gnueabi-gcc
    AS = arm-linux-gnueabi-as
    LD = arm-linux-gnueabi-ld
endif

# 编译选项
CFLAGS += -pipe -Wall -Wextra -fno-ident -fno-stack-protector -U _FORTIFY_SOURCE
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib
LDFLAGS += -L/usr/lib32/ -Wl,-Ttext,0x10000 -static -e z_start -Wl,-Bsymbolic,--build-id=none
TARGET := loader

ifeq "$(filter $(ARCH),$(ARCHS))" ""
  $(error ARCH='$(ARCH)' is not supported)
endif

# 针对不同架构添加不同的编译选项
ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
  CFLAGS += -m32 -DELFCLASS=ELFCLASS32
  ASFLAGS += -m32
  LDFLAGS += -m32
endif

ifeq ($(ARCH), arm)
  # 如果是 ARM 架构，移除 -m32 选项（ARM 默认是 32 位，不需要此选项）
  CFLAGS := $(filter-out -m32, $(CFLAGS))
  LDFLAGS := $(filter-out -m32, $(LDFLAGS))
  ASFLAGS := $(filter-out -m32, $(ASFLAGS))
endif


ifeq "$(ARCH)" "aarch64"
  # aarch64 默认编译为 64 位，不需要添加 -m32 或 -m64
  CFLAGS += -DELFCLASS=ELFCLASS64
  # 64 位 ARM 编译不需要额外的选项
endif

ifdef DEBUG
  CFLAGS += -O0 -g
  ASFLAGS += -g
else
  CFLAGS += -fvisibility=hidden
  # Disable unwind info to make prog smaller.
  CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables
  LDFLAGS += -s
endif

# 目标文件
OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.S,%.o, $(wildcard $(ARCH)/*.S))

ifdef SMALL
  OBJS := $(filter-out z_printf.%,$(OBJS))
  OBJS := $(filter-out z_err.%,$(OBJS))
  CFLAGS += -DZ_SMALL
endif

.PHONY: clean all

all: $(TARGET)

loader: $(OBJS)

clean:
	rm -rf *.o $(TARGET) */*.o
