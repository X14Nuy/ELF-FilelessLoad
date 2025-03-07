#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>

#define _DYNAMIC 0x1

#define PAGE_SIZE	4096 // 页面大小
#define ALIGN		(PAGE_SIZE - 1) // 对齐
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN)) // 向上取整
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)


#define SERVER_PORT 12345          // 本地主机端口
#define BUFFER_SIZE 1048576        // 1MB缓冲区大小

unsigned char elf_buffer[BUFFER_SIZE]; // ELF 数据缓冲区

int fetch_elf_data() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    ssize_t total_received = 0, bytes_received;

    // 创建套接字
    server_sock = z_socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        z_errx(1, "socket creation failed");
    }

    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // 监听所有本地IP
    server_addr.sin_port = htons(SERVER_PORT);

    // 绑定地址到套接字
    if (z_bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        z_errx(1, "socket bind failed");
    }

    // 开始监听
    if (z_listen(server_sock, 1) < 0) {  // 最大连接队列设置为1
        z_errx(1, "socket listen failed");
    }

    // printf("Waiting for connection on port %d...\n", SERVER_PORT);

    // 接受客户端连接
    client_sock = z_accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len, 0);
    if (client_sock < 0) {
        z_errx(1, "socket accept failed");
    }

    // printf("Connection accepted.\n");

    // 接收数据
    while ((bytes_received = z_read(client_sock, elf_buffer + total_received, BUFFER_SIZE - total_received)) > 0) {
        total_received += bytes_received;
    }

    // printf("Data received, total bytes: %zd\n", total_received);

    // 关闭客户端和服务器套接字
    z_close(client_sock);
    z_close(server_sock);

    return total_received; // 返回接收的总字节数
}


// 释放资源
static void z_fini(void)
{
	z_printf("My fini function\n");
}

// 检查ELF头，检查了ELF魔数和ELF类型
static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}

// 加载ELF文件
static unsigned long loadelf_anon(Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;

	// 遍历程序头表，找到最小和最大的虚拟地址
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	// printf("minva: %lx, maxva: %lx\n", minva, maxva);

	minva = TRUNC_PG(minva); // 向下取整到页边界
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */	
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);

	if (base == (void *)-1){
		z_printf("mmap failed\n");

		return -1;
	}

	z_munmap(base, maxva - minva);
	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;

	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		// start是虚拟地址向下取整到页边界
		start = dyn ? (unsigned long)base : 0; // 如果是动态链接，则使用base
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		// 往段起始地址映射
		p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);

		// printf("p: %p, start: %lx, sz: %lx\n", p, start, sz);

		if (p == (void *)-1)
			goto err;

		z_memcpy(p + off, elf_buffer + iter->p_offset, iter->p_filesz);
		// 利用lseek将指针定位到段在文件中的起始位置
		// if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
		// 	goto err;
		// // 往p + off的地方写入段
		// if (z_read(fd, p + off, iter->p_filesz) !=
		// 		(ssize_t)iter->p_filesz)
		// 	goto err;


		// 利用mprotect重新更改段保护属性
		z_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

#define Z_PROG		0
#define Z_INTERP	1

void z_entry(unsigned long *sp, void (*fini)(void))
{
	Elf_Ehdr ehdrs, *ehdr = &ehdrs;
	Elf_Phdr *phdr;
	Elf_auxv_t *av;
	char **argv, **env, **p;
	unsigned long base, entry;
	// const char *file;
	ssize_t sz;
	int argc, i;

	(void)fini; // unused

	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	// env是环境变量指针
	env = p = (char **)&argv[argc + 1];
	while (*p++ != NULL)
		;
	// av是auxv_t结构体指针
	av = (void *)p;

	(void)env; // unused
	// if (argc < 2)
	// 	z_errx(1, "no input file");
	// file = argv[1];
	fetch_elf_data();
	
	/* Open file, read and than check ELF header.*/
	// if ((fd = z_open(file, O_RDONLY)) < 0)
	// 	z_errx(1, "can't open %s", file);

	z_memcpy(ehdr, elf_buffer, sizeof(*ehdr));

	z_printf("sizeof(*ehdr) = %d\n", sizeof(*ehdr));
	// 打印ehdr的内容
	z_printf("ehdr->e_ident = %s\n", ehdr->e_ident);
	z_printf("ehdr->e_type = %d\n", ehdr->e_type);
	z_printf("ehdr->e_machine = %d\n", ehdr->e_machine);
	z_printf("ehdr->e_version = %d\n", ehdr->e_version);
	z_printf("ehdr->e_entry = %p\n", ehdr->e_entry);
	z_printf("ehdr->e_phoff = %d\n", ehdr->e_phoff);

	// if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
	// 	z_errx(1, "can't read ELF header %s", file);

	if (!check_ehdr(ehdr))
		z_errx(1, "bogus ELF header");

	/* Read the program header. */
	sz = ehdr->e_phnum * sizeof(Elf_Phdr);
	phdr = z_alloca(sz);
	z_memcpy(phdr, elf_buffer + ehdr->e_phoff, sz);
	// if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
	// 	z_errx(1, "can't lseek to program header %s", file);		
	// if (z_read(fd, phdr, sz) != sz)
	// if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
	// 	z_errx(1, "can't lseek to program header %s", file);		
	// if (z_read(fd, phdr, sz) != sz)
	// 	z_errx(1, "can't read program header %s", file);
	/* Time to load ELF. */

	if ((base = loadelf_anon(ehdr, phdr)) == LOAD_ERR)
		z_errx(1, "can't load ELF");

	/* Set the entry point, if the file is dynamic than add bias. */
	entry = ehdr->e_entry;
	// printf("entry = %p\n", entry);
	// /* The second round, we've loaded ELF interp. */
	// if (file == elf_interp) {
	// 	z_close(fd);
	// 	break;
	// }

	// // 遍历 ELF 文件的程序头表，寻找类型为 PT_INTERP 的段。
	// // PT_INTERP 是 ELF 中的 "interpreter" 段，指示动态 ELF 文件需要的动态链接器路径。
	// for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
	// 	if (iter->p_type != PT_INTERP)
	// 		continue;
	// 	elf_interp = z_alloca(iter->p_filesz); // PT_INTERP 段的内容通常只有一条动态链接器的路径
	// 	if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
	// 		z_errx(1, "can't lseek interp segment");
	// 	if (z_read(fd, elf_interp, iter->p_filesz) !=
	// 			(ssize_t)iter->p_filesz)
	// 		z_errx(1, "can't read interp segment");
	// 	if (elf_interp[iter->p_filesz - 1] != '\0') // 检查动态链接器路径是否以 \0 结尾。
	// 	file = elf_interp;
	// }

	// z_close(fd);
	// /* Looks like the ELF is static -- leave the loop. */
	// // 遍历完所有程序头表，没有找到 PT_INTERP 段，说明该 ELF 文件是静态链接的，直接跳出循环。
	// if (elf_interp == NULL)
	// 	break;

	/* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */

#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		// 将当前的辅助向量表中的 AT_PHDR、AT_PHNUM、AT_PHENT、AT_ENTRY、AT_EXECFN 设置为 ELF 文件中的值。
		AVSET(AT_PHDR, av, base + ehdrs.e_phoff);
		AVSET(AT_PHNUM, av, ehdrs.e_phnum);
		AVSET(AT_PHENT, av, ehdrs.e_phentsize);
		AVSET(AT_ENTRY, av, entry);
		AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
		// AVSET(AT_BASE, av, elf_interp ? base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;
	/* Shift argv, env and av. */
	// 因为argv[0]是ELF文件名，所以将argv[1]及其后面的参数都向前移动一个位置，包括argv、env和av。
	z_memcpy(&argv[0], &argv[1],
		 (unsigned long)av - (unsigned long)&argv[1]);
	/* SP points to argc. */
	// 参数数量要减一
	(*sp)--;
	// 汇编语言编写的函数，用于调用动态链接器或直接跳转到程序入口点。
	z_trampo((void (*)(void))entry, sp, z_fini);
	/* Should not reach. */
	z_exit(0);
}

void _init(void) {
    // 执行初始化操作
}

void _fini(void) {
    // 执行清理操作
}
