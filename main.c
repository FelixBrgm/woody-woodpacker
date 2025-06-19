#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20 // cant find MAP_ANONYMOUS in sys/mman.h when running on Macs
#endif

int elf64_ident_check(const Elf64_Ehdr *header);

int
main(int ac, char **av) {
    if (ac != 2) {
        printf("wrong usage: ./woody BINARY_NAME\n");
        return 1;
    }

    int fd_orig = open(av[1], O_RDONLY);
    if (fd_orig == -1) {
        fprintf(stderr, "error while opening %s\n", av[1]);
        return 1;
    }

    int fd_new = open("woody", O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd_new == -1) {
        perror("could not create new 'woody' binary:\n");
        return 1;
    }

    Elf64_Ehdr header;

    int bytes_read = read(fd_orig, &header, sizeof(header));
    if (bytes_read != sizeof(header)) {
        fprintf(stderr, "error while reading %s\n", av[1]);
        return 1;
    }

    printf("%p\n", header.e_shoff);
    printf("%p\n", header.e_phoff);

    int err = elf64_ident_check(&header);
    if (err) {
        printf("error while checking ident of elf with code: %i\n", err);
        return 1;
    }

    err = lseek(fd_orig, 0, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    char buf[100];
    do {
        bytes_read = read(fd_orig, &buf, sizeof(buf));
        if (bytes_read == -1) {
            fprintf(stderr, "error while reading %s\n", av[1]);
            return 1;
        }
        int bytes_written = write(fd_new, &buf, bytes_read);
        if (bytes_written == -1) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    } while (bytes_read == sizeof(buf));

    // copy stup at the end
    // int decrypt_offs = lseek(fd_new, 0, SEEK_END);
    // if (err == -1) {
    //     fprintf(stderr, "error while lseeking\n");
    //     return 1;
    // }

    // unsigned char exit_code_4_shellcode[] = {
    //     0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
    //     0x48, 0xc7, 0xc7, 0x04, 0x00, 0x00, 0x00, // mov rdi, 4
    //     0x0f, 0x05                                // syscall
    // };

    // int decrypt_size = sizeof(exit_code_4_shellcode);

    // int bytes_written = write(fd_new, &exit_code_4_shellcode, sizeof(exit_code_4_shellcode));
    // if (bytes_written != sizeof(exit_code_4_shellcode)) {
    //     fprintf(stderr, "error while writting to `woody`\n");
    //     return 1;
    // }

    // Copy section header table at the end of new file
    err = lseek(fd_orig, header.e_shoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }
    int section_header_offs = lseek(fd_new, 0, SEEK_END);
    if (section_header_offs == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    Elf64_Shdr section_header = {0};
    for (int i = 0; i < header.e_shnum; i++) {
        bytes_read = read(fd_orig, &section_header, sizeof(section_header));
        if (bytes_read != sizeof(section_header)) {
            fprintf(stderr, "error while reading %s\n", av[1]);
            return 1;
        }

        int bytes_written = write(fd_new, &section_header, bytes_read);
        if (bytes_written != bytes_read) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    }

    // 0'ro the section header in new to make sure it's not used
    err = lseek(fd_new, header.e_shoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    Elf64_Shdr section_header_empty = {0};
    for (int i = 0; i < header.e_shnum; i++) {
        int bytes_written = write(fd_new, &section_header_empty, sizeof(section_header_empty));
        if (bytes_written != sizeof(section_header_empty)) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    }

    // Insert new section_header
    // err = lseek(fd_new, 0, SEEK_END);
    // if (err == -1) {
    //     fprintf(stderr, "error while lseeking in %s\n", av[1]);
    //     return 1;
    // }
    // Elf64_Shdr section_header_insert = {.sh_name = 0, // e.g. 1 (if .shstrtab = "\0.text\0.data\0...")
    //                                     .sh_type = SHT_PROGBITS,
    //                                     .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
    //                                     .sh_addr = 0x60000,         // VA of .text in memory
    //                                     .sh_offset = decrypt_offs, // Offset in file
    //                                     .sh_size = decrypt_size,   // Length of .text
    //                                     .sh_link = 0,
    //                                     .sh_info = 0,
    //                                     .sh_addralign = 4096,
    //                                     .sh_entsize = 0};

    // int bytes_written = write(fd_new, &section_header_insert, sizeof(section_header_insert));
    // if (bytes_written != sizeof(section_header_insert)) {
    //     fprintf(stderr, "error while writting to `woody`\n");
    //     return 1;
    // }

    // Set sh_off in header to correct new value
    header.e_shoff = section_header_offs;
    // header.e_shnum++;
    err = lseek(fd_new, 0, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    int bytes_written = write(fd_new, &header, sizeof(header));
    if (bytes_written != sizeof(header)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    // Program headers
    // Copy program headers to the end
    err = lseek(fd_orig, header.e_phoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }
    int program_header_offset = lseek(fd_new, 0, SEEK_END);
    if (program_header_offset == -1) {
        fprintf(stderr, "error while lseeking\n");
        return 1;
    }

    Elf64_Phdr program_header = {0};
    for (int i = 0; i < header.e_phnum; i++) {
        bytes_read = read(fd_orig, &program_header, sizeof(program_header));
        if (bytes_read != sizeof(program_header)) {
            fprintf(stderr, "error while reading %s\n", av[1]);
            return 1;
        }

        int bytes_written = write(fd_new, &program_header, sizeof(program_header));
        if (bytes_written != sizeof(program_header)) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    }

    // 0'ro the program header in new to make sure it's not used
    err = lseek(fd_new, header.e_phoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    Elf64_Phdr program_header_empty = {0};
    for (int i = 0; i < header.e_phnum; i++) {
        int bytes_written = write(fd_new, &program_header_empty, sizeof(program_header_empty));
        if (bytes_written != sizeof(program_header_empty)) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    }

    // Insert new program header
    // err = lseek(fd_new, 0, SEEK_END);
    // if (err == -1) {
    //     fprintf(stderr, "error while lseeking in %s\n", av[1]);
    //     return 1;
    // }

    // Elf64_Phdr program_header_insert = {
    //     .p_type = PT_LOAD,        // Loadable segment
    //     .p_flags = PF_R | PF_X,   // Read + Execute
    //     .p_offset = decrypt_offs, // Offset in file
    //     .p_vaddr = 0x60000,        // Virtual address
    //     .p_paddr = 0x0,           // Physical address (ignored on most systems)
    //     .p_filesz = decrypt_size, // Size in file
    //     .p_memsz = decrypt_size,  // Size in memory (same unless .bss)
    //     .p_align = 0x1000         // Must be page-aligned (4096 bytes)
    // };
    // bytes_written = write(fd_new, &program_header_insert, sizeof(program_header_insert));
    // if (bytes_written != sizeof(program_header_insert)) {
    //     fprintf(stderr, "error while writting to `woody`\n");
    //     return 1;
    // }

    // Set sh_off in header to correct new value
    header.e_phoff = program_header_offset;
    // header.e_phnum++;
    // header.e_entry = 0x60000;
    err = lseek(fd_new, 0, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking in %s\n", av[1]);
        return 1;
    }

    bytes_written = write(fd_new, &header, sizeof(header));
    if (bytes_written != sizeof(header)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    close(fd_orig);
    close(fd_new);
}

int
elf64_ident_check(const Elf64_Ehdr *header) {
    assert(header);

    if (header->e_ident[EI_MAG0] != ELFMAG0) return 1;
    if (header->e_ident[EI_MAG1] != ELFMAG1) return 1;
    if (header->e_ident[EI_MAG2] != ELFMAG2) return 1;
    if (header->e_ident[EI_MAG3] != ELFMAG3) return 1;

    if (header->e_ident[EI_CLASS] != ELFCLASS64) return 2;

    if (header->e_ident[EI_DATA] == ELFDATANONE) return 3;

    if (header->e_ident[EI_VERSION] != EV_CURRENT) return 4;

    for (int i = EI_PAD; i < sizeof(header); i++) {
        if (header->e_ident[i] != 0) return 5;
    }
    return 0;
}
