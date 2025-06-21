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

int elf64_ident_check(const Elf64_Ehdr *header);

int
elf_header_parse(int fd, Elf64_Ehdr *header) {

    int bytes_read = read(fd, header, sizeof(header));
    if (bytes_read != sizeof(header)) {
        perror("read");
        return 1;
    }

    return elf64_ident_check(header);
}

int
fd_copy_whole(int fd_dest, int fd_src) {

    int bytes_read;
    int bytes_written;

    int off = lseek(fd_src, 0, SEEK_SET);
    if (off == -1) {
        perror("lseek - fd_src");
        return 1;
    }

    char buf[100];
    do {
        bytes_read = read(fd_src, &buf, sizeof(buf));
        if (bytes_read == -1) {
            perror("read - fd_src");
            return 1;
        }
        bytes_written = write(fd_dest, &buf, bytes_read);
        if (bytes_written == -1) {
            perror("write - fd_dest");
            return 1;
        }
    } while (bytes_read == sizeof(buf));

    return 0;
}

int
shellcode_add_at_end(int fd, unsigned char *shellcode, uint64_t size) {
    int bytes_written;

    int shellcode_off = lseek(fd, 0, SEEK_END);
    if (shellcode_off == -1) {
        perror("lseek - woody");
        return -1;
    }

    const int alignment = 0x1000;
    if (shellcode_off % alignment != 0) {
        const int padding = alignment - (shellcode_off % alignment);
        shellcode_off = lseek(fd, padding, SEEK_CUR);
        if (shellcode_off == -1) {
            perror("lseek - woody");
            return -1;
        }
    }

    bytes_written = write(fd, &shellcode, size);
    if (bytes_written != size) {
        perror("write - woody");
        return -1;
    }

    return shellcode_off;
}

int
program_header_note_get(int fd, const Elf64_Ehdr header, Elf64_Phdr *program_header_note) {
    int off = lseek(fd, header.e_phoff, SEEK_SET);
    if (off == -1) {
        perror("lseek - woody");
        return -1;
    }

    printf("%lx\n", off);
    printf("%lx\n", header.e_phoff);

    int program_header_note_off = 0;
    for (int i = 0; i < header.e_phnum; i++) {
        int bytes_read = read(fd, &program_header_note, sizeof(Elf64_Phdr));
        if (bytes_read != sizeof(Elf64_Phdr)) {
            perror("read - woody");
            return -1;
        }

        program_header_note_off = header.e_phoff + i * sizeof(Elf64_Phdr);
        if (program_header_note->p_type == PT_NOTE) break;
    }

    if (program_header_note->p_type != PT_NOTE) {
        fprintf(stderr, "could not find PT_NOTE program segment. Can't inject code.");
        return -1;
    }

    return program_header_note_off;
}

int
section_header_note_get(int fd, const Elf64_Ehdr header, const Elf64_Phdr program_header_note, Elf64_Shdr *section_header_note) {
    int off = lseek(fd, header.e_shoff, SEEK_SET);
    if (off == -1) {
        perror("lseek - woody");
        return -1;
    }

    int section_header_note_off = 0;
    for (int i = 0; i < header.e_shnum; i++) {
        int bytes_read = read(fd, &section_header_note, sizeof(Elf64_Shdr));
        if (bytes_read == -1) {
            perror("read - woody");
            return -1;
        }

        section_header_note_off = header.e_shoff + i * sizeof(Elf64_Shdr);
        uint8_t section_in_program_segment = program_header_note.p_offset <= section_header_note->sh_offset &&
                                             section_header_note->sh_offset <= program_header_note.p_offset + program_header_note.p_filesz;
        if (section_in_program_segment && section_header_note->sh_type == SHT_NOTE) break;
    }

    if (section_header_note->sh_type != SHT_NOTE) {
        fprintf(stderr, "could not find section SHT_NOTE. Can't inject code.");
        return -1;
    }

    return section_header_note_off;
}

int
main(int ac, char **av) {
    if (ac != 2) {
        printf("wrong usage: ./woody BINARY_NAME\n");
        return 1;
    }

    int fd_orig = open(av[1], O_RDONLY);
    if (fd_orig == -1) {
        perror(av[1]);
        return 1;
    }

    int fd_new = open("woody", O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd_new == -1) {
        perror("could not create new 'woody' binary:\n");
        return 1;
    }

    Elf64_Ehdr header;

    int err = elf_header_parse(fd_orig, &header);
    if (err) {
        fprintf(stderr, "error: invalid elf header");
        return 1;
    }

    printf("%x\n", header.e_phoff);

    err = fd_copy_whole(fd_new, fd_orig);
    if (err) {
        fprintf(stderr, "error: while copying whole file before modification");
        return 1;
    }

    unsigned char shellcode[] = {0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
                                 0x48, 0xc7, 0xc7, 0x04, 0x00, 0x00, 0x00, // mov rdi, 4
                                 0x0f, 0x05};

    int shellcode_off = shellcode_add_at_end(fd_new, &shellcode, sizeof(shellcode));
    if (shellcode_off == -1) {
        fprintf(stderr, "error: while adding shellcode at end of `woody`");
        return 1;
    }

    Elf64_Phdr program_header_note;

    int program_header_note_off = program_header_note_get(fd_new, header, &program_header_note);
    if (program_header_note_off == -1) {
        fprintf(stderr, "error: could not find program segment to inject code in %s\n", av[1]);
        return 1;
    }

    Elf64_Shdr section_header_note;

    int section_header_note_off = section_header_note_get(fd_new, header, program_header_note, &section_header_note);
    if (section_header_note_off == -1) {
        fprintf(stderr, "error: could not find section to inject code in %s\n", av[1]);
        return 1;
    }



    section_header_note.sh_type = SHT_PROGBITS;
    section_header_note.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    section_header_note.sh_addr = 0x10000;
    section_header_note.sh_offset = shellcode_off;
    section_header_note.sh_size = sizeof(shellcode);
    section_header_note.sh_addralign = 0x1000;

    err = lseek(fd_new, section_header_note_off, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    int bytes_written = write(fd_new, &section_header_note, sizeof(section_header_note));
    if (bytes_written != sizeof(section_header_note)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    program_header_note.p_type = PT_LOAD;
    program_header_note.p_offset = shellcode_off;
    program_header_note.p_vaddr = 0x10000;
    program_header_note.p_paddr = 0x10000;
    program_header_note.p_filesz = sizeof(shellcode);
    program_header_note.p_memsz = sizeof(shellcode);
    program_header_note.p_flags = PF_X | PF_R;
    program_header_note.p_align = 0x1000;

    err = lseek(fd_new, program_header_note_off, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    bytes_written = write(fd_new, &program_header_note, sizeof(program_header_note));
    if (bytes_written != sizeof(program_header_note)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    header.e_entry = 0x10000;

    err = lseek(fd_new, 0, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
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
