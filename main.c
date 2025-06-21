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

    int bytes_written;
    int bytes_read;

    Elf64_Ehdr header;

    bytes_read = read(fd_orig, &header, sizeof(header));
    if (bytes_read != sizeof(header)) {
        fprintf(stderr, "error while reading %s\n", av[1]);
        return 1;
    }

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
        bytes_written = write(fd_new, &buf, bytes_read);
        if (bytes_written == -1) {
            fprintf(stderr, "error while writting to `woody`\n");
            return 1;
        }
    } while (bytes_read == sizeof(buf));

    // Copy shellcode to the end of the file
    int decrypt_offs = lseek(fd_new, 0, SEEK_END);
    if (decrypt_offs == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    if (decrypt_offs % 0x1000 != 0) {
        int alignment = 0x1000 - (decrypt_offs % 0x1000);
        decrypt_offs = lseek(fd_new, alignment, SEEK_CUR);
        if (decrypt_offs == -1) {
            fprintf(stderr, "error while lseeking on `woody`\n");
            return 1;
        }
    }

    unsigned char shellcode[] = {0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
                                 0x48, 0xc7, 0xc7, 0x04, 0x00, 0x00, 0x00, // mov rdi, 4
                                 0x0f, 0x05};

    int decrypt_size = sizeof(shellcode);

    bytes_written = write(fd_new, &shellcode, sizeof(shellcode));
    if (bytes_written != sizeof(shellcode)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    err = lseek(fd_new, header.e_phoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    Elf64_Phdr program_header_note = {0};

    int program_header_note_off = 0;
    for (int i = 0; i < header.e_phnum; i++) {
        bytes_read = read(fd_new, &program_header_note, sizeof(program_header_note));
        if (bytes_read != sizeof(program_header_note)) {
            fprintf(stderr, "error while reading from `woody`\n");
            return 1;
        }

        program_header_note_off = header.e_phoff + i * sizeof(program_header_note);
        if (program_header_note.p_type == PT_NOTE) break;
    }

    if (program_header_note.p_type != PT_NOTE) {
        fprintf(stderr, "could not find PT_NOTE program segment in %s. Can't inject code.", av[1]);
        return 2;
    }

    err = lseek(fd_new, header.e_shoff, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    Elf64_Shdr section_header_note = {0};
    int section_header_note_off = 0;

    for (int i = 0; i < header.e_shnum; i++) {
        bytes_read = read(fd_new, &section_header_note, sizeof(section_header_note));
        if (bytes_read == -1) {
            fprintf(stderr, "error while reading from `woody`\n");
            return 1;
        }

        section_header_note_off = header.e_shoff + i * sizeof(section_header_note);
        uint8_t section_in_program_segment = program_header_note.p_offset <= section_header_note.sh_offset &&
                                             section_header_note.sh_offset <= program_header_note.p_offset + program_header_note.p_filesz;
        if (section_in_program_segment && section_header_note.sh_type == SHT_NOTE) break;
    }

    if (section_header_note.sh_type != SHT_NOTE) {
        fprintf(stderr, "could not find section SHT_NOTE in %s. Can't inject code.", av[1]);
        return 2;
    }

    section_header_note.sh_type = SHT_PROGBITS;
    section_header_note.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    section_header_note.sh_addr = 0x10000;
    section_header_note.sh_offset = decrypt_offs;
    section_header_note.sh_size = decrypt_size;
    section_header_note.sh_addralign = 0x1000;

    err = lseek(fd_new, section_header_note_off, SEEK_SET);
    if (err == -1) {
        fprintf(stderr, "error while lseeking on `woody`\n");
        return 1;
    }

    bytes_written = write(fd_new, &section_header_note, sizeof(section_header_note));
    if (bytes_written != sizeof(section_header_note)) {
        fprintf(stderr, "error while writting to `woody`\n");
        return 1;
    }

    program_header_note.p_type = PT_LOAD;
    program_header_note.p_offset = decrypt_offs;
    program_header_note.p_vaddr = 0x10000;
    program_header_note.p_paddr = 0x10000;
    program_header_note.p_filesz = decrypt_size;
    program_header_note.p_memsz = decrypt_size;
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
