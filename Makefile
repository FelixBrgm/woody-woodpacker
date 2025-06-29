all:
	nasm -f elf64 stub/test.asm -o stub.o
	objcopy -O binary stub.o stub.bin
	echo "// Auto-generated stub code" > stub_bytes.h
	echo "unsigned char decryption_stub[] = {" >> stub_bytes.h
	xxd -i < stub.bin | sed 's/^/	/' >> stub_bytes.h
	echo "};" >> stub_bytes.h
	cc main.c -g -o woody_woodpacker

fclean:
	rm woody woody_woodpacker crypto.bin crypto.o stub_bytes.h
