#pragma once

namespace shellcode {
    inline unsigned char crypt_init[] {
        0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,             // mov eax, fs:[0x30]
        0x8B, 0x70, 0x08,                               // mov esi, [eax+0x08]
        0xBB, 0x00, 0x00, 0x00, 0x00,                   // mov ebx, 0x00000000           (+10) // key length
    };

    inline unsigned char crypt[] {
        0x31, 0xC9,                                     // xor ecx, ecx
        0x31, 0xD2,                                     // xor edx, edx
        0x89, 0xC8,                                     // mov eax, ecx
        0xF7, 0xF3,                                     // div ebx
        0x8A, 0x84, 0x16, 0x00, 0x00, 0x00, 0x00,       // mov al, [esi+edx+0x00000000] (+11) // key address
        0x30, 0x84, 0x0E, 0x00, 0x00, 0x00, 0x00,       // xor [esi+ecx+0x00000000], al (+18) // start address
        0x41,                                           // inc ecx
        0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,             // cmp ecx, 0x00000000          (+25) // size
        0x75, 0xE3,                                     // jne
    };

    inline unsigned char crypt_end[] {
        0x8D, 0x86, 0x00, 0x00, 0x00, 0x00,             // lea eax, [esi+0x00000000]     (+2)  // jump address
        0x8B, 0xC8,                                     // mov ecx, eax
        0x8B, 0xD0,                                     // mov edx, eax
        0x8B, 0xF0,                                     // mov esi, eax
        0x8B, 0xF8,                                     // mov edi, eax
        0x31, 0xDB,                                     // mov ebx, ebx
        0xFF, 0xE0,                                     // jmp
    };

    inline unsigned char import_call[] {
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00
    };

    int generate(int eax, unsigned char* out);
}