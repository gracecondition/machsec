#include "detect.h"
#include "table.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach/machine.h>

// Helper function for searching memory (memmem may not be available on all systems)
static void* search_memory(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen > haystacklen) return NULL;
    if (needlelen == 0) return (void*)haystack;
    
    const char *h = (const char*)haystack;
    const char *n = (const char*)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void*)(h + i);
        }
    }
    return NULL;
}

// Mach-O helper functions
macho_t* macho_open(const char *path) {
    macho_t *macho = calloc(1, sizeof(macho_t));
    if (!macho) return NULL;
    
    macho->fd = open(path, O_RDONLY);
    if (macho->fd < 0) {
        free(macho);
        return NULL;
    }
    
    struct stat st;
    if (fstat(macho->fd, &st) < 0) {
        close(macho->fd);
        free(macho);
        return NULL;
    }
    
    macho->size = st.st_size;
    macho->data = mmap(NULL, macho->size, PROT_READ, MAP_PRIVATE, macho->fd, 0);
    if (macho->data == MAP_FAILED) {
        close(macho->fd);
        free(macho);
        return NULL;
    }
    
    // Check for Mach-O magic
    uint32_t *magic = (uint32_t *)macho->data;
    if (*magic == MH_MAGIC_64 || *magic == MH_CIGAM_64) {
        macho->is_64bit = true;
        macho->header = (struct mach_header_64 *)macho->data;
        macho->load_commands = (struct load_command *)((char *)macho->data + sizeof(struct mach_header_64));
    } else if (*magic == MH_MAGIC || *magic == MH_CIGAM) {
        macho->is_64bit = false;
        //struct mach_header *header32 = (struct mach_header *)macho->data;
        macho->load_commands = (struct load_command *)((char *)macho->data + sizeof(struct mach_header));
    } else if (*magic == FAT_MAGIC || *magic == FAT_CIGAM) {
        macho->is_fat = true;
        struct fat_header *fat_header = (struct fat_header *)macho->data;
        uint32_t nfat_arch = ntohl(fat_header->nfat_arch);
        struct fat_arch *archs = (struct fat_arch *)((char *)macho->data + sizeof(struct fat_header));
        
        // Prefer ARM64 architecture if available, otherwise use first available
        struct fat_arch *selected_arch = &archs[0];  // Default to first arch
        
        for (uint32_t i = 0; i < nfat_arch; i++) {
            uint32_t arch_cputype = ntohl(archs[i].cputype);
            if (arch_cputype == CPU_TYPE_ARM64) {
                selected_arch = &archs[i];
                break;  // ARM64 found, use it
            }
        }
        
        // Point to the selected architecture
        macho->data = (char *)macho->data + ntohl(selected_arch->offset);
        uint32_t *arch_magic = (uint32_t *)macho->data;
        
        if (*arch_magic == MH_MAGIC_64 || *arch_magic == MH_CIGAM_64) {
            macho->is_64bit = true;
            macho->header = (struct mach_header_64 *)macho->data;
            macho->load_commands = (struct load_command *)((char *)macho->data + sizeof(struct mach_header_64));
        } else {
            macho->is_64bit = false;
            macho->load_commands = (struct load_command *)((char *)macho->data + sizeof(struct mach_header));
        }
    } else {
        munmap(macho->data, macho->size);
        close(macho->fd);
        free(macho);
        return NULL;
    }
    
    return macho;
}

void macho_close(macho_t *macho) {
    if (macho) {
        if (macho->data) munmap(macho->data, macho->size);
        if (macho->fd >= 0) close(macho->fd);
        free(macho);
    }
}

struct load_command* macho_find_command(macho_t *macho, uint32_t cmd_type) {
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == cmd_type) {
            return cmd;
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return NULL;
}

struct segment_command_64* macho_find_segment(macho_t *macho, const char *segname) {
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (macho->is_64bit && cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strncmp(seg->segname, segname, 16) == 0) {
                return seg;
            }
        } else if (!macho->is_64bit && cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg32 = (struct segment_command *)cmd;
            if (strncmp(seg32->segname, segname, 16) == 0) {
                // Convert to 64-bit structure for consistency
                static struct segment_command_64 seg64;
                seg64.cmd = seg32->cmd;
                seg64.cmdsize = seg32->cmdsize;
                strncpy(seg64.segname, seg32->segname, 16);
                seg64.vmaddr = seg32->vmaddr;
                seg64.vmsize = seg32->vmsize;
                seg64.fileoff = seg32->fileoff;
                seg64.filesize = seg32->filesize;
                seg64.maxprot = seg32->maxprot;
                seg64.initprot = seg32->initprot;
                seg64.nsects = seg32->nsects;
                seg64.flags = seg32->flags;
                return &seg64;
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return NULL;
}

struct symtab_command* macho_get_symtab(macho_t *macho) {
    return (struct symtab_command *)macho_find_command(macho, LC_SYMTAB);
}

// Detection functions adapted for Mach-O
bool detect_canaries(struct DetectionResults *res, cs_insn *insn, size_t count, macho_t *macho) {
    // Check for __stack_chk_fail symbol first
    if (!res->canary_enabled && macho) {
        struct symtab_command *symtab = macho_get_symtab(macho);
        if (symtab) {
            struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
            char *strings = (char *)macho->data + symtab->stroff;
            
            for (uint32_t i = 0; i < symtab->nsyms; i++) {
                if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                    char *name = strings + symbols[i].n_un.n_strx;
                    if (strcmp(name, "___stack_chk_fail") == 0) {
                        res->canary_enabled = true;
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        // Look for x86_64 stack canary offset gs:[0x28] on macOS
        if ((strstr(insn[i].op_str, "gs:[0x28]") || strstr(insn[i].op_str, "gs:0x28")) &&
            (strcmp(insn[i].mnemonic, "mov") == 0)) {
            res->canary_enabled = true;
        }

        // Look for x86 32-bit stack canary offset gs:[0x14] on macOS
        if ((strstr(insn[i].op_str, "gs:[0x14]") || strstr(insn[i].op_str, "gs:0x14")) &&
            (strcmp(insn[i].mnemonic, "mov") == 0)) {
            res->canary_enabled = true;
        }

        // Check for canary validation (x86)
        if (strstr(insn[i].op_str, "gs:[0x28]") && strcmp(insn[i].mnemonic, "xor") == 0) {
            res->canary_enabled = true;
        }

        if (strstr(insn[i].op_str, "gs:[0x14]") && strcmp(insn[i].mnemonic, "xor") == 0) {
            res->canary_enabled = true;
        }

        // ARM64 stack canary detection for iOS devices
        // Look for stack canary loading from thread pointer
        if ((strcmp(insn[i].mnemonic, "ldr") == 0 || strcmp(insn[i].mnemonic, "ldur") == 0) &&
            (strstr(insn[i].op_str, "x18") || strstr(insn[i].op_str, "tpidr_el0"))) {
            res->canary_enabled = true;
        }

        // ARM32 stack canary patterns
        if ((strcmp(insn[i].mnemonic, "ldr") == 0) &&
            (strstr(insn[i].op_str, "pc") && strstr(insn[i].op_str, "___stack_chk_guard"))) {
            res->canary_enabled = true;
        }

        // Check for calls to ___stack_chk_fail (both x86 and ARM)
        if ((strcmp(insn[i].mnemonic, "call") == 0 || strcmp(insn[i].mnemonic, "bl") == 0) && 
            strstr(insn[i].op_str, "___stack_chk_fail")) {
            res->canary_enabled = true;
        }
    }

    if (res->canary_enabled) {
        res->canary_text = "Stack canaries found";
        res->canary_status = 0;
        res->canary_color = COLOR_GREEN;
    } else if (res->canary_text == NULL) {
        res->canary_text = "No stack canaries found";
        res->canary_status = 2;
        res->canary_color = COLOR_RED;
    }
    return res->canary_enabled;
}

bool detect_relro(struct DetectionResults *res, macho_t *macho) {
    // Mach-O doesn't have RELRO like ELF, but we can check for read-only segments
    struct segment_command_64 *data_seg = macho_find_segment(macho, SEG_DATA);
    
    if (data_seg && (data_seg->initprot & VM_PROT_WRITE) && !(data_seg->maxprot & VM_PROT_WRITE)) {
        res->relro_text = "Partial RELRO (read-only data)";
        res->relro_status = 1;
        res->relro_color = COLOR_YELLOW;
        res->relro_full = 2;
        return true;
    } else if (data_seg && (data_seg->initprot & VM_PROT_WRITE)) {
        res->relro_text = "No RELRO";
        res->relro_status = 2;
        res->relro_color = COLOR_RED;
        res->relro_full = 3;
        return false;
    } else {
        res->relro_text = "RELRO unknown";
        res->relro_status = 1;
        res->relro_color = COLOR_YELLOW;
        res->relro_full = 0;
        return false;
    }
}


bool detect_pie(struct DetectionResults *res, macho_t *macho) {
    uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
    
    if (flags & MH_PIE) {
        res->pie_enabled = true;
        res->pie_text = "PIE enabled";
        res->pie_status = 0;
        res->pie_color = COLOR_GREEN;
        return true;
    } else {
        res->pie_enabled = false;
        res->pie_text = "No PIE";
        res->pie_status = 2;
        res->pie_color = COLOR_RED;
        return false;
    }
}

bool detect_rpath(struct DetectionResults *res, macho_t *macho) {
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    bool has_rpath = false;
    bool has_runpath = false;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_RPATH) {
            has_rpath = true;
        } else if (cmd->cmd == LC_LOAD_DYLIB) {
            struct dylib_command *dylib = (struct dylib_command *)cmd;
            char *path = (char *)dylib + dylib->dylib.name.offset;
            if (strstr(path, "@rpath")) {
                has_runpath = true;
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (has_rpath) {
        res->rpath_text = "RPATH found";
        res->rpath_status = 2;
        res->rpath_color = COLOR_RED;
    } else {
        res->rpath_text = "No RPATH";
        res->rpath_status = 0;
        res->rpath_color = COLOR_GREEN;
    }
    
    if (has_runpath) {
        res->runpath_text = "@rpath usage found";
        res->runpath_status = 1;
        res->runpath_color = COLOR_YELLOW;
    } else {
        res->runpath_text = "No @rpath usage";
        res->runpath_status = 0;
        res->runpath_color = COLOR_GREEN;
    }
    
    return has_rpath || has_runpath;
}

bool detect_runpath(macho_t *macho) {
    // Handled in detect_rpath for Mach-O
    return false;
}

bool detect_fortify(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->fortify_text = "No symbols";
        res->fortify_status = 1;
        res->fortify_color = COLOR_YELLOW;
        res->fortified_count = 0;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    int fortified_count = 0;
    const char *fortified_functions[] = {
        "memcpy_chk", "strcpy_chk", "strcat_chk", "sprintf_chk", "snprintf_chk",
        "vsprintf_chk", "vsnprintf_chk", "gets_chk", "fgets_chk", "memset_chk",
        "stpcpy_chk", "stpncpy_chk", "strncpy_chk", "strncat_chk", "vprintf_chk",
        "printf_chk", "fprintf_chk", "vfprintf_chk", "read_chk", "recv_chk",
        "recvfrom_chk", "readlink_chk", "getwd_chk", "realpath_chk", "wctomb_chk",
        "wcstombs_chk", "mbstowcs_chk", "mbsrtowcs_chk", "wcrtomb_chk", "wcsrtombs_chk"
    };
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            // Remove leading underscore if present (common in Mach-O)
            if (name[0] == '_') name++;
            
            // Check against known fortified functions
            for (size_t j = 0; j < sizeof(fortified_functions) / sizeof(fortified_functions[0]); j++) {
                if (strstr(name, fortified_functions[j])) {
                    fortified_count++;
                    break;  // Don't double-count the same symbol
                }
            }
        }
    }
    
    res->fortified_count = fortified_count;
    
    if (fortified_count > 0) {
        char *text_buffer = malloc(64);
        if (text_buffer) {
            snprintf(text_buffer, 64, "FORTIFY enabled (%d functions)", fortified_count);
            res->fortify_text = text_buffer;
        } else {
            res->fortify_text = "FORTIFY enabled";
        }
        res->fortify_status = 0;
        res->fortify_color = COLOR_GREEN;
        return true;
    }
    
    res->fortify_text = "No FORTIFY";
    res->fortify_status = 2;
    res->fortify_color = COLOR_RED;
    return false;
}

bool detect_ubsan(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->ubsan_text = "No symbols";
        res->ubsan_status = 1;
        res->ubsan_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__ubsan") || strstr(name, "__sanitizer") || strstr(name, "_ubsan_handle")) {
                res->ubsan_text = "UBSan enabled";
                res->ubsan_status = 0;
                res->ubsan_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->ubsan_text = "No UBSan";
    res->ubsan_status = 2;
    res->ubsan_color = COLOR_RED;
    return false;
}

bool detect_asan(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->asan_text = "No symbols";
        res->asan_status = 1;
        res->asan_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__asan") || strstr(name, "__sanitizer_cov") || strstr(name, "__interceptor_malloc")) {
                res->asan_text = "ASAN enabled";
                res->asan_status = 0;
                res->asan_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->asan_text = "No ASAN";
    res->asan_status = 2;
    res->asan_color = COLOR_RED;
    return false;
}

bool detect_cfi(struct DetectionResults *res, macho_t *macho) {
    // CFI is less common on macOS, check for symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->cfi_text = "No symbols";
        res->cfi_status = 1;
        res->cfi_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__cfi") || strstr(name, "_cfi_") || strstr(name, "cfi_check")) {
                res->cfi_text = "CFI enabled";
                res->cfi_status = 0;
                res->cfi_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->cfi_text = "No CFI";
    res->cfi_status = 2;
    res->cfi_color = COLOR_RED;
    return false;
}


bool detect_symbols(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    
    if (!symtab || symtab->nsyms == 0) {
        res->symbols_text = "Fully stripped (0 symbols)";
        res->symbols_status = 0;
        res->symbols_color = COLOR_GREEN;
        return false;
    }
    
    // Count different types of symbols
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    uint32_t local_syms = 0, external_syms = 0, undef_syms = 0;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_type & N_EXT) {
            external_syms++;
        } else if ((symbols[i].n_type & N_TYPE) == N_UNDF) {
            undef_syms++;
        } else {
            local_syms++;
        }
    }
    
    char *text_buffer = malloc(128);
    if (!text_buffer) {
        res->symbols_text = "Memory error";
        res->symbols_status = 1;
        res->symbols_color = COLOR_YELLOW;
        return false;
    }
    
    if (local_syms > 0) {
        snprintf(text_buffer, 128, "Not stripped (%d symbols)", symtab->nsyms);
        res->symbols_text = text_buffer;
        res->symbols_status = 2;
        res->symbols_color = COLOR_RED;
        return true;
    } else if (external_syms > 0 || undef_syms > 0) {
        snprintf(text_buffer, 128, "Partially stripped (%d symbols)", external_syms + undef_syms);
        res->symbols_text = text_buffer;
        res->symbols_status = 1;
        res->symbols_color = COLOR_YELLOW;
        return true;
    } else {
        snprintf(text_buffer, 128, "Fully stripped (0 symbols)");
        res->symbols_text = text_buffer;
        res->symbols_status = 0;
        res->symbols_color = COLOR_GREEN;
        return false;
    }
}

bool detect_stack_clash(struct DetectionResults *res, macho_t *macho) {
    // Stack clash protection is less common on macOS, check for canaries as heuristic
    if (res->canary_enabled) {
        res->stack_clash_text = "Stack protection enabled";
        res->stack_clash_status = 0;
        res->stack_clash_color = COLOR_GREEN;
        return true;
    } else {
        res->stack_clash_text = "No stack protection";
        res->stack_clash_status = 2;
        res->stack_clash_color = COLOR_RED;
        return false;
    }
}

bool detect_heap_cookies(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->heap_cookies_text = "No symbols";
        res->heap_cookies_status = 1;
        res->heap_cookies_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "malloc_zone") || strstr(name, "guard_malloc") || strstr(name, "_malloc_check")) {
                res->heap_cookies_text = "Heap hardening enabled";
                res->heap_cookies_status = 0;
                res->heap_cookies_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->heap_cookies_text = "No heap hardening";
    res->heap_cookies_status = 2;
    res->heap_cookies_color = COLOR_RED;
    return false;
}

bool detect_integer_overflow(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->integer_overflow_text = "No symbols";
        res->integer_overflow_status = 1;
        res->integer_overflow_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__muloti4") || strstr(name, "__addoti4") || 
                strstr(name, "__ubsan_handle_add_overflow") || strstr(name, "__wrap_")) {
                res->integer_overflow_text = "Integer overflow protection enabled";
                res->integer_overflow_status = 0;
                res->integer_overflow_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->integer_overflow_text = "No integer overflow protection";
    res->integer_overflow_status = 2;
    res->integer_overflow_color = COLOR_RED;
    return false;
}

bool detect_sandbox(struct DetectionResults *res, macho_t *macho) {
    bool has_sandbox_symbols = false;
    bool has_code_signature = false;
    bool has_entitlements = false;
    
    // Check for sandboxing symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;
                
                // Check for macOS/iOS sandboxing symbols
                if (strstr(name, "sandbox_") || 
                    strstr(name, "_sandbox_init") ||
                    strstr(name, "sandbox_check") ||
                    strstr(name, "sandbox_free_error") ||
                    strstr(name, "container_") ||
                    strstr(name, "_container_create")) {
                    has_sandbox_symbols = true;
                    break;
                }
            }
        }
    }
    
    // Check for code signature and entitlements
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            has_code_signature = true;
            
            // Try to parse the code signature for entitlements
            struct linkedit_data_command *sig_cmd = (struct linkedit_data_command *)cmd;
            
            // Look for entitlement data in the signature
            if (sig_cmd->datasize > 0) {
                char *sig_data = (char *)macho->data + sig_cmd->dataoff;
                
                // Look for common sandbox entitlement strings
                if (sig_cmd->datasize > 20) {  // Minimum size check
                    // Search for sandbox-related entitlement keys
                    if (search_memory(sig_data, sig_cmd->datasize, "com.apple.security.app-sandbox", 31) ||
                        search_memory(sig_data, sig_cmd->datasize, "platform-application", 20) ||
                        search_memory(sig_data, sig_cmd->datasize, "sandbox", 7)) {
                        has_entitlements = true;
                    }
                }
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    // Determine sandbox status based on evidence
    if (has_sandbox_symbols) {
        res->sandbox_text = "Sandbox enabled (symbols)";
        res->sandbox_status = 0;
        res->sandbox_color = COLOR_GREEN;
        return true;
    } else if (has_entitlements) {
        res->sandbox_text = "Sandbox enabled (entitlements)";
        res->sandbox_status = 0;
        res->sandbox_color = COLOR_GREEN;
        return true;
    } else if (has_code_signature) {
        // Check if this is a system binary (likely sandboxed)
        uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
        if (flags & MH_PIE) {  // System binaries are typically PIE
            res->sandbox_text = "Likely sandboxed (system binary)";
            res->sandbox_status = 1;
            res->sandbox_color = COLOR_YELLOW;
            return true;
        } else {
            res->sandbox_text = "Code signed (may be sandboxed)";
            res->sandbox_status = 1;
            res->sandbox_color = COLOR_YELLOW;
            return true;
        }
    } else {
        res->sandbox_text = "No sandbox";
        res->sandbox_status = 2;
        res->sandbox_color = COLOR_RED;
        return false;
    }
}

bool detect_hardened_runtime(struct DetectionResults *res, macho_t *macho) {
    // Check for LC_CODE_SIGNATURE load command (both macOS and iOS)
    struct load_command *code_sig = macho_find_command(macho, LC_CODE_SIGNATURE);
    
    // Also check for iOS-specific security features
    //uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
    bool has_ios_security = false;
    
    // Check for iOS App Store binaries (encrypted)
    struct load_command *encryption = macho_find_command(macho, LC_ENCRYPTION_INFO);
    if (!encryption && macho->is_64bit) {
        encryption = macho_find_command(macho, LC_ENCRYPTION_INFO_64);
    }
    
    if (encryption) {
        has_ios_security = true;
    }
    
    if (code_sig || has_ios_security) {
        if (has_ios_security) {
            res->hardened_runtime_text = "iOS Security enabled";
        } else {
            res->hardened_runtime_text = "Hardened Runtime enabled";
        }
        res->hardened_runtime_status = 0;
        res->hardened_runtime_color = COLOR_GREEN;
        return true;
    } else {
        res->hardened_runtime_text = "No security hardening";
        res->hardened_runtime_status = 2;
        res->hardened_runtime_color = COLOR_RED;
        return false;
    }
}

bool detect_library_validation(struct DetectionResults *res, macho_t *macho) {
    // Check for restricted library loading
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    bool has_system_libs_only = true;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_LOAD_DYLIB) {
            struct dylib_command *dylib = (struct dylib_command *)cmd;
            char *path = (char *)dylib + dylib->dylib.name.offset;
            
            // Check if all libraries are system libraries
            if (!strstr(path, "/System/") && !strstr(path, "/usr/lib/") && !strstr(path, "@rpath")) {
                has_system_libs_only = false;
                break;
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (has_system_libs_only) {
        res->library_validation_text = "Library validation enabled";
        res->library_validation_status = 0;
        res->library_validation_color = COLOR_GREEN;
        return true;
    } else {
        res->library_validation_text = "No library validation";
        res->library_validation_status = 2;
        res->library_validation_color = COLOR_RED;
        return false;
    }
}

bool detect_code_signing(struct DetectionResults *res, macho_t *macho) {
    struct load_command *code_sig = macho_find_command(macho, LC_CODE_SIGNATURE);
    
    if (code_sig) {
        res->code_signing_text = "Code signed";
        res->code_signing_status = 0;
        res->code_signing_color = COLOR_GREEN;
        return true;
    } else {
        res->code_signing_text = "Not code signed";
        res->code_signing_status = 2;
        res->code_signing_color = COLOR_RED;
        return false;
    }
}

bool detect_pac(struct DetectionResults *res, macho_t *macho) {
    // PAC (Pointer Authentication Code) is available on ARM64 devices
    uint32_t cputype = macho->is_64bit ? macho->header->cputype : ((struct mach_header *)macho->data)->cputype;
    
    // PAC is only available on ARM64
    if (cputype != CPU_TYPE_ARM64) {
        res->pac_text = "N/A (not ARM64)";
        res->pac_status = 1;
        res->pac_color = COLOR_YELLOW;
        return false;
    }
    
    // Check for PAC-related symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;
                
                // Check for PAC-related symbols
                if (strstr(name, "_ptrauth") || 
                    strstr(name, "pac_") ||
                    strstr(name, "_auth_") ||
                    strstr(name, "pointer_auth")) {
                    res->pac_text = "PAC enabled";
                    res->pac_status = 0;
                    res->pac_color = COLOR_GREEN;
                    return true;
                }
            }
        }
    }
    
    // Check CPU subtype for PAC capability
    uint32_t cpusubtype = macho->is_64bit ? macho->header->cpusubtype : ((struct mach_header *)macho->data)->cpusubtype;
    
    // Mask out feature flags to get the actual subtype
    uint32_t actual_subtype = cpusubtype & ~CPU_SUBTYPE_MASK;
    
    // Apple Silicon and newer ARM64 chips support PAC
    if (actual_subtype == CPU_SUBTYPE_ARM64E) {
        // Check if this binary has the PAC ABI flag set
        if (cpusubtype & CPU_SUBTYPE_PTRAUTH_ABI) {
            res->pac_text = "PAC enabled (ARM64E with PtrAuth ABI)";
        } else {
            res->pac_text = "PAC capable (ARM64E)";
        }
        res->pac_status = 0;
        res->pac_color = COLOR_GREEN;
        return true;
    } else if (actual_subtype == CPU_SUBTYPE_ARM64_V8) {
        res->pac_text = "PAC capable (ARM64)";
        res->pac_status = 0;
        res->pac_color = COLOR_GREEN;
        return true;
    }
    
    // Default: ARM64 device but no PAC detected
    res->pac_text = "No PAC detected";
    res->pac_status = 2;
    res->pac_color = COLOR_RED;
    return false;
}

bool detect_arc(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->arc_text = "No symbols";
        res->arc_status = 1;
        res->arc_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    bool has_arc_symbols = false;
    bool has_manual_retain_release = false;
    bool has_objc_symbols = false;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            // Check for ARC-specific symbols (these indicate ARC usage)
            if (strstr(name, "objc_retainAutorelease") || strstr(name, "objc_storeStrong") || 
                strstr(name, "objc_destroyWeak") || strstr(name, "objc_retainAutoreleaseReturnValue") ||
                strstr(name, "objc_autoreleaseReturnValue") || strstr(name, "objc_retainAutoreleasedReturnValue")) {
                has_arc_symbols = true;
                break;
            }
            
            // Check for Swift runtime symbols (Swift uses ARC by default)
            if (strstr(name, "_swift_retain") || strstr(name, "_swift_release") ||
                strstr(name, "swift_rt_swift_retain") || strstr(name, "swift_bridgeObjectRetain")) {
                has_arc_symbols = true;
                break;
            }
            
            // Check for manual retain/release (indicates manual memory management)
            if ((symbols[i].n_type & N_TYPE) == N_UNDF && 
                (strcmp(name, "_objc_retain") == 0 || strcmp(name, "_objc_release") == 0 ||
                 strcmp(name, "_objc_autorelease") == 0)) {
                has_manual_retain_release = true;
            }
            
            // Check for general Objective-C symbols
            if (strstr(name, "_objc_") || strstr(name, "_OBJC_")) {
                has_objc_symbols = true;
            }
        }
    }
    
    if (has_arc_symbols) {
        res->arc_text = "ARC enabled";
        res->arc_status = 0;
        res->arc_color = COLOR_GREEN;
        return true;
    } else if (has_objc_symbols) {
        if (has_manual_retain_release) {
            res->arc_text = "Manual memory management";
            res->arc_status = 2;
            res->arc_color = COLOR_RED;
            return false;
        } else {
            // Has Objective-C but no clear ARC or manual symbols - assume ARC
            res->arc_text = "ARC enabled";
            res->arc_status = 0;
            res->arc_color = COLOR_GREEN;
            return true;
        }
    } else {
        res->arc_text = "No Objective-C/Swift";
        res->arc_status = 1;
        res->arc_color = COLOR_YELLOW;
        return false;
    }
}

bool detect_encrypted(struct DetectionResults *res, macho_t *macho) {
    // Check for LC_ENCRYPTION_INFO load command (32-bit)
    struct load_command *encryption = macho_find_command(macho, LC_ENCRYPTION_INFO);
    struct encryption_info_command *enc_cmd = NULL;
    
    // Check for LC_ENCRYPTION_INFO_64 load command (64-bit)
    if (!encryption && macho->is_64bit) {
        encryption = macho_find_command(macho, LC_ENCRYPTION_INFO_64);
    }
    
    if (encryption) {
        if (macho->is_64bit) {
            struct encryption_info_command_64 *enc_cmd_64 = (struct encryption_info_command_64 *)encryption;
            if (enc_cmd_64->cryptid != 0) {
                res->encrypted_text = "Encrypted (App Store)";
                res->encrypted_status = 0;
                res->encrypted_color = COLOR_GREEN;
                return true;
            }
        } else {
            enc_cmd = (struct encryption_info_command *)encryption;
            if (enc_cmd->cryptid != 0) {
                res->encrypted_text = "Encrypted (App Store)";
                res->encrypted_status = 0;
                res->encrypted_color = COLOR_GREEN;
                return true;
            }
        }
        
        // Encryption command present but cryptid is 0 (decrypted)
        res->encrypted_text = "Decrypted";
        res->encrypted_status = 1;
        res->encrypted_color = COLOR_YELLOW;
        return false;
    }
    
    res->encrypted_text = "Not encrypted";
    res->encrypted_status = 2;
    res->encrypted_color = COLOR_RED;
    return false;
}

bool detect_restrict(struct DetectionResults *res, macho_t *macho) {
    bool has_system_path = false;
    bool has_sip_entitlements = false;
    bool has_restricted_symbols = false;
    
    // Check if binary is in a system path (indicates SIP protection)
    // This would need the original file path, but we can check for system library dependencies
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_LOAD_DYLIB) {
            struct dylib_command *dylib = (struct dylib_command *)cmd;
            char *path = (char *)dylib + dylib->dylib.name.offset;
            
            // Check for system library dependencies
            if (strstr(path, "/System/Library/") || strstr(path, "/usr/lib/libSystem")) {
                has_system_path = true;
                break;
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    // Check for SIP-related entitlements in code signature
    struct load_command *code_sig = macho_find_command(macho, LC_CODE_SIGNATURE);
    if (code_sig) {
        struct linkedit_data_command *sig_cmd = (struct linkedit_data_command *)code_sig;
        
        if (sig_cmd->datasize > 0) {
            char *sig_data = (char *)macho->data + sig_cmd->dataoff;
            
            // Look for SIP/restriction-related entitlement strings
            if (sig_cmd->datasize > 20) {
                if (search_memory(sig_data, sig_cmd->datasize, "com.apple.rootless", 18) ||
                    search_memory(sig_data, sig_cmd->datasize, "platform-application", 20) ||
                    search_memory(sig_data, sig_cmd->datasize, "restrict", 8) ||
                    search_memory(sig_data, sig_cmd->datasize, "com.apple.security.system", 26)) {
                    has_sip_entitlements = true;
                }
            }
        }
    }
    
    // Check for restricted/system symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;
                
                // Check for system-level symbols that indicate restricted operations
                if (strstr(name, "_rootless") || 
                    strstr(name, "_csops") ||
                    strstr(name, "_sandbox_check") ||
                    strstr(name, "_platform_") ||
                    strstr(name, "_amfi_")) {
                    has_restricted_symbols = true;
                    break;
                }
            }
        }
    }
    
    // Determine restriction status
    if (has_sip_entitlements) {
        res->restrict_text = "SIP restrictions enabled";
        res->restrict_status = 0;
        res->restrict_color = COLOR_GREEN;
        return true;
    } else if (has_restricted_symbols) {
        res->restrict_text = "System restrictions present";
        res->restrict_status = 1;
        res->restrict_color = COLOR_YELLOW;
        return true;
    } else if (has_system_path) {
        res->restrict_text = "System binary (likely restricted)";
        res->restrict_status = 1;
        res->restrict_color = COLOR_YELLOW;
        return true;
    } else {
        res->restrict_text = "No restrictions";
        res->restrict_status = 2;
        res->restrict_color = COLOR_RED;
        return false;
    }
}

bool detect_nx_heap(struct DetectionResults *res, macho_t *macho) {
    // Check heap segments for NX protection
    struct segment_command_64 *data_seg = macho_find_segment(macho, SEG_DATA);
    struct segment_command_64 *heap_seg = macho_find_segment(macho, "__HEAP");
    
    bool heap_nx = true;
    
    // Check if heap segment exists and is executable (bad for NX)
    if (heap_seg && (heap_seg->initprot & VM_PROT_EXECUTE)) {
        heap_nx = false;
    }
    
    // If no explicit heap segment, check data segment (where heap allocations often go)
    if (!heap_seg && data_seg && (data_seg->initprot & VM_PROT_EXECUTE)) {
        heap_nx = false;
    }
    
    // For iOS/macOS, heap is typically non-executable by default
    if (heap_nx) {
        res->nx_heap_text = "NX heap enabled";
        res->nx_heap_status = 0;
        res->nx_heap_color = COLOR_GREEN;
        return true;
    } else {
        res->nx_heap_text = "NX heap disabled";
        res->nx_heap_status = 2;
        res->nx_heap_color = COLOR_RED;
        return false;
    }
}

bool detect_nx_stack(struct DetectionResults *res, macho_t *macho) {
    // Check stack segments for NX protection
    struct segment_command_64 *stack_seg = macho_find_segment(macho, "__STACK");
    
    bool stack_nx = true;
    
    // Check if stack segment exists and is executable (bad for NX)
    if (stack_seg && (stack_seg->initprot & VM_PROT_EXECUTE)) {
        stack_nx = false;
    }
    
    // If no explicit stack segment found, assume stack NX is enabled (default on modern macOS/iOS)
    if (stack_nx) {
        res->nx_stack_text = "NX stack enabled";
        res->nx_stack_status = 0;
        res->nx_stack_color = COLOR_GREEN;
        return true;
    } else {
        res->nx_stack_text = "NX stack disabled";
        res->nx_stack_status = 2;
        res->nx_stack_color = COLOR_RED;
        return false;
    }
}
