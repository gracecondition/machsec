#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <capstone/capstone.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include "detect.h"
#include "table.h"

int main(int argc, char *argv[]) {
    struct DetectionResults res = {0};
    if (argc != 2) {
        return 1;
    }
    
    macho_t *macho = macho_open(argv[1]);
    if (!macho) {
        fprintf(stderr, "Failed to open Mach-O file: %s\n", argv[1]);
        return 1;
    }
    
    // Run detectors once here
    detect_relro(&res, macho);
    detect_pie(&res, macho);
    detect_rpath(&res, macho);
    detect_fortify(&res, macho);
    detect_ubsan(&res, macho);
    detect_asan(&res, macho);
    detect_cfi(&res, macho);
    detect_cet(&res, macho);
    detect_symbols(&res, macho);
    detect_heap_cookies(&res, macho);
    detect_integer_overflow(&res, macho);
    detect_sandbox(&res, macho);
    detect_hardened_runtime(&res, macho);
    detect_library_validation(&res, macho);
    detect_code_signing(&res, macho);
    detect_pac(&res, macho);
    detect_arc(&res, macho);
    detect_encrypted(&res, macho);
    detect_restrict(&res, macho);
    detect_nx_heap(&res, macho);
    detect_nx_stack(&res, macho);
    
    // Parse executable segments for disassembly
    struct segment_command_64 *text_seg = macho_find_segment(macho, SEG_TEXT);
    if (text_seg) {
        void *text_data = (char *)macho->data + text_seg->fileoff;
        
        csh handle;
        cs_insn *insn;
        size_t count;
        
        // Determine architecture and mode from Mach-O header
        cs_arch arch = CS_ARCH_X86;
        cs_mode mode = macho->is_64bit ? CS_MODE_64 : CS_MODE_32;
        
        uint32_t cputype = macho->is_64bit ? macho->header->cputype : ((struct mach_header *)macho->data)->cputype;
        
        // Support both x86/x64 (macOS/iOS Simulator) and ARM64 (iOS devices)
        if (cputype == CPU_TYPE_ARM64) {
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_ARM;
        } else if (cputype == CPU_TYPE_ARM) {
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
        }
        
        if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
            macho_close(macho);
            return 1;
        }
        
        count = cs_disasm(handle, text_data, text_seg->filesize,
                          text_seg->vmaddr, 0, &insn);
        
        if (count > 0) {
            detect_canaries(&res, insn, count, macho);
            cs_free(insn, count);
        } else {
            // Even if disassembly fails, still check for canary symbols
            detect_canaries(&res, NULL, 0, macho);
        }
        
        cs_close(&handle);
    } else {
        // No TEXT segment found, but still check for canary symbols
        detect_canaries(&res, NULL, 0, macho);
    }
    
    // Run stack clash detection after canaries are detected
    detect_stack_clash(&res, macho);
    
    macho_close(macho);
    
    // Define security features table
  security_feature_t features[] = {
        {"RELRO",        res.relro_text,     res.relro_color},
        {"CANARIES", res.canary_text,    res.canary_color},
        {"PIE",          res.pie_text,        res.pie_color},
        {"NX HEAP", res.nx_heap_text, res.nx_heap_color},
        {"NX STACK", res.nx_stack_text, res.nx_stack_color},
        {"RPATH",        res.rpath_text,     res.rpath_color},
        {"RUNPATH",      res.runpath_text,   res.runpath_color},
        {"FORTIFY",      res.fortify_text,   res.fortify_color},
        {"UBSan",        res.ubsan_text,     res.ubsan_color},
        {"ASAN",         res.asan_text,      res.asan_color},
        {"CFI",          res.cfi_text,       res.cfi_color},
        {"CET",          res.cet_text,       res.cet_color},
        {"SYMBOLS",      res.symbols_text,   res.symbols_color},
        {"STACK CLASH",  res.stack_clash_text, res.stack_clash_color},
        {"HEAP COOKIES", res.heap_cookies_text, res.heap_cookies_color},
        {"INT OVERFLOW", res.integer_overflow_text, res.integer_overflow_color},
        {"SANDBOX",      res.sandbox_text,   res.sandbox_color},
        {"HARDENED RT",  res.hardened_runtime_text, res.hardened_runtime_color},
        {"LIB VALIDATION", res.library_validation_text, res.library_validation_color},
        {"CODE SIGNING", res.code_signing_text, res.code_signing_color},
        {"PAC", res.pac_text, res.pac_color},
        {"ARC", res.arc_text, res.arc_color},
        {"ENCRYPTED", res.encrypted_text, res.encrypted_color},
        {"RESTRICT", res.restrict_text, res.restrict_color},
    };

    int count = sizeof(features) / sizeof(features[0]);
    print_security_table(features, count);

    return 0;
}

