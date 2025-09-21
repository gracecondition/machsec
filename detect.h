#ifndef FILTER_H
#define FILTER_H

#include <capstone/capstone.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include "table.h"

// Mach-O binary structure
typedef struct {
    int fd;
    void *data;
    size_t size;
    struct mach_header_64 *header;
    struct load_command *load_commands;
    bool is_64bit;
    bool is_fat;
} macho_t;
// Struct for detection results
struct DetectionResults {
    bool cet_enabled;
    bool aslr_enabled;
    bool canary_enabled;

    int relro_full;
    bool pie_enabled;
    
    // Customizable output fields
    char *relro_text;
    int relro_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t relro_color;
    
    const char *canary_text;
    int canary_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t canary_color;
    
    const char *pie_text;
    int pie_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t pie_color;
    
    const char *rpath_text;
    int rpath_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t rpath_color;
    
    const char *runpath_text;
    int runpath_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t runpath_color;
    
    const char *fortify_text;
    int fortify_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t fortify_color;
    
    const char *ubsan_text;
    int ubsan_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t ubsan_color;
    
    const char *asan_text;
    int asan_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t asan_color;
    
    const char *cfi_text;
    int cfi_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t cfi_color;
    
    const char *cet_text;
    int cet_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t cet_color;
    
    const char *symbols_text;
    int symbols_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t symbols_color;
    
    const char *stack_clash_text;
    int stack_clash_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t stack_clash_color;
    
    const char *heap_cookies_text;
    int heap_cookies_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t heap_cookies_color;
    
    const char *integer_overflow_text;
    int integer_overflow_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t integer_overflow_color;
    
    const char *sandbox_text;
    int sandbox_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t sandbox_color;
    
    const char *hardened_runtime_text;
    int hardened_runtime_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t hardened_runtime_color;
    
    const char *library_validation_text;
    int library_validation_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t library_validation_color;
    
    const char *code_signing_text;
    int code_signing_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t code_signing_color;
    
    const char *pac_text;
    int pac_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t pac_color;
    
    const char *arc_text;
    int arc_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t arc_color;
    
    const char *encrypted_text;
    int encrypted_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t encrypted_color;
    
    const char *restrict_text;
    int restrict_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t restrict_color;
    
    const char *nx_heap_text;
    int nx_heap_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t nx_heap_color;
    
    const char *nx_stack_text;
    int nx_stack_status;   // 0=good/green, 1=neutral/yellow, 2=warning/red
    text_color_t nx_stack_color;
    
    int fortified_count;  // Count of fortified functions
};


// Mach-O helper functions
macho_t* macho_open(const char *path);
void macho_close(macho_t *macho);
struct load_command* macho_find_command(macho_t *macho, uint32_t cmd_type);
struct segment_command_64* macho_find_segment(macho_t *macho, const char *segname);
struct symtab_command* macho_get_symtab(macho_t *macho);

// Detection functions adapted for Mach-O
bool detect_canaries(struct DetectionResults *res, cs_insn *insn, size_t count, macho_t *macho);
bool detect_relro(struct DetectionResults *res, macho_t *macho);
bool detect_pie(struct DetectionResults *res, macho_t *macho);
bool detect_rpath(struct DetectionResults *res, macho_t *macho);
bool detect_runpath(macho_t *macho);
bool detect_fortify(struct DetectionResults *res, macho_t *macho);
bool detect_ubsan(struct DetectionResults *res, macho_t *macho);
bool detect_asan(struct DetectionResults *res, macho_t *macho);
bool detect_cfi(struct DetectionResults *res, macho_t *macho);
bool detect_cet(struct DetectionResults *res, macho_t *macho);
bool detect_symbols(struct DetectionResults *res, macho_t *macho);
bool detect_stack_clash(struct DetectionResults *res, macho_t *macho);
bool detect_heap_cookies(struct DetectionResults *res, macho_t *macho);
bool detect_integer_overflow(struct DetectionResults *res, macho_t *macho);
bool detect_sandbox(struct DetectionResults *res, macho_t *macho);
bool detect_hardened_runtime(struct DetectionResults *res, macho_t *macho);
bool detect_library_validation(struct DetectionResults *res, macho_t *macho);
bool detect_code_signing(struct DetectionResults *res, macho_t *macho);
bool detect_pac(struct DetectionResults *res, macho_t *macho);
bool detect_arc(struct DetectionResults *res, macho_t *macho);
bool detect_encrypted(struct DetectionResults *res, macho_t *macho);
bool detect_restrict(struct DetectionResults *res, macho_t *macho);
bool detect_nx_heap(struct DetectionResults *res, macho_t *macho);
bool detect_nx_stack(struct DetectionResults *res, macho_t *macho);





#endif
