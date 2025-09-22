#include <stdio.h>
#include <string.h>
#include "table.h"

#define VERSION "1.2.0"

// Map color enum to ANSI escape codes
const char* get_color_code(text_color_t color) {
    switch (color) {
        case COLOR_RED:    return "\033[1;31m";
        case COLOR_GREEN:  return "\033[1;32m";
        case COLOR_YELLOW: return "\033[1;33m";
        default:           return "\033[0m";
    }
}

// Print the security table
void print_security_table(security_feature_t features[], int count) {
    printf("\n\033[1;36m╔═══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                          machsec " VERSION "                            ║\033[0m\n");
    printf("\033[1;36m╠═══════════════════════════════════════════════════════════════════╣\033[0m\n");

    for (int i = 0; i < count; i++) {
        printf("║ \033[1;33m%-20s\033[0m", features[i].name);

        const char *color = get_color_code(features[i].color);
        const char *text = features[i].display_text ? features[i].display_text : "Unknown";
        int display_len = strlen(text);
        printf("%s%s\033[0m", color, text);

        int padding = 65 - 19 - display_len;  // 65 total width - 20 name - actual text length
        printf("%*s║\n", padding, "");
    }

    printf("\033[1;36m╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n");
}

