#include <stdio.h>
#include <string.h>
#include "table.h"

#define VERSION "1.6.1"

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

    // Print version header with proper centering
    char version_line[100];
    snprintf(version_line, sizeof(version_line), "machsec %s", VERSION);
    int version_len = strlen(version_line);
    int total_width = 67;  // Total width between the borders
    int left_padding = (total_width - version_len) / 2;
    int right_padding = total_width - version_len - left_padding;
    printf("\033[1;36m║%*s%s%*s║\033[0m\n", left_padding, "", version_line, right_padding, "");

    printf("\033[1;36m╠═══════════════════════════════════════════════════════════════════╣\033[0m\n");

    for (int i = 0; i < count; i++) {
        printf("║ \033[1;33m%-20s\033[0m", features[i].name);

        const char *color = get_color_code(features[i].color);
        const char *text = features[i].display_text ? features[i].display_text : "Unknown";
        int display_len = strlen(text);
        printf("%s%s\033[0m", color, text);

        // Calculate padding: total_width - "║ " - name_width - text_len - " ║"
        int padding = total_width - 1 - 20 - display_len;
        if (padding < 0) padding = 0;
        printf("%*s║\n", padding, "");
    }

    printf("\033[1;36m╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n");
}

