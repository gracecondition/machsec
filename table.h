#ifndef SECURITY_TABLE_H
#define SECURITY_TABLE_H

// Color enum
typedef enum {
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_RESET
} text_color_t;

// Security feature struct
typedef struct {
    char name[30];          // feature name
    const char *display_text;  // text to show in table
    text_color_t color;     // text color
} security_feature_t;

// Function to print the table
void print_security_table(security_feature_t features[], int count);

#endif

