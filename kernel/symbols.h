#include "types.h"
struct symbol {
    uint64  addr;
    char*   filename;
    char *  funcname;
    int     lineno;
};
extern const struct symbol symbols[];
extern const int num_symbols;