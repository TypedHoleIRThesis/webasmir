/* A hand-sized AsmWebIR example: one data web across three functions.
 * Build: see build.sh (Ubuntu 22.04, GCC 11.4, -O1, same flags as the webasmir fixtures). */
#include <stdlib.h>

struct Pair { long key; int val; };            /* key at +0 (8B), val at +8 (4B), size 16 */

__attribute__((noinline)) int get_val(struct Pair *p) { return p->val; }

__attribute__((noinline)) struct Pair *make(int v)
{
    struct Pair *p = malloc(16);
    p->key = 7;
    p->val = v;
    return p;
}

int main(int argc, char **argv)
{
    (void)argv;
    return get_val(make(argc));
}
