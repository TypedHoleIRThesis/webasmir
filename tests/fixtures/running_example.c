/* Running example of the AsmWebIR draft, Part A section 2.
 * Each function is noinline so it survives as its own unit at -O1/-O2.
 * main threads argc through so nothing folds to a constant. */
#include <stdlib.h>

struct Node { struct Node *next; int val; };        /* web #d1, size 16 */
struct Counter { long zero; int count; };           /* web #d7, same shape, different web */

#define NOINLINE __attribute__((noinline))

NOINLINE int list_sum(struct Node *node)            /* sub_401000 */
{
    int total = 0;
    while (node) {
        total += node->val;
        node = node->next;
    }
    return total;
}

NOINLINE struct Node *list_push(struct Node *head, int v)  /* sub_401020 */
{
    struct Node *n = malloc(16);
    n->next = head;
    n->val = v;
    return n;
}

NOINLINE void counter_bump(struct Counter *p)       /* sub_401060 */
{
    p->count += 1;
    p->zero = 0;
}

typedef long (*handler)(long, long, unsigned long);

NOINLINE long h_ping(long a, long b, unsigned long len) { (void)len; return a ^ b; }
NOINLINE long h_data(long a, long b, unsigned long len) { return a + b * (long)len; }

handler table[2] = { h_ping, h_data };

NOINLINE long dispatcher(unsigned op, long a, long b, unsigned long len)
{
    return table[op & 1](a, b, len);
}

NOINLINE int sum16(const int *a)
{
    int s = 0;
    for (int i = 0; i != 16; i++)
        s += a[i];
    return s;
}

NOINLINE int iabs(int x) { return x < 0 ? -x : x; }

int main(int argc, char **argv)
{
    (void)argv;
    struct Node *h = 0;
    h = list_push(h, argc);
    h = list_push(h, 2);
    struct Counter c = { 5, argc };
    counter_bump(&c);
    int arr[16];
    for (int i = 0; i < 16; i++) arr[i] = i * argc;
    long r = dispatcher((unsigned)argc, argc, 3, 4);
    return (list_sum(h) + c.count + sum16(arr) + iabs(-argc) + (int)r) & 0x7f;
}
