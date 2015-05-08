/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name : Your student ID */
    "2013-11395",
    /* Your full name */
    "HeeHoon Kim",
    /* Your student ID */
    "2013-11395",
    /* leave blank */
    "",
    /* leave blank */
    ""
};

/* DON'T MODIFY THIS VALUE AND LEAVE IT AS IT WAS */
static range_t **gl_ranges;

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8
#define HEADER_SIZE 8
#define MIN_BLOCK_SIZE 24

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define PREV_SIZE(p) (*(size_t*)(p))
#define PREV_SIZE_MASKED(p) (PREV_SIZE(p) & ~0x7)
#define PREV_FREE(p) (PREV_SIZE(p) & 0x1)
#define CUR_SIZE(p) (*(size_t*)((p) + 4))
#define CUR_SIZE_MASKED(p) (CUR_SIZE(p) & ~0x7)
#define CUR_FREE(p) (CUR_SIZE(p) & 0x1)
#define RB_LEFT(p) (*(void**)((p) + 8))
#define RB_RIGHT(p) (*(void**)((p) + 12))
#define RB_PARENT(p) (*(void**)((p) + 16))
#define RB_RED(p) (*(int*)((p) + 20))
#define PREV_BLOCK(p, sz) ((p) - (sz))
#define NEXT_BLOCK(p, sz) ((p) + (sz))
#define USER_BLOCK(p) ((p) + HEADER_SIZE)

static void *rb_root, *rb_null;

/* 
 * remove_range - manipulate range lists
 * DON'T MODIFY THIS FUNCTION AND LEAVE IT AS IT WAS
 */
static void remove_range(range_t **ranges, char *lo)
{
    range_t *p;
    range_t **prevpp = ranges;

    if (!ranges)
        return;

    for (p = *ranges;  p != NULL; p = p->next) {
        if (p->lo == lo) {
            *prevpp = p->next;
            free(p);
            break;
        }
        prevpp = &(p->next);
    }
}

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(range_t **ranges)
{
    /* YOUR IMPLEMENTATION */
    rb_root = mem_sbrk(4 + MIN_BLOCK_SIZE + MIN_BLOCK_SIZE);
    rb_null = rb_root + MIN_BLOCK_SIZE;
    RB_LEFT(rb_root) = RB_RIGHT(rb_root) = rb_null;
    RB_RED(rb_root) = 0;
    // prevent coalesce
    PREV_SIZE(NEXT_BLOCK(rb_null, MIN_BLOCK_SIZE)) = 0;

    /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
    gl_ranges = ranges;

    return 0;
}

static void* rb_find(size_t size){
    void *node = RB_LEFT(rb_root), *best = rb_null;
    while(node != rb_null){
        if(CUR_SIZE_MASKED(node) < size){
            node = RB_RIGHT(node);
        }else{
            best = node;
            node = RB_LEFT(node);
        }
    }
    return best;
}

static void* rb_successor(void *node){
    void *succ, *left;
    if((succ = RB_RIGHT(node)) != rb_null){
        while((left = RB_LEFT(succ)) != rb_null){
            succ = left;
        }
        return succ;
    }else{
        succ = RB_PARENT(node);
        while(RB_RIGHT(succ) == node){
            node = succ;
            succ = RB_PARENT(succ);
        }
        if(succ == rb_root) return rb_null;
        return succ;
    }
}

static void rb_rotate_left(void *node){
    void *right;

    right = RB_RIGHT(node);
    RB_RIGHT(node) = RB_LEFT(right);
    if(RB_LEFT(right) != rb_null)
        RB_PARENT(RB_LEFT(right)) = node;

    RB_PARENT(right) = RB_PARENT(node);
    if(node == RB_LEFT(RB_PARENT(node))){
        RB_LEFT(RB_PARENT(node)) = right;
    }else{
        RB_RIGHT(RB_PARENT(node)) = right;
    }
    RB_LEFT(right) = node;
    RB_PARENT(node) = right;
}

static void rb_rotate_right(void *node){
    void *left;

    left = RB_LEFT(node);
    RB_LEFT(node) = RB_RIGHT(left);
    if(RB_RIGHT(left) != rb_null)
        RB_PARENT(RB_RIGHT(left)) = node;

    RB_PARENT(left) = RB_PARENT(node);
    if(node == RB_LEFT(RB_PARENT(node))){
        RB_LEFT(RB_PARENT(node)) = left;
    }else{
        RB_RIGHT(RB_PARENT(node)) = left;
    }
    RB_RIGHT(left) = node;
    RB_PARENT(node) = left;
}

static void rb_fix(void *node){
    void *root, *sib;
    root = RB_LEFT(rb_root);
    while(!RB_RED(node) && node != root){
        if(node == RB_LEFT(RB_PARENT(node))){
            sib = RB_RIGHT(RB_PARENT(node));
            if(RB_RED(sib)){
                RB_RED(sib) = 0;
                RB_RED(RB_PARENT(node)) = 1;
                rb_rotate_left(RB_PARENT(node));
                sib = RB_RIGHT(RB_PARENT(node));
            }
            if(!RB_RED(RB_RIGHT(sib)) && !RB_RED(RB_LEFT(sib))){
                RB_RED(sib) = 1;
                node = RB_PARENT(node);
            }else{
                if(!RB_RED(RB_RIGHT(sib))){
                    RB_RED(RB_LEFT(sib)) = 0;
                    RB_RED(sib) = 1;
                    rb_rotate_right(sib);
                    sib = RB_RIGHT(RB_PARENT(node));
                }
                RB_RED(sib) = RB_RED(RB_PARENT(node));
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(RB_RIGHT(sib)) = 0;
                rb_rotate_left(RB_PARENT(node));
                node = root;
            }
        }else{
            sib = RB_LEFT(RB_PARENT(node));
            if(RB_RED(sib)){
                RB_RED(sib) = 0;
                RB_RED(RB_PARENT(node)) = 1;
                rb_rotate_right(RB_PARENT(node));
                sib = RB_LEFT(RB_PARENT(node));
            }
            if(!RB_RED(RB_RIGHT(sib)) && !RB_RED(RB_LEFT(sib))){
                RB_RED(sib) = 1;
                node = RB_PARENT(node);
            }else{
                if(!RB_RED(RB_LEFT(sib))){
                    RB_RED(RB_RIGHT(sib)) = 0;
                    RB_RED(sib) = 1;
                    rb_rotate_left(sib);
                    sib = RB_LEFT(RB_PARENT(node));
                }
                RB_RED(sib) = RB_RED(RB_PARENT(node));
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(RB_LEFT(sib)) = 0;
                rb_rotate_right(RB_PARENT(node));
                node = root;
            }
        }
        
    }
    RB_RED(node) = 0;
}

static void rb_delete(void *node){
    void *m, *c;
    m = RB_LEFT(node) == rb_null || RB_RIGHT(node) == rb_null ? node : rb_successor(node);
    c = RB_LEFT(m) == rb_null ? RB_RIGHT(m) : RB_LEFT(m);
    if((RB_PARENT(c) = RB_PARENT(m)) == rb_root){
        RB_LEFT(rb_root) = c;
    }else{
        if(RB_LEFT(RB_PARENT(m)) == m){
            RB_LEFT(RB_PARENT(m)) = c;
        }else{
            RB_RIGHT(RB_PARENT(m)) = c;
        }
    }
    if(m != node){
        if(!RB_RED(m)) rb_fix(c);
        RB_LEFT(m) = RB_LEFT(node);
        RB_RIGHT(m) = RB_RIGHT(node);
        RB_PARENT(m) = RB_PARENT(node);
        RB_RED(m) = RB_RED(node);
        RB_PARENT(RB_LEFT(node)) = RB_PARENT(RB_RIGHT(node)) = m;
        if(node == RB_LEFT(RB_PARENT(node))){
            RB_LEFT(RB_PARENT(node)) = m;
        }else{
            RB_RIGHT(RB_PARENT(node)) = m;
        }
    }else{
        if(!RB_RED(m)) rb_fix(c);
    }
}

static void rb_insert(void *node){
    void *parent, *child, *sib;

    RB_LEFT(node) = RB_RIGHT(node) = rb_null;
    parent = rb_root;
    child = RB_LEFT(rb_root);
    while(child != rb_null){
        parent = child;
        if(CUR_SIZE_MASKED(child) > CUR_SIZE_MASKED(node)){
            child = RB_LEFT(child);
        }else{
            child = RB_RIGHT(child);
        }
    }
    RB_PARENT(node) = parent;
    if(parent == rb_root || CUR_SIZE_MASKED(parent) > CUR_SIZE_MASKED(node)){
        RB_LEFT(parent) = node;
    }else{
        RB_RIGHT(parent) = node;
    }

    RB_RED(node) = 1;
    while(RB_RED(RB_PARENT(node))){
        if(RB_PARENT(node) == RB_LEFT(RB_PARENT(RB_PARENT(node)))){
            sib = RB_RIGHT(RB_PARENT(RB_PARENT(node)));
            if(RB_RED(sib)){
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(sib) = 0;
                RB_RED(RB_PARENT(RB_PARENT(node))) = 1;
                node = RB_PARENT(RB_PARENT(node));
            }else{
                if(node == RB_RIGHT(RB_PARENT(node))){
                    node = RB_PARENT(node);
                    rb_rotate_left(node);
                }
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(RB_PARENT(RB_PARENT(node))) = 1;
                rb_rotate_right(RB_PARENT(RB_PARENT(node)));
            }
        }else{
            sib = RB_LEFT(RB_PARENT(RB_PARENT(node)));
            if(RB_RED(sib)){
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(sib) = 0;
                RB_RED(RB_PARENT(RB_PARENT(node))) = 1;
                node = RB_PARENT(RB_PARENT(node));
            }else{
                if(node == RB_LEFT(RB_PARENT(node))){
                    node = RB_PARENT(node);
                    rb_rotate_right(node);
                }
                RB_RED(RB_PARENT(node)) = 0;
                RB_RED(RB_PARENT(RB_PARENT(node))) = 1;
                rb_rotate_left(RB_PARENT(RB_PARENT(node)));
            }
        }
    }
    RB_RED(RB_LEFT(rb_root)) = 0;
}

static void rb_preorder_impl(void *node){
    if(RB_LEFT(node) != rb_null){
        rb_preorder_impl(RB_LEFT(node));
    }
    printf("%p : %u\n", node, CUR_SIZE_MASKED(node));
    if(RB_RIGHT(node) != rb_null){
        rb_preorder_impl(RB_RIGHT(node));
    }
}

static void rb_preorder(){
    printf("rb_preorder()\n");
    if(RB_LEFT(rb_root) == rb_null){
        printf("empty\n");
    }else{
        rb_preorder_impl(RB_LEFT(rb_root));
    }
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void* mm_malloc(size_t size)
{
    size_t block_size, next_block_size;
    void *free_block, *next_block;
    
    block_size = ALIGN(HEADER_SIZE + size);
    block_size = block_size < MIN_BLOCK_SIZE ? MIN_BLOCK_SIZE : block_size;

    free_block = rb_find(block_size);
    if(free_block == rb_null){
        free_block = mem_heap_hi() - 3;
        if(PREV_FREE(free_block)){
            free_block -= PREV_SIZE_MASKED(free_block);
            if(CUR_SIZE_MASKED(free_block) >= MIN_BLOCK_SIZE){
                rb_delete(free_block);
            }
            mem_sbrk(block_size - CUR_SIZE_MASKED(free_block));
        }else{
            mem_sbrk(block_size);
        }
        CUR_SIZE(free_block) = PREV_SIZE(NEXT_BLOCK(free_block, block_size)) = block_size;
    }else{
        rb_delete(free_block);
        next_block = NEXT_BLOCK(free_block, block_size);
        PREV_SIZE(next_block) = block_size;
        if((next_block_size = CUR_SIZE_MASKED(free_block) - block_size) > 0){
            CUR_SIZE(next_block) = PREV_SIZE(NEXT_BLOCK(next_block, next_block_size)) = next_block_size | 1;
            if(next_block_size >= MIN_BLOCK_SIZE){
                rb_insert(next_block);
            }
        }
        CUR_SIZE(free_block) = block_size;
    }
    /*printf("mm_malloc(%u)\n", size);
    printf("free_block : %p\n", free_block);
    rb_preorder();*/
    return USER_BLOCK(free_block);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size, new_size;
    void *prev, *cur, *next, *new_block;

    cur = ptr - HEADER_SIZE;

    new_block = cur;
    new_size = CUR_SIZE_MASKED(cur);

    if(PREV_FREE(cur)){
        size = PREV_SIZE_MASKED(cur);
        prev = PREV_BLOCK(cur, size);
        if(size >= MIN_BLOCK_SIZE){
            rb_delete(prev);
        }
        new_block = prev;
        new_size += size;
    }

    size = CUR_SIZE_MASKED(cur);
    next = NEXT_BLOCK(cur, size);
    if(next + 4 <= mem_heap_hi() && CUR_FREE(next)){
        size = CUR_SIZE_MASKED(next);
        if(size >= MIN_BLOCK_SIZE){
            rb_delete(next);
        }
        new_size += size;
    }

    CUR_SIZE(new_block) = PREV_SIZE(NEXT_BLOCK(new_block, new_size)) = new_size | 1;
    if(new_size >= MIN_BLOCK_SIZE){
        rb_insert(new_block);
    }
    
    /*printf("mm_free(%p)\n", ptr);
    printf("new_block : %p\n", new_block);
    rb_preorder();*/

    /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
    if (gl_ranges)
        remove_range(gl_ranges, ptr);
}

/*
 * mm_realloc - empty implementation; YOU DO NOT NEED TO IMPLEMENT THIS
 */
void* mm_realloc(void *ptr, size_t t)
{
    return NULL;
}

/*
 * mm_exit - finalize the malloc package.
 */
void mm_exit(void)
{
}
