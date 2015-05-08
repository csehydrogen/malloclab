#include <stdio.h>

/*********************************************************
 * Records the extent of each block's payload
 * for evaluate the validity of your allocator
 * DON'T MODIFY THIS STRUCT.
 ********************************************************/
typedef struct range_t {
  char *lo;              /* low payload address */
  char *hi;              /* high payload address */
  struct range_t *next;  /* next list element */
} range_t;

/*
 * Function lists which student should implement.
 */
extern int mm_init (range_t **ranges);
extern void *mm_malloc (size_t size);
extern void mm_free (void *ptr);
extern void mm_exit (void);

/*
 * Students work in teams of one or two.  Teams enter their team name,
 * personal names and student IDs in a struct of this
 * type in their mm.c file.
 */
typedef struct {
    char *teamname; /* ID1+ID2 or ID1 */
    char *name1;    /* full name of first member */
    char *id1;      /* student ID of first member */
    char *name2;    /* full name of second member (if any) */
    char *id2;      /* student ID of second member */
} team_t;

extern team_t team;

// this is here for completeness, you don't need to implement this!
extern void *mm_realloc(void *ptr, size_t size);
