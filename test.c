#include <stdio.h>
#include <stdint.h>
//#include "msg_malloc.c"
#ifdef RCHECK
#define	RSLOP		sizeof (u_short)
#else
#define	RSLOP		0
#endif

#define	NBUCKETS 30
union overhead *nextf[NBUCKETS];

typedef char * caddr_t;

#define	MAGIC		0xef		/* magic # on accounting info */

static	int pagesz;			/* page size */
static	int pagebucket;			/* page size bucket */

union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
		uint8_t	ovu_magic;	/* magic number */
		uint8_t	ovu_index;	/* bucket # */
#ifdef RCHECK
		u_short	ovu_rmagic;	/* range magic number */
		u_int	ovu_size;	/* actual block size */
#endif
	} ovu;
        uint8_t  alignment_pad[8];       /* *** eight-byte alignment *** */
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
#define	ov_rmagic	ovu.ovu_rmagic
#define	ov_size		ovu.ovu_size
};

void *
myalloc(nbytes)
	unsigned nbytes;
{
  	register union overhead *op;
  	register int bucket, n;
	register unsigned amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */
	if (pagesz == 0) {
#if defined( HPUX )
                pagesz = n = (int)sysconf(_SC_PAGE_SIZE);
#elif defined( SOLARIS ) || defined ( SOLARIS_X86 ) || defined (UNIXWARE)
                pagesz = n = (int)sysconf(_SC_PAGESIZE);
#else
                pagesz = n = getpagesize();
#endif
		op = (union overhead *)sbrk(0);
  		n = n - sizeof (*op) - ((int)op & (n - 1));
		if (n < 0)
			n += pagesz;
  		if (n) {
  			if ((char *)sbrk(n) == (char *)-1)
			{

				return (NULL);
			}
		}
		bucket = 0;
		amt = 8;
		while (pagesz > amt) {
			amt <<= 1;
			bucket++;
		}
		pagebucket = bucket;
	}
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	if (nbytes <= (n = pagesz - sizeof (*op) - RSLOP)) {
#ifndef RCHECK
		amt = 8;	/* size of first bucket */
		bucket = 0;
#else
		amt = 16;	/* size of first bucket */
		bucket = 1;
#endif
		n = -(sizeof (*op) + RSLOP);
	} else {
		amt = pagesz;
		bucket = pagebucket;
	}
	while (nbytes > amt + n) {
		amt <<= 1;
		if (amt == 0)
		{

			return (NULL);
		}
		bucket++;
	}
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
  	if ((op = nextf[bucket]) == NULL) {
            {
                /* Start of inlined morecore. */
                int bucket1 = bucket;
                register union overhead *op;
                register int sz;		/* size of desired block */
                int amt;			/* amount to allocate */
                int nblks;			/* how many blocks we get */
                
                /*
                 * sbrk_size <= 0 only for big, FLUFFY, requests (about
                 * 2^30 bytes on a VAX, I think) or for a negative arg.
                 */
                sz = 1 << (bucket1 + 3);
#ifdef DEBUG
                ASSERT(sz > 0);
#else
                if (sz <= 0)
                    goto morecore_return;
#endif
                if (sz < pagesz) {
                    amt = pagesz;
                    nblks = amt / sz;
                } else {
                    amt = sz + pagesz;
                    nblks = 1;
                }
                op = (union overhead *)sbrk(amt);
                /* no more room! */
                if ((int)op == -1)
                    goto morecore_return;
                /*
                 * Add new memory allocated to that on
                 * free list for this hash bucket.
                 */
                nextf[bucket1] = op;
                while (--nblks > 0) {
                    op->ov_next = (union overhead *)((caddr_t)op + sz);
                    op = (union overhead *)((caddr_t)op + sz);
                } /* End of inlined morecore. */
              morecore_return:;
            }
            if ((op = nextf[bucket]) == NULL)
            {

                return (NULL);
            }
	}
	/* remove from linked list */
  	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
#ifdef MSTATS
  	nmalloc[bucket]++;
#endif
#ifdef RCHECK
	/*
	 * Record allocated size of block and
	 * bound space with magic numbers.
	 */
	op->ov_size = (nbytes + RSLOP - 1) & ~(RSLOP - 1);
	op->ov_rmagic = RMAGIC;
  	*(u_short *)((caddr_t)(op + 1) + op->ov_size) = RMAGIC;
#endif
  	return ((char *)(op + 1));
}



typedef struct point{
int x,y;
}p;

void main(){
	p b;
	b.x = 10;
	b.y = 20;
	p * a; 
	a = (p*)myalloc(sizeof(struct point));
	a->x = 30;
	a->y = 40;
	printf("%ld\n%d\n%d\n%d\n%d\n",a,b.x,b.y,a->x,a->y);
	printf("hello world\n");
}
