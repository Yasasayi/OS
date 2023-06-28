#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next) {
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head) {
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head) {
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next) {
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline void list_del_init(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline void list_move(struct list_head *list, struct list_head *head) {
        __list_del(list->prev, list->next);
        list_add(list, head);
}

static inline void list_move_tail(struct list_head *list,
				  struct list_head *head) {
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}

static inline int list_empty(const struct list_head *head) {
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
  for (pos = (head)->next; pos != (head);	\
       pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
        	pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))

#if 0    //DEBUG
#define debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define debug(fmt, args...)
#endif

#define PAGESIZE (32)
#define PAS_FRAMES (256)
#define PAS_SIZE (PAGESIZE * PAS_FRAMES) // 32 * 256 = 8192 B
#define VAS_PAGES (64)
#define VAS_SIZE (PAGESIZE * VAS_PAGES) // 32 * 64 = 2048 B
#define PTE_SIZE (4)
#define PAGETABLE_FRAMES (VAS_PAGES * PTE_SIZE / PAGESIZE)  // 64 * 4 / 32 = 8

#define PAGE_INVALID (0)
#define PAGE_VALID (1)

#define MAX_REFERENCES (256)

typedef struct {
    unsigned char frame; // allocated frame
    unsigned char vflag; // valid-invalid bit
    unsigned char ref; // reference bit
    unsigned char pad; // padding
} pte; // page table entry (4 Bytes)

typedef struct {
    int pid;
    int ref_len;
    unsigned char* references;
    struct list_head job;
} process_raw;

typedef struct {
    unsigned char b[PAGESIZE];
} frame;

typedef struct {
    int pid;
    int ref_len;
} process;

LIST_HEAD(job_q);

int demandPaging(process_raw* data, pte* cur_pte, int i, int* frame_index)
{
    list_for_each_entry(data, &job_q, job)
    {
        int ref = *(data->references + i);
        int index = VAS_PAGES * data->pid + ref;

        if (data->ref_len - i > 0)
        {
            //printf("pid %03d ref %03d page access %03d: ", data->pid, i, ref);
            if (cur_pte[index].vflag == PAGE_INVALID)
            {
                if (*frame_index >= PAS_FRAMES)
                {
                    printf("Out of memory!!\n");
                    return -1;
                }
                cur_pte[index].vflag = PAGE_VALID;
                cur_pte[index].frame = *frame_index;
                cur_pte[index].ref++;
                //printf("page fault, allocated frame %d\n", (*frame_index)++);
                *frame_index = *frame_index + 1;
            }
            else if (cur_pte[index].vflag == PAGE_VALID)
            {
                cur_pte[index].ref++;
                //printf("frame %d\n", cur_pte[index].frame);
            }
        }
    }

    return 0;
}

void osSimulator(process_raw* data)
{
    frame* pas = (frame*)malloc(PAS_SIZE); // 32 B * 256 frames

    int max_len = 0; // max ref_len
    int count = 0; // number of process

    // find max_len
    list_for_each_entry(data, &job_q, job)
    {
        count++;
        if (max_len < data->ref_len)
        {
            max_len = data->ref_len;
        }
    }

    pte* cur_pte = (pte*)&pas[0]; // pas를 순회하기 위한 변수

    // free frame, page table을 count만큼 할당
    // 0 ~ frame_index - 1 까지 page table
    int frame_index = count * PAGETABLE_FRAMES;

    for (int i = 0; i < max_len; i++)
    {
        if (demandPaging(data, cur_pte, i, &frame_index) == -1)
        {
            break;
        }
    }

    // final report
    int total_frames = 0;
    int total_pf = 0;
    int total_ref = 0;

    list_for_each_entry(data, &job_q, job)
    {
        int start = VAS_PAGES * data->pid; // for() starting point
        // count page faults
        int pf = 0;

        for (int i = start; i < start + VAS_PAGES; i++)
        {
            if (cur_pte[i].vflag == PAGE_VALID && cur_pte[i].ref != 0)
            {
                pf++;
            }
        }
        total_pf += pf;

        // count refernces
        int references = 0;

        for (int i = start; i < start + VAS_PAGES; i++)
        {
            if (cur_pte[i].vflag == PAGE_VALID && cur_pte[i].ref != 0)
            {
                references += cur_pte[i].ref;
            }
        }

        int alloc_frames = PAGETABLE_FRAMES + pf;

        total_frames += alloc_frames;
        total_ref += references;

        printf("** Process %03d: Allocated Frames=%03d PageFaults/References=%03d/%03d\n",
            data->pid, alloc_frames, pf, references);
        for (int i = start; i < start + VAS_PAGES; i++)
        {
            if (cur_pte[i].vflag == PAGE_VALID)
            {
                printf("%03d -> %03d REF=%03d\n", i - start, cur_pte[i].frame, cur_pte[i].ref);
            }
        }
    }

    printf("Total: Allocated Frames=%03d Page Faults/References=%03d/%03d\n",
        total_frames, total_pf, total_ref);

    free(pas);
}

process_raw* initData(process_raw* data, process temp)
{
    // 프로세스 정보를 미리 temp에 읽어온 뒤 data로 옮기고 return함
    data = malloc(sizeof(*data));
    data->pid = temp.pid;
    data->ref_len = temp.ref_len;
    data->references = malloc(sizeof(*data->references) * data->ref_len);

    INIT_LIST_HEAD(&data->job);

    return data;
}

int main(int argc, char* argv[])
{
    process_raw* data = NULL;
    process temp;

    while (fread(&temp, sizeof(process), 1, stdin) == 1)
    {
        // data 변수 초기화
        data = initData(data, temp);

        fread(data->references, sizeof(*data->references), data->ref_len, stdin);

        list_add_tail(&data->job, &job_q);
    }

    osSimulator(data);

    //메모리 반환
    process_raw* next;
    list_for_each_entry_safe(data, next, &job_q, job)
    {
        list_del(&data->job);
        free(data->references);
        free(data);
    }

    return 0;
}