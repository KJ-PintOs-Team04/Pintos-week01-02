/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
# define MIN_USER_STACK (USER_STACK - (1 << 20))
static bool vm_copy_uninit_page(struct page *page, bool writable);
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&hash_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

		// struct page *page = calloc(1, sizeof(struct page));
		struct page *page = malloc(sizeof(struct page));
		/* create "uninit" page struct according to the VM type */
		if (VM_TYPE(type) == VM_ANON)
			uninit_new(page, upage, init, type, aux, anon_initializer);
		else if (VM_TYPE(type) == VM_FILE)
			uninit_new(page, upage, init, type, aux, file_backed_initializer);
		else
			return false;
		// printf("writable: %d\n", writable);
		// printf("va: %p\n", upage);
		page->writable = writable;

		/* Insert the page into the spt */
		int succ = spt_insert_page(spt, page);
		ASSERT(succ == true);

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	struct page p;
  	struct hash_elem *e;

  	p.va = pg_round_down(va); 
	e = hash_find(spt->h, &p.hash_elem);

	return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	int succ = false;
	struct hash_elem *e;

	/* TODO: Fill this function. */
	lock_acquire(&hash_lock);
	e = hash_insert(spt->h, &page->hash_elem);
	lock_release(&hash_lock);
	if (!e)
		succ = true;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	struct frame *frame = calloc(1, sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->kva = palloc_get_page(PAL_USER);
	if (!frame->kva)
		PANIC("todo");
	// TODO: initialize frame's member
	
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_STACK_PAGE, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	/* TODO: Validate the fault */
	/*
	 1. If the supplemental page table indicates that the user process should not expect any data at the address 
	 2. if the page lies within kernel virtual memory, 
	 3. if the access is an attempt to write to a read-only page
	 */
	/* TODO: Your code goes here */
	
	/* valid check */
	if (!not_present || addr == NULL || is_kernel_vaddr(addr))
		exit(-1);
	struct page *page = spt_find_page(spt, addr);
	uintptr_t rsp = user ? f->rsp : thread_current()->rsp;
	// printf("fault_addr: %p\n", addr);

	/* case for stack growth */
	if (!page && addr < USER_STACK && addr > MIN_USER_STACK && addr >= rsp - 8) {
		
		void *new_stack_bottom = pg_round_down(addr);
		vm_stack_growth(new_stack_bottom);
		return vm_claim_page(new_stack_bottom);
	}

	/* cannot find page in spt */
	if (!page) 
		exit(-1);

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	/* TODO: Fill this function */
	struct page *page = spt_find_page(&thread_current ()->spt, va);
	if (page)
		return vm_do_claim_page (page);

	return false;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();

	if (pml4_get_page(curr->pml4, page->va))
		return false;
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	bool succ = pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);
	ASSERT(succ == true);

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	spt->h = calloc(1, sizeof(struct hash));
	hash_init(spt->h, page_hash, page_less, NULL);
	// lock_init(&spt->spt_lock);

}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	struct hash_iterator i;
	struct page *p;
	struct thread *curr = thread_current();
	void *parent_page;

	/* Iterate through each page in the src's supplemental page table */
	hash_first (&i, src->h);
	while (hash_next (&i)) {
		p = hash_entry (hash_cur (&i), struct page, hash_elem);

		enum vm_type type = p->operations->type;


		if (VM_TYPE(type) == VM_UNINIT) {
			lazy *aux = malloc(sizeof(lazy));
			memcpy(aux, p->uninit.aux, sizeof(*aux));	
			bool alloc = vm_alloc_page_with_initializer(page_get_type(p), p->va, p->writable, p->uninit.init, aux);
			ASSERT(alloc == true);
			continue;
		}

		/* alloc page */
		bool alloc = vm_alloc_page(type, p->va, p->writable);
		ASSERT(alloc == true);
		
		
		parent_page = pml4_get_page (curr->parent->pml4, p->va);
		if (parent_page) {
			struct page *newpage = spt_find_page(dst, p->va);
			struct frame *frame = vm_get_frame ();
			/* Set links */
			frame->page = newpage;
			newpage->frame = frame;

			memcpy(frame->kva, parent_page, PGSIZE);

			/* TODO: Insert page table entry to map page's VA to frame's PA. */
			bool succ = pml4_set_page(curr->pml4, newpage->va, frame->kva, newpage->writable);
			ASSERT(succ == true);

			swap_in(newpage, frame->kva);
		}	
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if (spt->h) {
		lock_acquire(&hash_lock);
		hash_destroy(spt->h, page_free);
		lock_release(&hash_lock);
		free(spt->h);
	}
	// TODO: writeback(cache)
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}


void
page_free (struct hash_elem *e, void *aux) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	
	destroy(page);
	free(page);
}