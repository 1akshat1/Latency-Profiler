#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/fs.h>		
#include <linux/proc_fs.h>	
#include <linux/seq_file.h>	
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

	/*	MACRO  */

#define STACK_DEPTH 16
#define MAX_SYMBOL_LEN	64
DEFINE_SPINLOCK(hashtbl_lock);
DEFINE_SPINLOCK(rbtree_lock);
unsigned long flags;

	/* Hash Table initialization */

DEFINE_HASHTABLE(first_table,14);

	/* RB Tree initialization */
	
struct rb_root my_root_rb = RB_ROOT;

static char task_1[MAX_SYMBOL_LEN] = "activate_task";
module_param_string(task_1, task_1, sizeof(task_1), 0644);

static char task_2[MAX_SYMBOL_LEN] = "deactivate_task";
module_param_string(task_2, task_2, sizeof(task_2), 0644);

	/* Kprobe structure */

static struct kprobe kp = {
	.symbol_name	= task_1,
};
static struct kprobe kp_1 = {
	.symbol_name	= task_2,
};

	/*Structure to store task information*/

struct myData {
	unsigned long stack[STACK_DEPTH];
	pid_t pid;
	struct stack_trace trace;
	char *name;
	unsigned long sleep_time;
	unsigned long deque_time;
	unsigned long user_stack[STACK_DEPTH];
	struct stack_trace user;
};

	/*Structure to store hashnode 
	* and RB node heads along
	* with pointer to task information
	*/

struct hash_node {
	struct hlist_node hash;
	struct rb_node mnode;
	struct myData *pointer_to_myData;	
};

	/* Initialize stack_trace */
	
static void initiliase(struct myData *cavity)
{
	cavity->trace.nr_entries = 0;
	cavity->trace.entries = cavity->stack;
	cavity->trace.max_entries = STACK_DEPTH;
	cavity->trace.skip = 0;
	cavity->sleep_time = 0;
	cavity->deque_time = 0;
	cavity->user.nr_entries = 0;
	cavity->user.entries = cavity->user_stack;
	cavity->user.max_entries = STACK_DEPTH;
	cavity->user.skip = 0;
}
	
	/*	RB Tree Insert Function	*/

static void enter(struct rb_root *my_root_rb, struct hash_node *tmp)
{
		struct rb_node **chain = &my_root_rb->rb_node;
		struct rb_node *p = NULL;
		struct hash_node *insert;
			
		while(*chain) {
		p = *chain;
		insert = rb_entry(p, struct hash_node, mnode);
		if(tmp->pointer_to_myData->sleep_time <= insert->pointer_to_myData->sleep_time)
		chain = &p->rb_left;
		else
		chain = &p->rb_right;
		}
						
		rb_link_node(&tmp->mnode,p,chain);
		rb_insert_color(&tmp->mnode, my_root_rb);
}


	/*	Hash Table Search Function, 
	*	returns NULL if elemen not there 
	*	and pointer to the element if 
	*	found
	*/

struct hash_node* hash_search(unsigned key, struct hash_node *data_to_be_compared ){
	
	int match;
	int i;
	struct hash_node *cursor;

	hash_for_each_possible(first_table, cursor, hash, key){
		if(data_to_be_compared->pointer_to_myData->pid == cursor->pointer_to_myData->pid){
			match = 0;
			for(i=0;i<cursor->pointer_to_myData->trace.nr_entries;i++){
				if(!(data_to_be_compared->pointer_to_myData->trace.entries[i] == cursor->pointer_to_myData->trace.entries[i])){
					break;
				}
				else
					match++;
			}
			if(match == cursor->pointer_to_myData->trace.nr_entries)
				return cursor;
		}		
	}
		return NULL;	
}

	/* Hash Key Generation function */

unsigned int key_gen(struct myData *current_cavity){

	unsigned size, key;
	int i;
	
	/* Garbage value issue for hash function*/	
	
	if(current_cavity->trace.nr_entries<STACK_DEPTH){
		for(i=(current_cavity->trace.nr_entries+1);i<=(STACK_DEPTH-current_cavity->trace.nr_entries);i++)
			current_cavity->trace.entries[i] = 0;
	}
	size = sizeof(current_cavity->pid) + sizeof(current_cavity->trace.entries);
	key = jhash(current_cavity, size, 0);
	return key;

}

	/*	User stack printing	*/

struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

static int
copy_stack_frame(const void __user *fp, struct stack_frame_user *frame)
{
	int ret;

	if (!access_ok(VERIFY_READ, fp, sizeof(*frame)))
		return 0;

	ret = 1;
	pagefault_disable();
	if (__copy_from_user_inatomic(frame, fp, sizeof(*frame)))
		ret = 0;
	pagefault_enable();

	return ret;
}

static inline void __save_stack_trace_user(struct stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(current);
	const void __user *fp = (const void __user *)regs->bp;

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = regs->ip;

	while (trace->nr_entries < trace->max_entries) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
		if (!copy_stack_frame(fp, &frame))
			break;
		if ((unsigned long)fp < regs->sp)
			break;
		if (frame.ret_addr) {
			trace->entries[trace->nr_entries++] =
				frame.ret_addr;
		}
		if (fp == frame.next_fp)
			break;
		fp = frame.next_fp;
	}
}

void save_stack_trace_user(struct stack_trace *trace)
{
	/*
	 * Trace user stack if we are not a kernel thread
	 */
	if (current->mm) {
		__save_stack_trace_user(trace);
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

	/*Prehandler*/

static int handler_pre_act(struct kprobe *p, struct pt_regs *regs)
{
	
unsigned key;
struct task_struct *ts;	
struct myData *cavity;

	/* Declaring variable to store myData */

struct hash_node *cursor, *cursor_1;	
 
cavity = kmalloc(sizeof(struct myData), GFP_ATOMIC);
	if(!cavity)
		return -ENOMEM;

initiliase(cavity);

	/* Storing current task vairables */

ts = (struct task_struct*)regs->si;
cavity->pid = ts->pid;
cavity->name = ts->comm;
	
	/* Saving current process's stack */
	
save_stack_trace_tsk(ts,&cavity->trace);


	/* Getting the hashed key */
	
key = key_gen(cavity);

	/* Hash Node initialization */

cursor = kmalloc(sizeof(struct hash_node),GFP_ATOMIC);
	if(!cursor)
		return -ENOMEM;

	/* Add current task value */
	
cursor->pointer_to_myData = cavity;

	/*  Check if current value 
	*	exists or not, if not then add 
	*	else update sleeping time
	*/

if(hash_empty(first_table)){
	cursor->pointer_to_myData->sleep_time = rdtsc();
	
	spin_lock_irqsave(&hashtbl_lock, flags);
		hash_add(first_table, &cursor->hash, key);
	spin_unlock_irqrestore(&hashtbl_lock, flags);
	
	spin_lock_irqsave(&rbtree_lock, flags);
		enter(&my_root_rb,cursor);
	spin_unlock_irqrestore(&rbtree_lock, flags);
}
else{
	spin_lock_irqsave(&hashtbl_lock, flags);
		cursor_1 = hash_search(key, cursor);
	spin_unlock_irqrestore(&hashtbl_lock, flags);
	
	if(cursor_1 == NULL){
		spin_lock_irqsave(&hashtbl_lock, flags);
			cursor->pointer_to_myData->sleep_time = 0;
			hash_add(first_table, &cursor->hash, key);
		spin_unlock_irqrestore(&hashtbl_lock, flags);
		
		spin_lock_irqsave(&rbtree_lock, flags);
			enter(&my_root_rb,cursor);
		spin_unlock_irqrestore(&rbtree_lock, flags);
	}
	else{
		spin_lock_irqsave(&hashtbl_lock, flags);
			cursor_1->pointer_to_myData->sleep_time += rdtsc() - cursor_1->pointer_to_myData->deque_time;
		spin_unlock_irqrestore(&hashtbl_lock, flags);
		
		spin_lock_irqsave(&rbtree_lock, flags);
			rb_erase(&(cursor_1->mnode),&my_root_rb);
			enter(&my_root_rb,cursor_1);
		spin_unlock_irqrestore(&rbtree_lock, flags);
		}
			
}

return 0;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	
	
	
	/* Return 0 because we don't handle the fault. */
	return 0;
}


static int handler_pre_de(struct kprobe *p, struct pt_regs *regs)
{

struct myData *cavity; 
struct task_struct *ts;
struct hash_node *cursor, *cursor_1;
unsigned key;
cavity = kmalloc(sizeof(struct myData), GFP_ATOMIC);
	if(!cavity)
		return -ENOMEM;

initiliase(cavity);

	/* Storing current task vairables */

ts = (struct task_struct*)regs->si;
cavity->pid = ts->pid;
cavity->trace.skip = 5;
	
	/* Saving current process's stack */
	
save_stack_trace_tsk(ts,&cavity->trace);

	/* Getting the hashed key */

key = key_gen(cavity);


	/* Hash Node initialization */

cursor = kmalloc(sizeof(struct hash_node),GFP_ATOMIC);
	if(!cursor)
		return -ENOMEM;

cursor->pointer_to_myData = cavity;


spin_lock_irqsave(&hashtbl_lock, flags);
	cursor_1 = hash_search(key, cursor);
spin_unlock_irqrestore(&hashtbl_lock, flags);
	
if(cursor_1!=NULL){
	spin_lock_irqsave(&hashtbl_lock, flags);
		save_stack_trace_user(&cursor_1->pointer_to_myData->user);	
		cursor_1->pointer_to_myData->deque_time = rdtsc();
	spin_unlock_irqrestore(&hashtbl_lock, flags);	
	}
kfree(cavity);
kfree(cursor);
	return 0;
}


static int lattop_show(struct seq_file *m, void *v) {
    
	char* test;
	char* test2;
	struct hash_node *cursor;
	struct rb_node *iter;
	test = kmalloc(300*sizeof(char),GFP_ATOMIC);
	test2 = kmalloc(300*sizeof(char),GFP_ATOMIC);
	
	seq_printf(m, "Latency Profiler!\n");
	seq_printf(m, "Begins...\n");
	
	/*	Iterating through the RB Tree  */
	
	spin_lock_irqsave(&rbtree_lock, flags);
	iter = rb_last(&my_root_rb);
    while(iter){
        cursor = rb_entry(iter, struct hash_node, mnode);
		if(cursor->pointer_to_myData->sleep_time != 0){
		snprint_stack_trace(test, 300, &cursor->pointer_to_myData->trace, 4);
		seq_printf(m, "Sleep : %lu\n", cursor->pointer_to_myData->sleep_time);
		seq_printf(m, "Name : %s\n", cursor->pointer_to_myData->name);
		seq_printf(m, "PID : %d\n", cursor->pointer_to_myData->pid);
		seq_printf(m, "%s\n", test);
		snprint_stack_trace(test2, 300, &cursor->pointer_to_myData->user, 4);
		seq_printf(m, "User Stack:\n%s\n", test2);
		}
        iter = rb_prev(iter);
    };
	spin_unlock_irqrestore(&rbtree_lock, flags);
	kfree(test);
	kfree(test2);
    return 0;
}

static int lattop_open(struct inode *inode, struct  file *file) {
    return single_open(file, lattop_show, NULL);
}

static const struct file_operations lattop_fops = {
    .owner = THIS_MODULE,
    .open = lattop_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};


static int __init kprobe_init(void)
{
	int ret, ret_1;
	hash_init(first_table);
	kp.pre_handler = handler_pre_act;
	kp.fault_handler = handler_fault;
	kp_1.pre_handler = handler_pre_de;
	kp_1.fault_handler = handler_fault;
	
	
	
	ret = register_kprobe(&kp);
	ret_1 = register_kprobe(&kp_1);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	if (ret_1 < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret_1);
		return ret_1;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	pr_info("Planted kprobe at %p\n", kp_1.addr);
	
	if(!proc_create("lattop", 0, NULL, &lattop_fops)){
		return -ENOMEM;
	}
	else{
	pr_info("Process lattop proc created");
	}
	
	return 0;
}



static void __exit kprobe_exit(void)
{
	struct hash_node *cursor_2;
	struct hlist_node *tmp;
	int bkt;
	unregister_kprobe(&kp);
	unregister_kprobe(&kp_1);

	
	/*Removing the hashtable*/
	
		hash_for_each_safe(first_table, bkt, tmp, cursor_2, hash){
			spin_lock_irqsave(&hashtbl_lock, flags);
			hash_del(&cursor_2->hash);
			spin_unlock_irqrestore(&hashtbl_lock, flags);
			kfree(cursor_2->pointer_to_myData);
			kfree(cursor_2);
		}
	 
	remove_proc_entry("lattop", NULL);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
