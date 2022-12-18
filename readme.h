#ifndef __README_H__
#define __README_H__

/****************************************************
 *       作用： 整理ebpf的map类型和用法(内核态)
 *       日期： 2022.12.18
 *       特别说明：并非严格的头文件，不能引用
 ****************************************************/






/****************************************************
 *          section 0： MAP结构定义                  *
 ****************************************************/

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

/****************************************************
 *          section 1： MAP的操作函数                *
 *      内核空间,MAP操作函数类型少于用户空间           *
 ****************************************************/

/* ------------>  1. 创建 MAP
 * @说明：
 *   目前创建MAP的方式主要有三种：
 *      方法一： 用户空间, 使用bpf系统调用创建
 *      方法二： 用户空间, 使用封装后的bpf系统调用创建
 *      方法三： 内核空间, 通过section属性告诉内核创建
 * 
 * 以下为方式三的demo:
 */
struct bpf_map_def SEC("maps") accept_count_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 100,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} kprobe_map SEC(".maps");


/* ------------>  2. 插入、更新MAP
 *
 * @函数名称
 *      bpf_map_update_elem
 * @函数参数
 * @返回值
 *      成功：0 
 *      失败：<0
 * @作用
 * 	  Add or update the value of the entry associated to *key* in  *map* with *value*. *flags* is one of:
 * 	     BPF_NOEXIST : 仅在不存在key时, 创建元素.
 * 	     BPF_EXIST   : 仅在存在key时, 更新元素.	
 * 	     BPF_ANY     : 不存在key时, 创建元素; 存在key时, 更新元素.
 * 		
 * 	Flag value **BPF_NOEXIST** cannot be used for maps of types
 * 	**BPF_MAP_TYPE_ARRAY** or **BPF_MAP_TYPE_PERCPU_ARRAY**  (all
 * 	elements always exist), the helper would return an error. 	 
 */
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;


/* ------------>  3. 读取MAP中指定key内容
 * 
 * @函数名称
 *      bpf_map_lookup_elem
 * @函数参数
 * @作用
 * 	  Perform a lookup in *map* for an entry associated to *key*.
 * @返回值
 * 	  Map value associated to *key*, or **NULL** if no entry was found.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;


/* ------------->  4. 删除MAP指定key
 * 
 * @函数名称
 *      bpf_map_delete_elem
 * @函数参数
 * @作用
 * 	    Delete entry with *key* from *map*.
 * @返回值
 *      成功: 0
 *      失败: <0
 */
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;




/****************************************************
 *          section 2： MAP的类型                    *
 ****************************************************/

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                = 0,
	BPF_MAP_TYPE_HASH                  = 1,
	BPF_MAP_TYPE_ARRAY                 = 2,
	BPF_MAP_TYPE_PROG_ARRAY            = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
	BPF_MAP_TYPE_PERCPU_HASH           = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
	BPF_MAP_TYPE_STACK_TRACE           = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
	BPF_MAP_TYPE_LRU_HASH              = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
	BPF_MAP_TYPE_LPM_TRIE              = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
	BPF_MAP_TYPE_DEVMAP                = 14,
	BPF_MAP_TYPE_SOCKMAP               = 15,
	BPF_MAP_TYPE_CPUMAP                = 16,
	BPF_MAP_TYPE_XSKMAP                = 17,
	BPF_MAP_TYPE_SOCKHASH              = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE                 = 22,
	BPF_MAP_TYPE_STACK                 = 23,
	BPF_MAP_TYPE_SK_STORAGE            = 24,
	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
	BPF_MAP_TYPE_STRUCT_OPS            = 26,
	BPF_MAP_TYPE_RINGBUF               = 27,
	BPF_MAP_TYPE_INODE_STORAGE         = 28,
};










#endif