#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ioctl.h>
#include <asm/ioctl.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm/atomic.h>
#include "ioctl_commands.h"
#include <linux/pagemap.h> 	/* PAGE_CACHE_SIZE */
#include <linux/spinlock.h>
#include <linux/semaphore.h>

static struct semaphore sem;

#define SUCCESS 0
#define MY_MODULE_NAME "advanced_sniffer"
#define MAX_SYS_BUF_LEN 32
#define MAX_PROC_BUF_LEN 4096
#define LFS_MAGIC 0x19980122
#define TMPSIZE 20

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amir Sabzi <97.amirsabzi@gmail.com>");
MODULE_DESCRIPTION("This is a packet sniffer module that works in different mode");
MODULE_VERSION("1.0.0");



static struct inode *lfs_make_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_mode = mode;
		ret->i_blocks = 0;
		// ret->i_fop = &lfs_file_ops;
		ret->i_atime = ret->i_mtime = ret->i_ctime = current_time(ret);
	}
	return ret;
}

static spinlock_t lock;
static char FS_buffer[MAX_PROC_BUF_LEN * 10000]= "sniffing";
static int FS_buffer_ptr = 0;
static int lfs_open(struct inode *inode, struct file *filp)
{
	spin_lock(&lock);
	filp->private_data = inode->i_private;
	spin_unlock(&lock);
	return 0;
}


static ssize_t lfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	spin_lock(&lock);
	char *data = (char *) filp->private_data;
	int len;
	char tmp[MAX_PROC_BUF_LEN*10000];


	len = snprintf(tmp, MAX_PROC_BUF_LEN*10000, "%s\n", data);
	if(FS_buffer_ptr > 0)
		len = FS_buffer_ptr;
	if (*offset > len)
		return 0;
	if (count > len - *offset)
		count = len - *offset;
	if (copy_to_user(buf, tmp + *offset, count))
		return -EFAULT;
	*offset += count;
	spin_unlock(&lock);
	return count;
}

static ssize_t lfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	printk(KERN_ALERT "advanced_sniffer: You are Not allowed to write in this file\n");
	return -EINVAL;

}

static struct file_operations lfs_file_ops = {
	.open	= lfs_open,
	.read 	= lfs_read_file,
	.write  = lfs_write_file,
};

static struct dentry *lfs_create_file (struct super_block *sb,
		struct dentry *dir, const char *name,
		char *data)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
	//EEEEEEEEEEEEEEEEEEEEEEEEEE
	qname.hash_len = hashlen_string(dir, name);
	dentry = d_alloc(dir, &qname);
	if (! dentry)
		goto out;
	inode = lfs_make_inode(sb, S_IFREG | 0644);
	if (! inode)
		goto out_dput;
	inode->i_fop = &lfs_file_ops;
	inode->i_private = data;
/*
 * Put it all into the dentry cache and we're done.
 */
	d_add(dentry, inode);
	return dentry;
/*
 * Then again, maybe it didn't work.
 */
  out_dput:
	dput(dentry);
  out:
	return 0;
}
static struct dentry *lfs_create_dir (struct super_block *sb,
		struct dentry *parent, const char *name)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
		//EEEEEEEEEEEEEEEEEEEE
	qname.hash_len = hashlen_string(parent, name);
	dentry = d_alloc(parent, &qname);
	if (! dentry)
		goto out;

	inode = lfs_make_inode(sb, S_IFDIR | 0644);
	if (! inode)
		goto out_dput;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	d_add(dentry, inode);
	return dentry;

  out_dput:
	dput(dentry);
  out:
	return 0;
}

//static atomic_t counter, subcounter;
static void lfs_create_files (struct super_block *sb, struct dentry *root)
{
	struct dentry *subdir;
  printk(KERN_INFO"we wancreated directory");
	lfs_create_file(sb, root, "packet_log", FS_buffer);
  printk(KERN_INFO"we created directory");
}



/*
 * Superblock stuff.  This is all boilerplate to give the vfs something
 * that looks like a filesystem to work with.
 */

/*
 * Our superblock operations, both of which are generic kernel ops
 * that we don't have to write ourselves.
 */
static struct super_operations lfs_s_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

/*
 * "Fill" a superblock with mundane stuff.
 */
static int lfs_fill_super (struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *root_dentry;
/*
 * Basic parameters.
 */
	sb->s_blocksize = VMACACHE_SIZE;
	sb->s_blocksize_bits = VMACACHE_SIZE;
	sb->s_magic = LFS_MAGIC;
	sb->s_op = &lfs_s_ops;
/*
 * We need to conjure up an inode to represent the root directory
 * of this filesystem.  Its operations all come from libfs, so we
 * don't have to mess with actually *doing* things inside this
 * directory.
 */
	root = lfs_make_inode (sb, S_IFDIR | 0755);
	if (! root)
		goto out;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
/*
 * Get a dentry to represent the directory in core.
 */
	root_dentry = d_make_root(root);
	if (! root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;
/*
 * Make up the files which will be in this filesystem, and we're done.
 */
	lfs_create_files (sb, root_dentry);
	return 0;

  out_iput:
	iput(root);
  out:
	return -ENOMEM;
}


/*
 * Stuff to pass in when registering the filesystem.
 */
static struct dentry *lfs_get_super(struct file_system_type *fst,
		int flags, const char *devname, void *data)
{
	return mount_bdev(fst, flags, devname, data, lfs_fill_super);
}

static struct file_system_type lfs_type = {
	.owner 		= THIS_MODULE,
	.name		= "lwnfs",
	.mount		= lfs_get_super,
	.kill_sb	= kill_litter_super,
};


















/*

  in this module we can choose the interface  that we want to sniffing packets
  comes through that and also we can set specific protocols we want to sniff
  their packets. so for this features we set a sys interface.

*/

//---------------------sysfs interface initial variables  --------------------//
static char* list_of_interfaces[5] = {"lo\n","enp3s0\n","wlp2s0\n","virbr0\n","virbr0-nic\n"};
//static char* list_of_ports = {"FTP:20 [0], SSH:22 [1], Telnet:23 [2], smtp:25 [3] , *SSL:443 [4], DNS:53 [5], "HTTP", "other"};
static struct kobject *our_kobj;
static char sys_interface_buffer[MAX_SYS_BUF_LEN] = "wlp2s0\n";
static char sys_port_buffer[MAX_SYS_BUF_LEN],global_interface_name[MAX_SYS_BUF_LEN];
static long sys_port_num = 0;



//------------------start of sysfs interface functions sectoin---------------//
static long convert_port_num(char* port_num){
  long temp;
  kstrtol(port_num, 10, &temp);
  return temp;
}

static int valid_interface(char* interface_name){
  int len = sizeof(list_of_interfaces)/sizeof(list_of_interfaces[0]);
  int i;
  for (i = 0; i < len ; i++) {
    if(strcmp(interface_name,list_of_interfaces[i]) == 0)
      return 1 ;
    }
  return 0 ;
}



static int valid_port(char* port_num){
  if(convert_port_num(port_num) > 65535 || convert_port_num(port_num) < 1)
    return 0;
  return 1 ;
}


static ssize_t sysfs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	printk(KERN_INFO "advanced_sniffer: Show Function, %s Attribute,  Process \"%s:%i\"\n",  attr->attr.name, current->comm, current->pid);
	if(strcmp(attr->attr.name, "sys_interface") == 0)
		return sprintf(buf, "%s", sys_interface_buffer);
	else if (strcmp(attr->attr.name, "sys_port") == 0)
		return sprintf(buf, "%s", sys_port_buffer);
	else
		printk(KERN_INFO  "advanced_sniffer: I don't know what you are doing, but it seems you are not doing it right!\n");
	return NULL;
}


static ssize_t sysfs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	printk(KERN_INFO "advanced_sniffer: Clock Store Function, %s Attribute,  Process \"%s:%i\"\n",  attr->attr.name, current->comm, current->pid);

  if(strcmp(attr->attr.name, "sys_interface") == 0){
      if(valid_interface(buf)){
        sprintf(sys_interface_buffer,"%s",buf);
      }else{
        printk(KERN_ALERT "advanced_sniffer: you should enter a valid interface name; to get list of interfaces use command:  $ ip link show ");}
  }else if (strcmp(attr->attr.name, "sys_port") == 0){
      if(valid_port(buf)){
        sprintf(sys_port_buffer,"%s",buf);
        sys_port_num = convert_port_num(sys_port_buffer);
      }else{
        printk(KERN_ALERT "advanced_sniffer: you should enter a valid port number between 1 and 65535 ");}
	}else
		printk(KERN_ALERT "advanced_sniffer: I don't know what you are doing, but it seems you are not permitted!\n");
	return count;
}


static struct kobj_attribute sys_interface_attribute = __ATTR(sys_interface, 0664, sysfs_show, sysfs_store);
static struct kobj_attribute sys_port_attribute = __ATTR(sys_port, 0664, sysfs_show, sysfs_store);

static struct attribute *attrs[] = {
	&sys_interface_attribute.attr,
	&sys_port_attribute.attr,
	NULL,
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};
//-----------------------proc interface initial variables ---------------------//
static struct proc_dir_entry* protocol_log_file;
//static struct proc_dir_entry* port_log;
static struct proc_dir_entry* srcAddr_log_file;
static struct proc_dir_entry* dstPort_log_file;
static struct proc_dir_entry* time_log_file;
static struct proc_dir_entry* sniff_log_file;

static char* protocols[6] = {"UDP","TCP","IP","ICMP","L2TP","OSPF"};
static int protocol_counter[6] = {0};
static char GENERAL_BUFFER[1000*4096];
static int GENERAL_BUFFER_ptr = 0;
static int src_addrs[1000] = {-1};
static int   src_addrs_counter[1000] = {0};
//unsigned char ip_string[4];

static int dst_ports[1000] = {-1};
static int   dst_ports_counter[1000] = {0};

long packet_counter = 0;
long time_sum = 0;
int min_time = INT_MAX;
int max_time = INT_MIN;
int avg_time = 0;

//------------------------start of ioctl interface functions------------------//
void set_array(int* array,int size,int element){
  int i;
  for (i = 0; i < size; i++) {
    array[i]  = element;
  }
}
static long proc_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
  //static int err = 0;
  printk(KERN_INFO "advanced_sniffer: IOCTL Function, Process \"%s:%i\"\n", current->comm, current->pid);
	printk(KERN_INFO "advanced_sniffer: IOCTL Command, %d\n", cmd);
  if(capable(CAP_NET_RAW))
		printk(KERN_INFO "advanced_sniffer: Caller is Capable\n");
	else
	{
		printk(KERN_INFO "advanced_sniffer: Caller is not Capable\n");
		return -EPERM;
	}
  if(_IOC_TYPE(cmd) != MAGIC || _IOC_NR(cmd) > IOC_MAXNR)
		return -ENOTTY;
  switch(cmd){
		case IOCTL_RESET_TIME_STAT:
      packet_counter = 0;
      time_sum = 0;
      min_time = INT_MAX;
      max_time = INT_MIN;
      avg_time = 0;
			break;
		case IOCTL_RESET_PROTOCOL_STAT:
			//protocol_counter[6] = {0};
      set_array(protocol_counter,6,0);
			break;
		case IOCTL_RESET_IP_STAT:
      //src_addrs[1000] = {-1};
      //src_addrs_counter[1000] = {0};
      set_array(src_addrs,1000,-1);
      set_array(src_addrs_counter,1000,0);
			break;
    case IOCTL_RESET_PORT_STAT:
      //dst_ports[1000] = {-1};
      //dst_ports_counter[1000] = {0};
      set_array(dst_ports,1000,-1);
      set_array(dst_ports_counter,1000,0);
			break;
    default:
			printk(KERN_ALERT "advanced_sniffer: Invalid IOCTL Command!\n");
			return -ENOTTY;
    }
    return SUCCESS;
}
//-------------------start of procs interface functions sectoin---------------//
void change_address_to_string(unsigned int addr,char * ip_string){
  int i;
	for(i=0; i<4; i++)
		ip_string[i] = (addr >> i*8) & 0xFF;
}

static int proc_protocol_show(struct seq_file *m, void *v){
	printk(KERN_EMERG "advanced_sniffer: you entered the show function and next lines are log\n");
	seq_printf(m, "|   PROTOCOL    |   PACKET#   |\n");
  seq_printf(m, "|---------------|-------------|\n");
  seq_printf(m, "|      IP       |     %d      \n",protocol_counter[0]);
  seq_printf(m, "|      UDP      |     %d      \n",protocol_counter[1]);
  seq_printf(m, "|      TCP      |     %d      \n",protocol_counter[2]);
  seq_printf(m, "|      ICMP     |     %d      \n",protocol_counter[3]);
  seq_printf(m, "|      L2TP     |     %d      \n",protocol_counter[4]);
  seq_printf(m, "|      OSPF     |     %d      \n",protocol_counter[5]);
	return SUCCESS;
}
static int proc_protocol_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "advanced_sniffer: Proc Open Function, Process \"%s:%i\"\n", current->comm, current->pid);
	return single_open(file, proc_protocol_show, NULL);
}
static const struct file_operations protocol_ops = {
	.open = proc_protocol_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
  .unlocked_ioctl = proc_ioctl,
};

static void get_top10_index(int* in_array,int size,int* out_array){
  int i,j;
  int temp_array[size];
  for (i = 0; i < size; i++) {
    temp_array[i] = in_array[i];
  }

  for (i = 0; i < 10; i++) {
    int temp_index = 0;
    for (j = 0; j < size; j++) {
      if(in_array[j] > temp_array[temp_index])
        temp_index = j;
    }
    out_array[i] = temp_index;
    temp_array[temp_index]  = -1;
  }
}

static int proc_saddr_show(struct seq_file *m, void *v){
	printk(KERN_EMERG "advanced_sniffer: you entered the show function and next lines are log\n");
  seq_printf(m, "|----------------------------------------------------|\n");
  seq_printf(m, "|********************TOP 10 soucre IPs***************|\n");
  seq_printf(m, "|----------------------------------------------------|\n");
	seq_printf(m, "|     rank      |       IP address     |   PACKET#   |\n");
  int  top10_IP_index[10];
  get_top10_index(src_addrs_counter,1000,top10_IP_index);
  int i;

  //printk(KERN_INFO "IPADDRESSFILTER: %s packet SRC:(%d.%d.%d.%d) --> DST: (%d.%d.%d.%d)\n", ip_header->protocol == IPPROTO_TCP ? "TCP" : "UDP", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
  for (i = 0; i < 10; i++) {
    unsigned char saddr[4];
    change_address_to_string((unsigned int) src_addrs[top10_IP_index[i]],saddr);
    seq_printf(m, "|      %d        |    %03d.%03d.%03d.%03d   |     %-7d %s   \n",i, saddr[0], saddr[1], saddr[2], saddr[3],src_addrs_counter[top10_IP_index[i]],"|");
  }
	return SUCCESS;
}
static int proc_saddr_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "advanced_sniffer: Proc Open Function, Process \"%s:%i\"\n", current->comm, current->pid);
	return single_open(file, proc_saddr_show, NULL);
}

static const struct file_operations saddr_ops = {
	.open = proc_saddr_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};




static int proc_dstport_show(struct seq_file *m, void *v){
	printk(KERN_EMERG "advanced_sniffer: you entered the show function and next lines are log\n");
  seq_printf(m, "|-------------------------------------------------|\n");
  seq_printf(m, "|**************TOP 10 destination PORT************|\n");
  seq_printf(m, "|-------------------------------------------------|\n");
	seq_printf(m, "|     rank      |    PORT address   |   PACKET#   |\n");
  int  top10_PORT_index[10];
  get_top10_index(dst_ports_counter,1000,top10_PORT_index);
  int i;
  //printk(KERN_INFO "IPADDRESSFILTER: %s packet SRC:(%d.%d.%d.%d) --> DST: (%d.%d.%d.%d)\n", ip_header->protocol == IPPROTO_TCP ? "TCP" : "UDP", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
  for (i = 0; i < 10; i++){
    seq_printf(m, "|      %d        |       %-10d  |     %-6d  %s \n",i,dst_ports[top10_PORT_index[i]],dst_ports_counter[top10_PORT_index[i]],"|");
  }
	return SUCCESS;
}

static int proc_dstport_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "advanced_sniffer: Proc Open Function, Process \"%s:%i\"\n", current->comm, current->pid);
	return single_open(file, proc_dstport_show, NULL);
}

static const struct file_operations dstport_ops = {
	.open = proc_dstport_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};



static int proc_time_show(struct seq_file *m, void *v){
  //spin_lock(&lock);
  //seq_printf(m,"advanced_sniffer:  packet TCP counter:%d\n",x);
	printk(KERN_EMERG "advanced_sniffer: you entered the show function and next lines are log\n");
  seq_printf(m, "|-----------------------------------------------------------|\n");
  seq_printf(m, "|*************** Time statisitcs of pipline ****************|\n");
  seq_printf(m, "|-----------------------------------------------------------|\n");
	seq_printf(m, "|  Minimum Time of packet Process  =   %d(micro secend)   \n",min_time);
  seq_printf(m, "|  Maximum Time of packet Process  =   %d(micro secend)   \n",max_time);
  seq_printf(m, "|  Average Time of packet Process  =   %d(micro secend)   \n",avg_time);
  //spin_unlock(&lock);
	return SUCCESS;
}

static int proc_time_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "advanced_sniffer: Proc Open Function, Process \"%s:%i\"\n", current->comm, current->pid);
	return single_open(file, proc_time_show, NULL);
}

static const struct file_operations time_ops = {
	.open = proc_time_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};



static int proc_sniff_show(struct seq_file *m, void *v){
  spin_lock(&lock);
	printk(KERN_ALERT "advanced_sniffer: Proc Open Function%d ", FS_buffer_ptr);
  FS_buffer[FS_buffer_ptr] = 0;
  seq_printf(m,"%s\n",FS_buffer);
  spin_unlock(&lock);
	return SUCCESS;
}

static int proc_sniff_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "advanced_sniffer: Proc Open Function, Process \"%s:%i\"\n", current->comm, current->pid);
	return single_open(file, proc_sniff_show, NULL);
}

static const struct file_operations sniff_ops = {
	.open = proc_sniff_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};



//--------------------sniffer netfilter initial variables --------------------//
struct net *netns;
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;

static struct file *filp = NULL;
//static unsigned int file_size = 0;
static loff_t file_offset = 0;
static int file_counter = 0;
//static spinlock_t lock;

//------------------start of sniffer netfilter functions sectoin---------------//
static void standardize_interface_name(char* buf){
  sprintf(global_interface_name,"%s",buf);
  global_interface_name[strlen(global_interface_name)-1] = 0;
}

struct file *file_open(const char *path, int flags, int rights)
{
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file)
{
    filp_close(file, NULL);
}

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = kernel_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}


static int sniffer_counter = 0;
//static int PREVIUOS_BUFFER_ptr = 0;
unsigned int sniff_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
  standardize_interface_name(sys_interface_buffer);
	if(strcmp(state->in->name, global_interface_name) == 0){
    ip_header = (struct iphdr *) skb_network_header(skb);
    if(sys_port_num == 0){
      if(ip_header){
          spin_lock(&lock);
					sniffer_counter ++ ;
					int i=0;
          while(i<(skb->tail)){
            if((char *)((skb->data)[i]) != 0){
							sprintf((char*)(GENERAL_BUFFER + GENERAL_BUFFER_ptr),"%02X", (char *)((skb->data)[i]));
	            GENERAL_BUFFER_ptr += 2;
						}
            i++;
          }
					unsigned char saddr[4];
					unsigned char daddr[4];
					//printk(KERN_INFO "IPADDRESSFILTER: %s packet SRC:(%d.%d.%d.%d) --> DST: (%d.%d.%d.%d)\n", ip_header->protocol == IPPROTO_TCP ? "TCP" : "UDP", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
					change_address_to_string((unsigned int) ip_header->saddr,saddr);
					change_address_to_string((unsigned int) ip_header->saddr,daddr);
					int add = sprintf((char*)(GENERAL_BUFFER + GENERAL_BUFFER_ptr),"\n\n\n%s packet SRC:(%d.%d.%d.%d) --> DST: (%d.%d.%d.%d)\n", ip_header->protocol == IPPROTO_TCP ? "TCP" : "UDP",saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3]);
					GENERAL_BUFFER_ptr = GENERAL_BUFFER_ptr + add;





					i = 0;
					printk(KERN_ALERT "counter %d",sniffer_counter);
					if(sniffer_counter > 20){
						printk(KERN_ALERT "counter %d",sniffer_counter);
						sniffer_counter = 0;
						while(i < GENERAL_BUFFER_ptr - FS_buffer_ptr){
							FS_buffer[i +  FS_buffer_ptr] = GENERAL_BUFFER[i +  FS_buffer_ptr];
							i++;
						}
						FS_buffer_ptr = GENERAL_BUFFER_ptr;
					}
          spin_unlock(&lock);
        }
      }else{
    	//This will filter any TCP requsts for the specified port
    	if(ip_header && ip_header->protocol == IPPROTO_TCP){
    		tcp_header = (struct tcphdr *) skb_transport_header(skb);
    		if(tcp_header && (ntohs(tcp_header->dest) == (unsigned short) sys_port_num || ntohs(tcp_header->source) == (unsigned short) sys_port_num)){
          spin_lock(&lock);
          int i=0;
          while(i<(skb->tail)){
            if((char *)((skb->data)[i]) != 0){
            GENERAL_BUFFER[GENERAL_BUFFER_ptr]=(char *)((skb->data)[i]);
            GENERAL_BUFFER_ptr++;}
            i++;
          }
          spin_unlock(&lock);
    	   }
      }
      if(ip_header && ip_header->protocol == IPPROTO_UDP){
        udp_header = (struct udphdr *) skb_transport_header(skb);
        if(udp_header && (ntohs(udp_header-> dest) == (unsigned short) sys_port_num || ntohs(udp_header-> source) == (unsigned short) sys_port_num)){
          spin_lock(&lock);
          int i=0;
          while(i<(skb->tail)){
            if((char *)((skb->data)[i]) != 0)
            GENERAL_BUFFER[GENERAL_BUFFER_ptr]=(char *)((skb->data)[i]);
            else
            GENERAL_BUFFER[GENERAL_BUFFER_ptr] = '0';
            GENERAL_BUFFER_ptr++;
            i++;
          }
          spin_unlock(&lock);
        }
      }
    }

  }
  return NF_ACCEPT;
}


atomic_t u = ATOMIC_INIT(0);
unsigned int protocol_stat_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

    //-----------------------statistics for protocols-------------------------//
    //static char* protocols[6] = {"IP","UDP","TCP","ICMP","L2TP","OSPF"};
    ip_header = (struct iphdr *) skb_network_header(skb);
    if(ip_header){
      protocol_counter[0] ++;
      if(ip_header->protocol == IPPROTO_UDP)
        protocol_counter[1] ++;
      else if(ip_header->protocol == IPPROTO_TCP)
        protocol_counter[2] ++;
      else if(ip_header->protocol == IPPROTO_ICMP)
        protocol_counter[3] ++;
      else if(ip_header->protocol == 115)
        protocol_counter[4] ++;
      else if(ip_header->protocol == 89)
        protocol_counter[5]++;
    }
    return NF_ACCEPT;
}

static int in_list(int* array,int element,int size){
  int j;
  for(j=0;j<size;j++){
      if(array[j] == element){
        return j ;
      }
  }
  return -1;
}

static int min_index(int * array,int size){
  int j;
  int k = 0;
  for(j=0;j<size;j++){
      if(array[j]<array[k]){
        k = j;
      }
  }
  return k;
}
unsigned int ip_stat_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

    //-----------------------statistics for source addr-------------------------//
    ip_header = (struct iphdr *) skb_network_header(skb);
    if(ip_header){
      unsigned int temp_saddr = (unsigned int) ip_header->saddr ;
      int list_index = in_list(src_addrs,temp_saddr,1000);
      if(list_index != -1){
          src_addrs_counter[list_index] ++ ;
      }else{
          int flag = 1;
          int i;
          for ( i = 0; i < 1000; i++) {
            if(src_addrs[i] < 0){
              src_addrs[i] = temp_saddr;
              src_addrs_counter[i] ++;
              flag = 0;
              break;
            }
          }
          if(flag){
            src_addrs[min_index(src_addrs_counter,1000)] = temp_saddr;
            src_addrs_counter[min_index(src_addrs_counter,1000)] = 1;
          }
      }
    }
		return NF_ACCEPT;
}

unsigned int port_stat_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

    //-----------------------statistics for destination port-------------------------//

    	ip_header = (struct iphdr *) skb_network_header(skb);
    	if(ip_header && ip_header->protocol == IPPROTO_TCP){
    		tcp_header = (struct tcphdr *) skb_transport_header(skb);
          if(tcp_header){
            unsigned int temp_port = ntohs(tcp_header->dest);
            int list_index = in_list(dst_ports,temp_port,1000);
            if(list_index != -1){
                dst_ports_counter[list_index] ++ ;
            }else{
                int flag = 1;
                int i;
                for ( i = 0; i < 1000; i++) {
                  if(dst_ports[i] < 0){
                    dst_ports[i] = temp_port;
                    dst_ports_counter[i] ++;
                    flag = 0;
                    break;
                  }
                }
                if(flag){
                  dst_ports[min_index(dst_ports_counter,1000)] = temp_port;
                  dst_ports_counter[min_index(dst_ports_counter,1000)] = 1;
                }
            }
    		  }
    	}
    	if(ip_header && ip_header->protocol == IPPROTO_UDP){
    		udp_header = (struct udphdr *) skb_transport_header(skb);
    		//if(udp_header && (ntohs(udp_header->dest) == (unsigned short) hook_port || ntohs(udp_header->source) == (unsigned short) hook_port)){
        if(udp_header){
          unsigned int temp_port = ntohs(udp_header->dest);
          int list_index = in_list(dst_ports,temp_port,1000);
          if(list_index != -1){
              dst_ports_counter[list_index] ++ ;
          }else{
              int flag = 1;
              int i;
              for ( i = 0; i < 1000; i++) {
                if(dst_ports[i] < 0){
                  dst_ports[i] = temp_port;
                  dst_ports_counter[i] ++;
                  flag = 0;
                  break;
                }
              }
              if(flag){
                dst_ports[min_index(dst_ports_counter,1000)] = temp_port;
                dst_ports_counter[min_index(dst_ports_counter,1000)] = 1;
              }
          }
        }
    	}

    	return NF_ACCEPT;
    }

unsigned int time_stat_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
        //-----------------------time for source addr-------------------------//
        //printk(KERN_ALERT "advanced_sniffer:  packet SRC:%d --> DST:%d\n", ntohs(ip_header->saddr), ntohs(ip_header->daddr));
      struct timeval time;
      skb_get_timestamp (	skb, &time);
      int micro_sec = (time.tv_usec);
      time_sum = time_sum + micro_sec ;
      if(micro_sec < min_time)
        min_time = micro_sec ;
      if(micro_sec > max_time)
        max_time = micro_sec;
      packet_counter ++ ;
      avg_time = time_sum / packet_counter ;
      //printk(KERN_ALERT "advanced_sniffer:  time:%d\n",avg_time);
    	return NF_ACCEPT;
}

//Netfilter hook_operations would be the key to add this functionality to he Kernel
static struct nf_hook_ops sniff_nfho ={
	.hook = sniff_hook_func,
	.hooknum = 1,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops protocol_stat_nfho ={
	.hook = protocol_stat_hook_func,
	.hooknum = 1,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST+1,
};

static struct nf_hook_ops ip_stat_nfho ={
	.hook = ip_stat_hook_func,
	.hooknum = 1,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST+2,
};

static struct nf_hook_ops port_stat_nfho ={
	.hook = port_stat_hook_func,
	.hooknum = 1,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST+3,
};

static struct nf_hook_ops time_stat_nfho ={
	.hook = time_stat_hook_func,
	.hooknum = 1,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST+4,
};






static int __init advanced_sniffer_init(void){
  //--------------------- sysfs interface Initialization  --------------------//
  register_filesystem(&lfs_type);
  printk(KERN_INFO "advanced_sniffer:File system have been Registered.\n");
	int return_value ;
	printk(KERN_INFO "advanced_sniffer: Initialization\n");
	our_kobj = kobject_create_and_add(MY_MODULE_NAME, NULL);
	if (!our_kobj){
		printk(KERN_ALERT "advanced_sniffer: KOBJECT Registration Failure.\n");
		return -ENOMEM;
	}
	return_value = sysfs_create_group(our_kobj, &attr_group);
	if (return_value){
		printk(KERN_ALERT "advanced_sniffer: Creating attribute groupe has been failed.\n");
		kobject_put(our_kobj);
	}
  //--------------------- procfs interface Initialization  --------------------//
  protocol_log_file = proc_create("protocol_stat", 0644 , NULL, &protocol_ops);
  if(!protocol_log_file){
    printk(KERN_ALERT "advanced_sniffer: Registration Failure.\n");
    return -ENOMEM;
  }printk(KERN_INFO "advanced_sniffer:File system have been Registered.\n");
  srcAddr_log_file = proc_create("srcAddr_stat", 0644 , NULL, &saddr_ops);
  if(!srcAddr_log_file){
    printk(KERN_ALERT "advanced_sniffer: Registration Failure.\n");
    return -ENOMEM;
  }
  dstPort_log_file = proc_create("dstPort_stat", 0644 , NULL, &dstport_ops);
  if(!dstPort_log_file){
    printk(KERN_ALERT "advanced_sniffer: Registration Failure.\n");
    return -ENOMEM;
  }
  time_log_file = proc_create("time_stat", 0644 , NULL, &time_ops);
  if(!time_log_file){
    printk(KERN_ALERT "advanced_sniffer: Registration Failure.\n");
    return -ENOMEM;
  }
  sniff_log_file = proc_create("sniff_log", 0644 , NULL, &sniff_ops);
  if(!sniff_log_file){
    printk(KERN_ALERT "advanced_sniffer: Registration Failure.\n");
    return -ENOMEM;
  }
  //-------------------- ---netfilter Initialization----------------------------//
  netns = get_net(&init_net);
  nf_register_net_hook(netns, &sniff_nfho);
  nf_register_net_hook(netns, &protocol_stat_nfho);
  nf_register_net_hook(netns, &ip_stat_nfho);
  nf_register_net_hook(netns, &port_stat_nfho);
  nf_register_net_hook(netns, &time_stat_nfho);
  // enable setting time stamps
  net_enable_timestamp();
  printk(KERN_INFO "advanced_sniffer: Netfilter-Hooks have been Registered.\n");
  //printk(KERN_INFO "advanced_sniffer: file in tmp is created.\n");
  spin_lock_init(&lock);
	return SUCCESS;
}

static void __exit advanced_sniffer_exit(void){
  //--------------------- sysfs interface clean up  --------------------//
	printk(KERN_INFO "advanced_sniffer: Cleanup Module\"%s:%i\"\n", current->comm, current->pid);
	kobject_put(our_kobj);
	printk(KERN_INFO "advanced_sniffer: /sys/kernel/%s and all its attributes has been removed.\n", MY_MODULE_NAME);

  remove_proc_entry("protocol_stat", NULL);
  remove_proc_entry("srcAddr_stat", NULL);
  remove_proc_entry("dstPort_stat", NULL);
  remove_proc_entry("time_stat", NULL);
  remove_proc_entry("sniff_log", NULL);
  printk(KERN_INFO "advanced_sniffer: /proc/%s has been removed.\n", MY_MODULE_NAME);

  nf_unregister_net_hook(netns, &sniff_nfho);
  nf_unregister_net_hook(netns, &protocol_stat_nfho);
  nf_unregister_net_hook(netns, &ip_stat_nfho);
  nf_unregister_net_hook(netns, &port_stat_nfho);
  nf_unregister_net_hook(netns, &time_stat_nfho);
	//nf_unregister_net_hook(netns, &out_nfho);
	printk(KERN_INFO "advanced_sniffer: Netfilter-Hooks have been UN-Registered.\n");
	printk(KERN_INFO "advanced_sniffer:Close the file\n", MY_MODULE_NAME);
  unregister_filesystem(&lfs_type);
  printk(KERN_INFO "advanced_sniffer:File system have been unRegistered.\n");
}

module_init(advanced_sniffer_init);
module_exit(advanced_sniffer_exit);
