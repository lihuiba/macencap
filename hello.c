#include<linux/module.h>
#include<linux/init.h>

int __init hello_init (void)
{
    printk("HelloWorld\n");
    return 0;
}

void __exit hello_exit(void)
{
    printk("GoodBye\n");
}

MODULE_AUTHOR("wanghaifeng <haifengwang1987@gmail.com>");
MODULE_DESCRIPTION("hello");
MODULE_LICENSE("GPL");
