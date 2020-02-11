/////////////////////////IOCTL interface variables//////////////////////////////
#define MAGIC 'A'
#define IOC_MAXNR 4
#define IOCTL_RESET_TIME_STAT _IO(MAGIC, 0)
#define IOCTL_RESET_PROTOCOL_STAT _IO(MAGIC, 1)
#define IOCTL_RESET_IP_STAT _IO(MAGIC, 2)
#define IOCTL_RESET_PORT_STAT _IO(MAGIC, 3)
