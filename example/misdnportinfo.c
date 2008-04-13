#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <mISDNif.h>
#include <q931.h>

int main()
{
	int 			cnt, ret = 0, i;
	int			sk;
	struct mISDN_devinfo	devinfo;

	sk = socket(PF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (sk < 1) {
		fprintf(stdout, "could not open socket %s\n", strerror(errno));
		return 2;
	}
	ret = ioctl(sk, IMGETCOUNT, &cnt);
	if (ret) {
		fprintf(stdout, "ioctl error %s\n", strerror(errno));
		close(sk);
		return 3;
	}

	printf("Found %d devices\n",cnt);

	for (i=0; i<cnt; i++) {

		devinfo.id = i;
		ret = ioctl(sk, IMGETDEVINFO, &devinfo);
		if (ret < 0) {
			fprintf(stdout, "ioctl error %s\n", strerror(errno));
		} else  {  
			fprintf(stdout, "        id:             %d\n", devinfo.id);
			fprintf(stdout, "        Dprotocols:     %08x\n", devinfo.Dprotocols);
			fprintf(stdout, "        Bprotocols:     %08x\n", devinfo.Bprotocols);
			fprintf(stdout, "        protocol:       %d\n", devinfo.protocol);
			fprintf(stdout, "        nrbchan:        %d\n", devinfo.nrbchan);
			fprintf(stdout, "        name:           %s\n", devinfo.name);
		}
	}

	close(sk);
	return 0;
}