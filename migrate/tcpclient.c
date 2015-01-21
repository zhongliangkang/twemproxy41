/* tcpclient.c */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>


typedef struct server_info {
	int status;
	int seg_start;
	int seg_end;
	char app[32];
	char host[16];
	uint16_t port;

} serverInfo;

int tcp_connect (char *ip, uint16_t port) {

		struct hostent *host;
		int n, sock;

		struct sockaddr_in server_addr;
		host = gethostbyname(ip);

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("Socket");
			exit(1);
		}
		port = 22222;

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port);
		server_addr.sin_addr = *((struct in_addr *) host->h_addr);
		bzero(&(server_addr.sin_zero), 8);

		if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
			return -1;
		}

		return sock;
}

int do_proxy_cmd (int sock, char *cmd, char *buf, int buflen) {
	int n;


	n = send(sock, cmd, strlen(cmd), 0);
	if (n < 0 ) {

	} else if (n == strlen(cmd)) {

	} else {

	}

	n = recv(sock, buf, buflen, 0);
	return n;
}
/* atoi from twemproxy */
int
nc_atoi(uint8_t *line, size_t n)
{
    int value;

    if (n == 0) {
        return -1;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return -1;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return -1;
    }

    return value;
}

char *
parse_server(char *line_start, char *line_end, serverInfo* server)
{
	int status, n;

    char *p, *q, *start, *tp;
    char *pname, *addr, *port, *weight, *name, *papp, *seg, *pstatus, *p_seg_start, *p_seg_end;
    uint32_t k, delimlen, pnamelen, addrlen, portlen, weightlen, namelen, pstatus_len, seg_len, app_len, seg_start_len, seg_end_len;

    char delim[] = "   :";


    p = line_start;

    start = line_start;

    addr = NULL;
    addrlen = 0;
    weight = NULL;
    weightlen = 0;
    port = NULL;
    portlen = 0;
    name = NULL;
    namelen = 0;

    delimlen = 4;

    p = line_end;
    for (k = 0; k < sizeof(delim); k++) {

        for(q=p;*q != delim[k] && q > line_start;q--);

        if (q == NULL) {
            break;
        }

        switch (k) {
        case 0:
            pstatus = q+1;
            pstatus_len = (uint32_t)(p - pstatus +1);
            p = q;
            break;

        case 1:
            seg = q + 1;
            seg_len = (uint32_t)(p - seg + 1);
            for(tp=seg + seg_len;*tp != '-';tp--);
            if(tp == NULL){
                    p_seg_start = p_seg_end = seg;
                    seg_start_len = seg_end_len = seg_len;
            }else{
                    p_seg_start = seg;
                    seg_start_len = (uint32_t)(tp - p_seg_start);
                    p_seg_end = tp+1;
                    seg_end_len = (uint32_t)(seg + seg_len - tp - 1);
            }

            break;

        case 2:
            papp = q + 1;
            app_len = (uint32_t)(p - papp + 1);
            break;


        case 3:
            port = q + 1;
            portlen = (uint32_t)(p - port + 1);
            break;

        default:
        	;
        }

        p = q - 1;
    }

    server->port = nc_atoi(port, portlen);
    server->seg_start = nc_atoi(p_seg_start, seg_start_len);
    server->seg_end = nc_atoi(p_seg_end, seg_end_len);
    server->status = nc_atoi(pstatus, pstatus_len);

    strncpy(server->app, papp, app_len);
    strncpy(server->host, line_start, (port - line_start) - 1);

    printf ("%s:%d %s %d-%d %d\n", server->host, server->port, server->app, server->seg_start, server->seg_end, server->status);


    if (k != delimlen) {
    	return 0;
    }


    return 1;
}

int parse_servers (char* buf, int buflen, serverInfo* serverList) {
	char *start, *pos, *end;
	char *line_start, *line_end;
	int idx;
	start = buf;
	pos = buf;
	end = buf + buflen;

	idx = 0;
	line_start = start;
	for(pos=start;pos<=end ; pos++ ) {
		switch (*pos) {
		case '\n':
			//printf ("%s",line_start );
			parse_server (line_start, pos-1, &serverList[idx++]);
			line_start = pos + 1;

			break;
		default:
			;
		}

	}

	return 1;
}

int main() {
	int sock, bytes_recieved, n, i;
	char send_data[1024], buf[1024];
	serverInfo serverList[100];

	for (i=0;i<100;i++) {
		serverList[i].status = -2;
	}



	sock = tcp_connect ("127.0.0.1", 22222);
	if (sock < 0 ) {
		perror ("connect");
	}
	n = do_proxy_cmd (sock, "get alpha servers", buf, sizeof(buf));
	printf ("<%s>\n", buf);
	parse_servers (buf, n, serverList);
	close(sock);

	for (i=0;i<100;i++) {
		if ( serverList[i].status == -2) {
			break;
		}
		printf ("%s:%d %s %d-%d %d\n", serverList[i].host, serverList[i].port, serverList[i].app, serverList[i].seg_start, serverList[i].seg_end, serverList[i].status);
	}


	return 0;
}
