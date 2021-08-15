/*
 * (C) Copyright 2016
 * Stefano Babic, DENX Software Engineering, sbabic@denx.de.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include "swupdate.h"
#include <handler.h>
#include "util.h"
#include "pctl.h"
#include "network_ipc.h"
#include "network_interface.h"
#include <status.h>
#include "generated/autoconf.h"

#ifdef CONFIG_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

struct status_conn {
	SIMPLEQ_ENTRY(status_conn) next;
	int sockfd;
};

SIMPLEQ_HEAD(connections, status_conn);

/*
 * Structure contains data regarding
 * current installation
 */
struct swupdate_status {
	struct status_msg msg;
	char *current_image;
	const handler *curhnd;
	struct connections conns;
	pthread_mutex_t lock;
	bool step_running;
};
static struct swupdate_status notification;

/*
 * This must be called after acquiring the mutex
 * for the status structure
 */
static void send_status_msg(void)
{
	struct status_conn *conn, *tmp;
	struct swupdate_status *nmsg = &notification;
	void *buf;
	size_t count;
	ssize_t n;

	SIMPLEQ_FOREACH_SAFE(conn, &nmsg->conns, next, tmp) {
		buf = &nmsg->msg;
		count = sizeof(nmsg->msg);
		while (count > 0) {
			n = send(conn->sockfd, buf, count, MSG_NOSIGNAL);
			if (n <= 0) {
				if (n == 0) {
					TRACE("A status client is not responding, removing it.");
				} else {
					TRACE("A status client disappeared, removing it: %s", strerror(errno));
				}
				close(conn->sockfd);
				SIMPLEQ_REMOVE(&nmsg->conns, conn,
					       	status_conn, next);
				free(conn);
				break;
			}
			count -= (size_t)n;
			buf = (char*)buf + n;
		}
	}
}

void swupdate_status_info(RECOVERY_STATUS status, int error, int level, const char *msg)
{
	struct swupdate_status *nmsg = &notification;
	pthread_mutex_lock(&nmsg->lock);
	memset(&nmsg->msg, 0, sizeof(nmsg->msg));
	if (msg) {
		strncpy(nmsg->msg.desc, msg,
				sizeof(nmsg->msg.desc) - 1);
		clean_msg(nmsg->msg.desc, '\t');
		clean_msg(nmsg->msg.desc, '\n');
		clean_msg(nmsg->msg.desc, '\r');
	}
	nmsg->msg.current = status;
	nmsg->msg.level = level;
	nmsg->msg.error = error;
	nmsg->msg.desclen = strlen(nmsg->msg.desc);
	send_status_msg();
	pthread_mutex_unlock(&nmsg->lock);
}

static void unlink_socket(void)
{
#ifdef CONFIG_SYSTEMD
	if (sd_booted() && sd_listen_fds(0) > 0) {
		/*
		 * There were socket fds handed-over by systemd,
		 * so don't delete the socket file.
		 */
		return;
	}
#endif
	unlink(get_status_socket());
}

void *status_thread (void __attribute__ ((__unused__)) *data)
{
	int listen, connfd;
	socklen_t clilen;
	struct sockaddr_un cliaddr;
	struct swupdate_status *nmsg = &notification;
	struct status_conn *conn;

	pthread_mutex_init(&nmsg->lock, NULL);
	SIMPLEQ_INIT(&nmsg->conns);

	/* Initialize and bind to UDS */
	listen = listener_create(get_status_socket(), SOCK_STREAM);
	if (listen < 0 ) {
		ERROR("Error creating IPC socket %s, exiting.", get_status_socket());
		exit(2);
	}

	if (atexit(unlink_socket) != 0) {
		TRACE("Cannot setup socket cleanup on exit, %s won't be unlinked.",
			get_status_socket());
	}

	thread_ready();
	do {
		clilen = sizeof(cliaddr);
		if ( (connfd = accept(listen, (struct sockaddr *) &cliaddr, &clilen)) < 0) {
			if (errno == EINTR)
				continue;
			else {
				TRACE("Accept returns: %s", strerror(errno));
				continue;
			}
		}

		/*
		 * Save the new connection to be handled by the status thread
		 */
		conn = (struct status_conn *)calloc(1, sizeof(*conn));
		if (!conn) {
			ERROR("Out of memory, skipping...");
			continue;
		}
		conn->sockfd = connfd;
		pthread_mutex_lock(&nmsg->lock);
		SIMPLEQ_INSERT_TAIL(&nmsg->conns, conn, next);
		pthread_mutex_unlock(&nmsg->lock);
	} while(1);
}
