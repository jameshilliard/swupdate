/*
 * Author: Christian Storm
 * Copyright (C) 2017, Siemens AG
 *
 * SPDX-License-Identifier:     LGPL-2.1-or-later
 */

#ifndef _STATUS_IPC_H
#define _STATUS_IPC_H

#include <stdbool.h>
#include <swupdate_status.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRDESCSIZE	2048

extern char* SOCKET_STATUS_PATH;

/*
 * Message sent via status socket.
 * Data is sent in LE if required.
 */
struct status_msg {
	unsigned int	magic;		/* Magic Number */
	int current;
	int level;
	int error;
	unsigned int 	desclen;    	/* Len of data valid in desc */
	char		desc[PRDESCSIZE]; /* additional information about install */
};

char *get_status_socket(void);

/* Standard function to connect to status interface */
int status_ipc_connect(bool reconnect);

/*
 * In case more as an instance of SWUpdate is running, this allows to select
 * which should be taken
 */
int status_ipc_connect_with_path(const char *socketpath, bool reconnect);

/* Retrieve messages from status interface (it blocks) */
int status_ipc_receive(int *connfd, struct status_msg *msg);

#ifdef __cplusplus
}   // extern "C"
#endif

#endif
