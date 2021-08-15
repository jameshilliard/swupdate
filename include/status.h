/*
 * (C) Copyright 2016
 * Stefano Babic, DENX Software Engineering, sbabic@denx.de.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

#ifndef _INSTALL_STATUS_H
#define _INSTALL_STATUS_H

#include <swupdate_status.h>
#include <status_ipc.h>

/*
 * Internal SWUpdate functions to drive the status
 * interface. Common status definitions for internal
 * as well as external use are defined in status_ipc.h
 */
void swupdate_status_info(RECOVERY_STATUS status, int event, int level, const char *msg);

void *status_thread (void *data);

#endif
