/*
 * Copyright (c) 2004-2013 Sergey Lyubka
 * Copyright (c) 2013-2020 Cesanta Software Limited
 * All rights reserved
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <https://www.cesanta.com/license>.
 */

#include "mongoose.h"

#define MG_EV_HTTP_MULTIPART_REQUEST 121 /* struct http_message */
#define MG_EV_HTTP_PART_BEGIN 122        /* struct mg_http_multipart_part */
#define MG_EV_HTTP_PART_DATA 123         /* struct mg_http_multipart_part */
#define MG_EV_HTTP_PART_END 124          /* struct mg_http_multipart_part */
/* struct mg_http_multipart_part */
#define MG_EV_HTTP_MULTIPART_REQUEST_END 125

/* HTTP multipart part */
struct mg_http_multipart_part {
	struct mg_str file_name;
	struct mg_str var_name;
	struct mg_str data;
	int status; /* <0 on error */
	void *user_data;
	/*
	 * User handler can indicate how much of the data was consumed
	 * by setting this variable. By default, it is assumed that all
	 * data has been consumed by the handler.
	 * If not all data was consumed, user's handler will be invoked again later
	 * with the remainder.
	 */
	size_t num_data_consumed;
};

void multipart_upload_handler(struct mg_connection *nc, int ev, void *ev_data, mg_event_handler_t fn, void *fn_data);
