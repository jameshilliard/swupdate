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

#include "mongoose_multipart.h"

enum mg_http_multipart_stream_state {
	MPS_BEGIN,
	MPS_WAITING_FOR_BOUNDARY,
	MPS_WAITING_FOR_CHUNK,
	MPS_GOT_BOUNDARY,
	MPS_FINALIZE,
	MPS_FINISHED
};

struct mg_http_multipart_stream {
	struct mg_http_part part;
	struct mg_str boundary;
	void *user_data;
	enum mg_http_multipart_stream_state state;
	int processing_part;
	int data_avail;
	size_t len;
};

static void mg_http_free_proto_data_mp_stream(
		struct mg_http_multipart_stream *mp) {
	free((void *) mp->boundary.ptr);
	free((void *) mp->part.name.ptr);
	free((void *) mp->part.filename.ptr);
	memset(mp, 0, sizeof(*mp));
}

static void mg_http_multipart_begin(struct mg_connection *nc,
									struct mg_http_message *hm) {
	struct mg_http_multipart_stream *mp_stream = nc->pfn_data;
	struct mg_str *ct;
	struct mg_iobuf *io = &nc->recv;

	struct mg_str boundary;

	ct = mg_http_get_header(hm, "Content-Type");
	if (ct == NULL) {
		/* We need more data - or it isn't multipart mesage */
		return;
	}

	/* Content-type should start with "multipart" */
	if (ct->len < 9 || strncmp(ct->ptr, "multipart", 9) != 0) {
		return;
	}

	boundary = mg_http_get_header_var(*ct, mg_str_n("boundary", 8));
	if (boundary.len == 0) {
		/*
		 * Content type is multipart, but there is no boundary,
		 * probably malformed request
		 */
		nc->is_closing = 1;
		LOG(LL_DEBUG,("invalid request"));
		return;
	}

	/* If we reach this place - that is multipart request */

	if (mp_stream->boundary.len != 0) {
		/*
		 * Another streaming request was in progress,
		 * looks like protocol error
		 */
		nc->is_closing = 1;
	} else {
		mp_stream->state = MPS_BEGIN;
		mp_stream->boundary = mg_strdup(boundary);
		mp_stream->part.name.ptr = mp_stream->part.filename.ptr = NULL;
		mp_stream->part.name.len = mp_stream->part.filename.len = 0;
		mp_stream->len = hm->body.len;

		mg_call(nc, MG_EV_HTTP_MULTIPART_REQUEST, hm);

		mg_iobuf_del(io, 0, hm->head.len + 2);
	}
}

#define CONTENT_DISPOSITION "Content-Disposition: "

static size_t mg_http_multipart_call_handler(struct mg_connection *c, int ev,
											 const char *data,
											 size_t data_len) {
	struct mg_http_multipart mp;
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;
	memset(&mp, 0, sizeof(mp));

	mp.part.name = mp_stream->part.name;
	mp.part.filename = mp_stream->part.filename;
	mp.user_data = mp_stream->user_data;
	mp.part.body.ptr = data;
	mp.part.body.len = data_len;
	mp.num_data_consumed = data_len;
	mp.len = mp_stream->len;
	mg_call(c, ev, &mp);
	mp_stream->user_data = mp.user_data;
	mp_stream->data_avail = (mp.num_data_consumed != data_len);
	return mp.num_data_consumed;
}

static int mg_http_multipart_finalize(struct mg_connection *c) {
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;

	mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
	free((void *) mp_stream->part.filename.ptr);
	mp_stream->part.filename.ptr = NULL;
	free((void *) mp_stream->part.name.ptr);
	mp_stream->part.name.ptr = NULL;
	mg_http_multipart_call_handler(c, MG_EV_HTTP_MULTIPART_REQUEST_END, NULL, 0);
	mg_http_free_proto_data_mp_stream(mp_stream);
	mp_stream->state = MPS_FINISHED;

	return 1;
}

static int mg_http_multipart_wait_for_boundary(struct mg_connection *c) {
	const char *boundary;
	struct mg_iobuf *io = &c->recv;
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;

	if (mp_stream->boundary.len == 0) {
		mp_stream->state = MPS_FINALIZE;
		LOG(LL_DEBUG,("Invalid request: boundary not initialized"));
		return 0;
	}

	if ((int) io->len < mp_stream->boundary.len + 2) {
		return 0;
	}

	boundary = mg_strstr(mg_str_n((char *) io->buf, io->len), mp_stream->boundary);
	if (boundary != NULL) {
		const char *boundary_end = (boundary + mp_stream->boundary.len);
		if (io->len - (boundary_end - (char *) io->buf) < 4) {
			return 0;
		}
		if (strncmp(boundary_end, "--\r\n", 4) == 0) {
			mp_stream->state = MPS_FINALIZE;
			mg_iobuf_del(io, 0, (boundary_end - (char *) io->buf) + 4);
		} else {
			mp_stream->state = MPS_GOT_BOUNDARY;
		}
	} else {
		return 0;
	}

	return 1;
}

static size_t mg_get_line_len(const char *buf, size_t buf_len) {
	size_t len = 0;
	while (len < buf_len && buf[len] != '\n') len++;
	return len == buf_len ? 0 : len + 1;
}

static int mg_http_multipart_process_boundary(struct mg_connection *c) {
	int data_size;
	const char *boundary, *block_begin;
	struct mg_iobuf *io = &c->recv;
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;
	int line_len;
	boundary = mg_strstr(mg_str_n((char *) io->buf, io->len), mp_stream->boundary);
	block_begin = boundary + mp_stream->boundary.len + 2;
	data_size = io->len - (block_begin - (char *) io->buf);
	mp_stream->len -= ((2 * mp_stream->boundary.len) + 6);

	while (data_size > 0 &&
		   (line_len = mg_get_line_len(block_begin, data_size)) != 0) {
		mp_stream->len -= (line_len + 2);
		if (line_len > (int) sizeof(CONTENT_DISPOSITION) &&
			mg_ncasecmp(block_begin, CONTENT_DISPOSITION,
						sizeof(CONTENT_DISPOSITION) - 1) == 0) {
			struct mg_str header;

			header.ptr = block_begin + sizeof(CONTENT_DISPOSITION) - 1;
			header.len = line_len - sizeof(CONTENT_DISPOSITION) - 1;

			mp_stream->part.name = mg_strdup(mg_http_get_header_var(header, mg_str_n("name", 4)));
			mp_stream->part.filename = mg_strdup(mg_http_get_header_var(header, mg_str_n("filename", 8)));

			block_begin += line_len;
			data_size -= line_len;

			continue;
		}

		if (line_len == 2 && mg_ncasecmp(block_begin, "\r\n", 2) == 0) {
			if (mp_stream->processing_part != 0) {
				mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
			}

			mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_BEGIN, NULL, 0);
			mp_stream->state = MPS_WAITING_FOR_CHUNK;
			mp_stream->processing_part++;

			mg_iobuf_del(io, 0, block_begin - (char *) io->buf + 2);
			return 1;
		}

		block_begin += line_len;
	}

	mp_stream->state = MPS_WAITING_FOR_BOUNDARY;

	return 0;
}

static int mg_http_multipart_continue_wait_for_chunk(struct mg_connection *c) {
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;
	struct mg_iobuf *io = &c->recv;

	const char *boundary;
	if ((int) io->len < mp_stream->boundary.len + 6 /* \r\n, --, -- */) {
		return 0;
	}

	boundary = mg_strstr(mg_str_n((char *) io->buf, io->len), mp_stream->boundary);
	if (boundary == NULL) {
		int data_len = io->len - (mp_stream->boundary.len + 6);
		if (data_len > 0) {
			size_t consumed = mg_http_multipart_call_handler(
					c, MG_EV_HTTP_PART_DATA, (char *) io->buf, (size_t) data_len);
			mg_iobuf_del(io, 0, consumed);
		}
		return 0;
	} else if (boundary != NULL) {
		size_t data_len = io->len - (mp_stream->boundary.len + 8);
		size_t consumed = mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_DATA,
														 (char *) io->buf, data_len);
		mg_iobuf_del(io, 0, consumed);
		if (consumed == data_len) {
			mg_iobuf_del(io, 0, 4);
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

static void mg_http_multipart_continue(struct mg_connection *c) {
	struct mg_http_multipart_stream *mp_stream = c->pfn_data;
	while (1) {
		switch (mp_stream->state) {
			case MPS_BEGIN: {
				mp_stream->state = MPS_WAITING_FOR_BOUNDARY;
				break;
			}
			case MPS_WAITING_FOR_BOUNDARY: {
				if (mg_http_multipart_wait_for_boundary(c) == 0) {
					return;
				}
				break;
			}
			case MPS_GOT_BOUNDARY: {
				if (mg_http_multipart_process_boundary(c) == 0) {
					return;
				}
				break;
			}
			case MPS_WAITING_FOR_CHUNK: {
				if (mg_http_multipart_continue_wait_for_chunk(c) == 0) {
					return;
				}
				break;
			}
			case MPS_FINALIZE: {
				if (mg_http_multipart_finalize(c) == 0) {
					return;
				}
				break;
			}
			case MPS_FINISHED: {
				return;
			}
		}
	}
}

void multipart_upload_handler(struct mg_connection *nc, int ev, void *ev_data, mg_event_handler_t fn,
		void __attribute__ ((__unused__)) *fn_data)
{
	struct mg_http_message *hm = (struct mg_http_message *) ev_data;
	struct mg_http_multipart_stream *mp_stream = nc->pfn_data;
	struct mg_str *s;

	if (mp_stream != NULL && mp_stream->boundary.len != 0) {
		if (ev == MG_EV_READ || ev == MG_EV_POLL) {
			if (ev == MG_EV_READ) {
				mg_http_multipart_continue(nc);
			} else if (mp_stream->data_avail) {
				/* Try re-delivering the data. */
				mg_http_multipart_continue(nc);
			}
			return;
		} else if (ev == MG_EV_CLOSE) {
			/*
			 * Multipart message is in progress, but connection is closed.
			 * Finish part and request with an error flag.
			 */
			struct mg_http_multipart mp;
			memset(&mp, 0, sizeof(mp));
			mp.status = -1;
			mp.user_data = mp_stream->user_data;
			mp.part.name = mp_stream->part.name;
			mp.part.filename = mp_stream->part.filename;
			mg_call(nc, MG_EV_HTTP_PART_END, &mp);
			mp.part.name.ptr = NULL;
			mp.part.filename.ptr = NULL;
			mg_call(nc, MG_EV_HTTP_MULTIPART_REQUEST_END, &mp);
			mp_stream->state = MPS_FINISHED;
			return;
		}
	}

	if (hm->chunk.len >= 0 && ev == MG_EV_HTTP_CHUNK) {
		s = mg_http_get_header(hm, "Content-Type");
		if (s->len >= 9 && strncmp(s->ptr, "multipart", 9) == 0) {
			/* New request - new proto data */
			nc->label[0] = 'M';

			nc->pfn = fn;
			nc->pfn_data = calloc(1, sizeof(struct mg_http_multipart_stream));
			mg_http_multipart_begin(nc, hm);
			mg_http_multipart_continue(nc);
			return;
		}
	}
}