/*
 * ahdlc.h
 *
 * Written by Christoph Schulz <develop@kristov.de>
 *
 * Copyright (C) 2017 Christoph Schulz <develop@kristov.de>
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * version 2.1 as published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU LESSER GENERAL PUBLIC LICENSE for more details.
 *
 */

#ifndef _AHDLC_H
#define _AHDLC_H

#include "m_capi.h"

struct ahdlc_decode_state {
	struct mc_buf *mc;
	int escape_flag;
	int flush_flag;
	int fcs;
};

typedef int (*ahdlc_callback_t)(void *arg, struct mc_buf *mc);

struct ahdlc_decode_state *ahdlc_alloc_decode_state(void);
int ahdlc_alloc_decode_buffer(unsigned char **buf);
void ahdlc_free_decode_buffer(unsigned char *buf);
int ahdlc_decode(struct ahdlc_decode_state *state, unsigned char *p, int n,
		 ahdlc_callback_t callback, void *cb_arg);
void ahdlc_free_decode_state(struct ahdlc_decode_state *state);

int ahdlc_encode(unsigned char *p, int n, unsigned char **out);

#endif
