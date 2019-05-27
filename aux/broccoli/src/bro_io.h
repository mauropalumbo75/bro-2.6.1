/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef broccoli_io_h
#define broccoli_io_h

#include <broccoli.h>
#include <bro_sobject.h>

/**
 * __bro_io_msg_new -- allocates a new message destined to a given peer.
 */
BroMsg * __bro_io_msg_new(char type, uint32 peer_id);

/**
 * __bro_io_msg_free -- releases message plus any data hooked into it.
 * @param msg msg to free.
 */
void     __bro_io_msg_free(BroMsg *msg);

/**
 * __bro_io_msg_set_cont -- sets the content of a message.
 * @param msg message to set content of.
 * @param type type of the message, a BRO_MSG_CONT_xxx constant.
 * @param content the content itself.
 *
 * The function sets @p msg's content, of given @p type, to @p content.
 * Note that __bro_io_msg_free will release the data pointed to
 * by @p content, depending on @p type!
 */
void     __bro_io_msg_set_cont(BroMsg *msg, int type, void *content);

int      __bro_io_msg_queue_flush(BroConn *bc);
void     __bro_io_msg_queue_dump(BroConn *bc, const char *message);

/**
 * __bro_io_raw_queue -- enqueues raw data.
 * @param bc connection handle.
 * @param type type of the message, a BRO_MSG_xxx value.
 * @param data raw bytes of data
 * @param data_len length of @p data.
 *
 * The function enqueues a message containing raw data for a
 * message of type @p type.
 *
 * @returns %FALSE on error, %TRUE otherwise.
 */
int      __bro_io_raw_queue(BroConn *bc, int type,
			    uchar *data, int data_len);

/**
 * __bro_io_rawbuf_queue -- enqueues raw buffer data.
 * @param bc connection handle.
 * @param type type of the message, a BRO_MSG_xxx value.
 * @param buf buffer with payload to be enqueued.
 *
 * The function enqueues a message containing raw buffer data for a
 * message of type @p type.
 *
 * NOTE: @p buf's ownership is taken over by the function. You do not
 * need to clean it up, and should not expect the pointer to it to
 * remain valid.
 *
 * @returns %FALSE on error, %TRUE otherwise.
 */
int      __bro_io_rawbuf_queue(BroConn *bc, int type, BroBuf *buf);

/**
 * __bro_io_event_queue -- enqueues an event.
 * @param bc connection handle.
 * @param ev event handle.
 *
 * The function enqueues an event for later transmission.
 *
 * @returns %FALSE on error, %TRUE otherwise.
 */
int      __bro_io_event_queue(BroConn *bc, BroEvent *ev);

/**
 * __bro_io_request_queue -- enqueues a request.
 * @param bc connection handle.
 * @param req request handle.
 *
 * The function enqueues an request for later transmission.
 *
 * @returns %FALSE on error, %TRUE otherwise.
 */
int      __bro_io_request_queue(BroConn *bc, BroRequest *req);

#ifdef BRO_PCAP_SUPPORT
/**
 * __bro_io_packet_queue - enqueues a pcap packet.
 * @param bc connection handle.
 * @param packet pcap packet.
 *
 * The function enqueues a pcap packet wrapped via bro_packet_new()
 * for later transmission.
 *
 * @returns %FALSE on error, %TRUE otherwise.
 */
int      __bro_io_packet_queue(BroConn *bc, BroPacket *packet);
#endif


int      __bro_io_process_input(BroConn *bc);

void     __bro_io_writer_loop(BroConn *bc);

/**
 * __bro_io_loop -- performs I/O in the handler process.
 * @param bc connection handle.
 *
 * This function is the implementation of the I/O handler processes.
 * It sits in a blocking loop and depending on the request sent to it via
 * bc->state->io_msg it performs the requested I/O operation. It does not
 * return unless the connection encounters an error or teardown is requested.
 */
void     __bro_io_loop(BroConn *bc);

#endif
