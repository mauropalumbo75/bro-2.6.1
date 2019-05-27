// See the file "COPYING" in the main distribution directory for copyright.

#ifndef frag_h
#define frag_h

#include "util.h"
#include "IP.h"
#include "Net.h"
#include "Reassem.h"
#include "Timer.h"

class HashKey;
class NetSessions;

class FragReassembler;
class FragTimer;

typedef void (FragReassembler::*frag_timer_func)(double t);

class FragReassembler : public Reassembler {
public:
	FragReassembler(NetSessions* s, const IP_Hdr* ip, const u_char* pkt,
			HashKey* k, double t);
	~FragReassembler() override;

	void AddFragment(double t, const IP_Hdr* ip, const u_char* pkt);

	void Expire(double t);
	void DeleteTimer();
	void ClearTimer()	{ expire_timer = 0; }

	const IP_Hdr* ReassembledPkt()	{ return reassembled_pkt; }
	HashKey* Key() const	{ return key; }

protected:
	void BlockInserted(DataBlock* start_block) override;
	void Overlap(const u_char* b1, const u_char* b2, uint64 n) override;
	void Weird(const char* name) const;

	u_char* proto_hdr;
	IP_Hdr* reassembled_pkt;
	uint16 proto_hdr_len;
	NetSessions* s;
	uint64 frag_size;	// size of fully reassembled fragment
	uint16 next_proto; // first IPv6 fragment header's next proto field
	HashKey* key;

	FragTimer* expire_timer;
};

class FragTimer : public Timer {
public:
	FragTimer(FragReassembler* arg_f, double arg_t)
		: Timer(arg_t, TIMER_FRAG)
			{ f = arg_f; }
	~FragTimer() override;

	void Dispatch(double t, int is_expire) override;

	// Break the association between this timer and its creator.
	void ClearReassembler()	{ f = 0; }

protected:
	FragReassembler* f;
};

#endif
