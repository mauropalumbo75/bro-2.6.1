// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_INTERCONN_INTERCONN_H
#define ANALYZER_PROTOCOL_INTERCONN_INTERCONN_H

#include "analyzer/protocol/tcp/TCP.h"
#include "Timer.h"
#include "NetVar.h"

namespace analyzer { namespace interconn {

class InterConnEndpoint : public BroObj {
public:
	explicit InterConnEndpoint(tcp::TCP_Endpoint* e);

	int DataSent(double t, uint64 seq, int len, int caplen, const u_char* data,
		     const IP_Hdr* ip, const struct tcphdr* tp);

	RecordVal* BuildStats();

protected:
	int EstimateGapPacketNum(int gap) const;
	int IsPotentialKeystrokePacket(int len) const;
	int IsNormalKeystrokeInterarrival(double t) const;

	tcp::TCP_Endpoint* endp;
	double last_keystroke_time;
	uint64 max_top_seq;
	uint32 num_pkts;
	uint32 num_keystrokes_two_in_a_row;
	uint32 num_normal_interarrivals;
	uint32 num_8k4_pkts;
	uint32 num_8k0_pkts;
	uint32 num_bytes;
	uint32 num_7bit_ascii;
	uint32 num_lines;
	uint32 num_normal_lines;
	int is_partial;
	int keystroke_just_seen;
};


class InterConn_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit InterConn_Analyzer(Connection* c);
	~InterConn_Analyzer() override;

	void Init() override;
	void Done() override;
	void StatTimer(double t, int is_expire);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new InterConn_Analyzer(conn); }

protected:
	// We support both packet and stream input and can be put in place even
	// if the TCP analyzer is not yet reassembling.
	void DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;
	void DeliverStream(int len, const u_char* data, bool is_orig) override;

	void StatEvent();
	void RemoveEvent();

	InterConnEndpoint* orig_endp;
	InterConnEndpoint* resp_endp;

	int orig_stream_pos;
	int resp_stream_pos;

	double timeout;
	double backoff;
};

class InterConnTimer : public Timer {
public:
	InterConnTimer(double t, InterConn_Analyzer* a);
	~InterConnTimer() override;

	void Dispatch(double t, int is_expire) override;

protected:
	InterConn_Analyzer* analyzer;
};

} } // namespace analyzer::* 

#endif
