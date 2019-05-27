// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_TCP_TCP_H
#define ANALYZER_PROTOCOL_TCP_TCP_H

#include "analyzer/Analyzer.h"
#include "PacketDumper.h"
#include "IPAddr.h"
#include "TCP_Endpoint.h"
#include "TCP_Flags.h"
#include "Conn.h"

// We define two classes here:
// - TCP_Analyzer is the analyzer for the TCP protocol itself.
// - TCP_ApplicationAnalyzer is an abstract base class for analyzers for a
//   protocol running on top of TCP.
// 
namespace analyzer { namespace pia { class PIA_TCP; } };

namespace analyzer { namespace tcp {

class TCP_Endpoint;
class TCP_ApplicationAnalyzer;
class TCP_Reassembler;

class TCP_Analyzer : public analyzer::TransportLayerAnalyzer {
public:
	explicit TCP_Analyzer(Connection* conn);
	~TCP_Analyzer() override;

	void EnableReassembly();

	// Add a child analyzer that will always get the packets,
	// independently of whether we do any reassembly.
	void AddChildPacketAnalyzer(analyzer::Analyzer* a);

	Analyzer* FindChild(ID id) override;
	Analyzer* FindChild(Tag tag) override;

	// True if the connection has closed in some sense, false otherwise.
	int IsClosed() const	{ return orig->did_close || resp->did_close; }
	int BothClosed() const	{ return orig->did_close && resp->did_close; }

	int IsPartial() const	{ return is_partial; }

	bool HadGap(bool orig) const;

	TCP_Endpoint* Orig() const	{ return orig; }
	TCP_Endpoint* Resp() const	{ return resp; }
	int OrigState() const	{ return orig->state; }
	int RespState() const	{ return resp->state; }
	int OrigPrevState() const	{ return orig->prev_state; }
	int RespPrevState() const	{ return resp->prev_state; }
	uint32 OrigSeq() const	{ return orig->LastSeq(); }
	uint32 RespSeq() const	{ return resp->LastSeq(); }

	// True if either endpoint still has pending data.  closing_endp
	// is an endpoint that has indicated it is closing (i.e., for
	// which we have seen a FIN) - for it, data is pending unless
	// everything's been delivered up to the FIN.  For its peer,
	// the test is whether it has any outstanding, un-acked data.
	int DataPending(TCP_Endpoint* closing_endp);

	void SetContentsFile(unsigned int direction, BroFile* f) override;
	BroFile* GetContentsFile(unsigned int direction) const override;

	// Callback to process a TCP option.
	typedef int (*proc_tcp_option_t)(unsigned int opt, unsigned int optlen,
			const u_char* option, TCP_Analyzer* analyzer,
			bool is_orig, void* cookie);

	// From Analyzer.h
	void UpdateConnVal(RecordVal *conn_val) override;

	// Needs to be static because it's passed as a pointer-to-function
	// rather than pointer-to-member-function.
	static int ParseTCPOptions(const struct tcphdr* tcp,
			proc_tcp_option_t proc, TCP_Analyzer* analyzer,
			bool is_orig, void* cookie);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCP_Analyzer(conn); }

protected:
	friend class TCP_ApplicationAnalyzer;
	friend class TCP_Reassembler;
	friend class analyzer::pia::PIA_TCP;

	// Analyzer interface.
	void Init() override;
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen) override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;
	void FlipRoles() override;
	bool IsReuse(double t, const u_char* pkt) override;

	// Returns the TCP header pointed to by data (which we assume is
	// aligned), updating data, len & caplen.  Returns nil if the header
	// isn't fully present.
	const struct tcphdr* ExtractTCP_Header(const u_char*& data, int& len,
						int& caplen);

	// Returns true if the checksum is valid, false if not (and in which
	// case also updates the status history of the endpoint).
	bool ValidateChecksum(const struct tcphdr* tp, TCP_Endpoint* endpoint,
				int len, int caplen);

	void SetPartialStatus(TCP_Flags flags, bool is_orig);

	// Update the state machine of the TCPs based on the activity.  This
	// includes our pseudo-states such as TCP_ENDPOINT_PARTIAL.
	//
	// On return, do_close is true if we should consider the connection
	// as closed, and gen_event if we shouuld generate an event about
	// this fact.
	void UpdateStateMachine(double t,
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			uint32 base_seq, uint32 ack_seq,
			int len, int32 delta_last, int is_orig, TCP_Flags flags,
			int& do_close, int& gen_event);

	void UpdateInactiveState(double t,
				TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				uint32 base_seq, uint32 ack_seq,
				int len, int is_orig, TCP_Flags flags,
				int& do_close, int& gen_event);

	void UpdateSYN_SentState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				 int len, int is_orig, TCP_Flags flags,
				 int& do_close, int& gen_event);

	void UpdateEstablishedState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				    TCP_Flags flags, int& do_close, int& gen_event);

	void UpdateClosedState(double t, TCP_Endpoint* endpoint,
				int32 delta_last, TCP_Flags flags,
				int& do_close);

	void UpdateResetState(int len, TCP_Flags flags);

	void GeneratePacketEvent(uint64 rel_seq, uint64 rel_ack,
				 const u_char* data, int len, int caplen,
				 int is_orig, TCP_Flags flags);

	int DeliverData(double t, const u_char* data, int len, int caplen,
			const IP_Hdr* ip, const struct tcphdr* tp,
			TCP_Endpoint* endpoint, uint64 rel_data_seq,
			int is_orig, TCP_Flags flags);

	void CheckRecording(int need_contents, TCP_Flags flags);
	void CheckPIA_FirstPacket(int is_orig, const IP_Hdr* ip);

	friend class ConnectionTimer;
	void AttemptTimer(double t);
	void PartialCloseTimer(double t);
	void ExpireTimer(double t);
	void ResetTimer(double t);
	void DeleteTimer(double t);
	void ConnDeleteTimer(double t);

	void EndpointEOF(TCP_Reassembler* endp);
	void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, int gen_event);
	void ConnectionFinished(int half_finished);
	void ConnectionReset();
	void PacketWithRST();

	void SetReassembler(tcp::TCP_Reassembler* rorig, tcp::TCP_Reassembler* rresp);

	// Needs to be static because it's passed as a pointer-to-function
	// rather than pointer-to-member-function.
	static int TCPOptionEvent(unsigned int opt, unsigned int optlen,
				const u_char* option, TCP_Analyzer* analyzer,
				  bool is_orig, void* cookie);

private:
	TCP_Endpoint* orig;
	TCP_Endpoint* resp;

	typedef list<analyzer::Analyzer*> analyzer_list;
	analyzer_list packet_children;

	unsigned int first_packet_seen: 2;
	unsigned int reassembling: 1;
	unsigned int is_partial: 1;
	unsigned int is_active: 1;
	unsigned int finished: 1;

	// Whether we're waiting on final data delivery before closing
	// this connection.
	unsigned int close_deferred: 1;

	// Whether to generate an event when we finally do close it.
	unsigned int deferred_gen_event: 1;

	// Whether we have seen the first ACK from the originator.
	unsigned int seen_first_ACK: 1;
};

class TCP_ApplicationAnalyzer : public analyzer::Analyzer {
public:
	TCP_ApplicationAnalyzer(const char* name, Connection* conn)
	: Analyzer(name, conn)
		{ tcp = 0; }

	explicit TCP_ApplicationAnalyzer(Connection* conn)
	: Analyzer(conn)
		{ tcp = 0; }

	~TCP_ApplicationAnalyzer() override { }

	// This may be nil if we are not directly associated with a TCP
	// analyzer (e.g., we're part of a tunnel decapsulation pipeline).
	TCP_Analyzer* TCP()
		{
		return tcp ?
			tcp :
			static_cast<TCP_Analyzer*>(Conn()->FindAnalyzer("TCP"));
		}

	void SetTCP(TCP_Analyzer* arg_tcp)	{ tcp = arg_tcp; }

	// The given endpoint's data delivery is complete.
	virtual void EndpointEOF(bool is_orig);

	// Called whenever an end enters TCP_ENDPOINT_CLOSED or
	// TCP_ENDPOINT_RESET.  If gen_event is true and the connection
	// is now fully closed, a connection_finished event will be
	// generated; otherwise not.
	virtual void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
				      analyzer::tcp::TCP_Endpoint* peer, int gen_event);
	virtual void ConnectionFinished(int half_finished);
	virtual void ConnectionReset();

	// Called whenever a RST packet is seen - sometimes the invocation
	// of ConnectionReset is delayed.
	virtual void PacketWithRST();

	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;
	void Init() override;

	// This suppresses violations if the TCP connection wasn't
	// fully established.
	void ProtocolViolation(const char* reason,
					const char* data = 0, int len = 0) override;

	// "name" and "val" both now belong to this object, which needs to
	//  delete them when done with them.
	virtual void SetEnv(bool orig, char* name, char* val);

private:
	TCP_Analyzer* tcp;
};

class TCP_SupportAnalyzer : public analyzer::SupportAnalyzer {
public:
	TCP_SupportAnalyzer(const char* name, Connection* conn, bool arg_orig)
		: analyzer::SupportAnalyzer(name, conn, arg_orig)	{ }

	~TCP_SupportAnalyzer() override {}

	// These are passed on from TCP_Analyzer.
	virtual void EndpointEOF(bool is_orig)	{ }
	virtual void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, int gen_event) 	{ }
	virtual void ConnectionFinished(int half_finished)	{ }
	virtual void ConnectionReset()	{ }
	virtual void PacketWithRST()	{ }
};


class TCPStats_Endpoint {
public:
	explicit TCPStats_Endpoint(TCP_Endpoint* endp);

	int DataSent(double t, uint64 seq, int len, int caplen, const u_char* data,
			const IP_Hdr* ip, const struct tcphdr* tp);

	RecordVal* BuildStats();

protected:
	TCP_Endpoint* endp;
	int num_pkts;
	int num_rxmit;
	int num_rxmit_bytes;
	int num_in_order;
	int num_OO;
	int num_repl;
	uint64 max_top_seq;
	int last_id;
	int endian_type;
};

class TCPStats_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit TCPStats_Analyzer(Connection* c);
	~TCPStats_Analyzer() override;

	void Init() override;
	void Done() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCPStats_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;

	TCPStats_Endpoint* orig_stats;
	TCPStats_Endpoint* resp_stats;
};

} } // namespace analyzer::* 

#endif
