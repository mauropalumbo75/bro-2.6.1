// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_RPC_PORTMAP_H
#define ANALYZER_PROTOCOL_RPC_PORTMAP_H

#include "RPC.h"

namespace analyzer { namespace rpc {

class PortmapperInterp : public RPC_Interpreter {
public:
	explicit PortmapperInterp(analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) override;
	int RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success,
			   const u_char*& buf, int& n, double start_time,
			   double last_time, int reply_len) override;
	uint32 CheckPort(uint32 port);

	void Event(EventHandlerPtr f, Val* request, BifEnum::rpc_status status, Val* reply);

	Val* ExtractMapping(const u_char*& buf, int& len);
	Val* ExtractPortRequest(const u_char*& buf, int& len);
	Val* ExtractCallItRequest(const u_char*& buf, int& len);
};

class Portmapper_Analyzer : public RPC_Analyzer {
public:
	explicit Portmapper_Analyzer(Connection* conn);
	~Portmapper_Analyzer() override;
	void Init() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Portmapper_Analyzer(conn); }
};

} } // namespace analyzer::* 

#endif
