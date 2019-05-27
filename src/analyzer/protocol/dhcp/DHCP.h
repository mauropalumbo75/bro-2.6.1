#ifndef ANALYZER_PROTOCOL_DHCP_DHCP_H
#define ANALYZER_PROTOCOL_DHCP_DHCP_H

#include "analyzer/protocol/udp/UDP.h"

#include "dhcp_pac.h"

namespace analyzer { namespace dhcp {

class DHCP_Analyzer : public analyzer::Analyzer {
public:
	explicit DHCP_Analyzer(Connection* conn);
	~DHCP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64 seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DHCP_Analyzer(conn); }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

} } // namespace analyzer::* 

#endif
