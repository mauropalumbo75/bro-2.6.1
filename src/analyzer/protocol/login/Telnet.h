// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_LOGIN_TELNET_H
#define ANALYZER_PROTOCOL_LOGIN_TELNET_H

#include "Login.h"

namespace analyzer { namespace login {

class Telnet_Analyzer : public Login_Analyzer {
public:
	explicit Telnet_Analyzer(Connection* conn);
	~Telnet_Analyzer() override {}

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Telnet_Analyzer(conn); }
};

} } // namespace analyzer::* 

#endif
