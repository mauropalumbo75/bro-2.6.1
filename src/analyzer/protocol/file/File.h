// Analyzer for connections that transfer binary data.

#ifndef ANALYZER_PROTOCOL_FILE_FILE_H
#define ANALYZER_PROTOCOL_FILE_FILE_H

#include "analyzer/protocol/tcp/TCP.h"

#include <string>

namespace analyzer { namespace file {

class File_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	File_Analyzer(const char* name, Connection* conn);

	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;

	void Undelivered(uint64 seq, int len, bool orig) override;

//	static analyzer::Analyzer* Instantiate(Connection* conn)
//		{ return new File_Analyzer(conn); }

protected:
	void Identify();

	static const int BUFFER_SIZE = 1024;
	char buffer[BUFFER_SIZE];
	int buffer_len;
	string file_id_orig;
	string file_id_resp;
};

class IRC_Data : public File_Analyzer {
public:
	explicit IRC_Data(Connection* conn)
		: File_Analyzer("IRC_Data", conn)
		{ }

	static Analyzer* Instantiate(Connection* conn)
		{ return new IRC_Data(conn); }
};

class FTP_Data : public File_Analyzer {
public:
	explicit FTP_Data(Connection* conn)
		: File_Analyzer("FTP_Data", conn)
		{ }

	static Analyzer* Instantiate(Connection* conn)
		{ return new FTP_Data(conn); }
};

} } // namespace analyzer::* 

#endif
