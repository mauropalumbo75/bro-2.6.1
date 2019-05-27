// See the file "COPYING" in the main distribution directory for copyright.

#include "bro-config.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string>
#include <algorithm>

#include "NetVar.h"
#include "HTTP.h"
#include "Event.h"
#include "analyzer/protocol/mime/MIME.h"
#include "file_analysis/Manager.h"

#include "events.bif.h"

using namespace analyzer::http;

const bool DEBUG_http = false;

// The EXPECT_*_NOTHING states are used to prevent further parsing. Used if a
// message was interrupted.
enum {
	EXPECT_REQUEST_LINE,
	EXPECT_REQUEST_MESSAGE,
	EXPECT_REQUEST_TRAILER,
	EXPECT_REQUEST_NOTHING,
};

enum {
	EXPECT_REPLY_LINE,
	EXPECT_REPLY_MESSAGE,
	EXPECT_REPLY_TRAILER,
	EXPECT_REPLY_NOTHING,
};

HTTP_Entity::HTTP_Entity(HTTP_Message *arg_message, MIME_Entity* parent_entity, int arg_expect_body)
:MIME_Entity(arg_message, parent_entity)
	{
	http_message = arg_message;
	expect_body = arg_expect_body;
	chunked_transfer_state = NON_CHUNKED_TRANSFER;
	content_length = range_length = -1;	// unspecified
	expect_data_length = 0;
	body_length = 0;
	header_length = 0;
	deliver_body = true;
	encoding = IDENTITY;
	zip = 0;
	is_partial_content = false;
	offset = 0;
	instance_length = -1; // unspecified
	send_size = true;
	}

void HTTP_Entity::EndOfData()
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: end of data\n", network_time);

	if ( zip )
		{
		zip->Done();
		delete zip;
		zip = 0;
		encoding = IDENTITY;
		}

	if ( body_length )
		http_message->MyHTTP_Analyzer()->
			ForwardEndOfData(http_message->IsOrig());

	MIME_Entity::EndOfData();
	}

void HTTP_Entity::Deliver(int len, const char* data, int trailing_CRLF)
	{
	if ( DEBUG_http )
		{
		DEBUG_MSG("%.6f HTTP_Entity::Deliver len=%d, in_header=%d\n",
		          network_time, len, in_header);
		}

	if ( end_of_data )
		{
		// Multipart entities may have trailers
		if ( content_type != mime::CONTENT_TYPE_MULTIPART )
			IllegalFormat("data trailing the end of entity");
		return;
		}

	if ( in_header )
		{
		if ( ! trailing_CRLF )
			http_message->MyHTTP_Analyzer()->Weird("http_no_crlf_in_header_list");

		header_length += len;
		MIME_Entity::Deliver(len, data, trailing_CRLF);
		return;
		}

	// Entity body.
	if ( content_type == mime::CONTENT_TYPE_MULTIPART ||
	     content_type == mime::CONTENT_TYPE_MESSAGE )
		DeliverBody(len, data, trailing_CRLF);

	else if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		{
		switch ( chunked_transfer_state ) {
		case EXPECT_CHUNK_SIZE:
			ASSERT(trailing_CRLF);
			if ( ! atoi_n(len, data, 0, 16, expect_data_length) )
				{
				http_message->Weird("HTTP_bad_chunk_size");
				expect_data_length = 0;
				}

			if ( expect_data_length > 0 )
				{
				chunked_transfer_state = EXPECT_CHUNK_DATA;
				SetPlainDelivery(expect_data_length);
				}
			else
				{
				// This is the last chunk
				in_header = 1;
				chunked_transfer_state = EXPECT_CHUNK_TRAILER;
				}
			break;

		case EXPECT_CHUNK_DATA:
			ASSERT(! trailing_CRLF);
			ASSERT(len <= expect_data_length);
			expect_data_length -= len;
			if ( expect_data_length <= 0 )
				{
				SetPlainDelivery(0);
				chunked_transfer_state = EXPECT_CHUNK_DATA_CRLF;
				}
			DeliverBody(len, data, 0);
			break;

		case EXPECT_CHUNK_DATA_CRLF:
			ASSERT(trailing_CRLF);
			if ( len > 0 )
				IllegalFormat("inaccurate chunk size: data before <CR><LF>");
			chunked_transfer_state = EXPECT_CHUNK_SIZE;
			break;
		}
		}

	else if ( content_length >= 0 )
		{
		ASSERT(! trailing_CRLF);
		ASSERT(len <= expect_data_length);

		DeliverBody(len, data, 0);

		expect_data_length -= len;
		if ( expect_data_length <= 0 )
			{
			SetPlainDelivery(0);
			EndOfData();
			}
		}

	else
		DeliverBody(len, data, trailing_CRLF);
	}

class HTTP_Entity::UncompressedOutput : public analyzer::OutputHandler {
public:
	UncompressedOutput(HTTP_Entity* e)	{ entity = e; }
	virtual	~UncompressedOutput() { }
	virtual void DeliverStream(int len, const u_char* data, bool orig)
		{
		entity->DeliverBodyClear(len, (char*) data, false);
		}
private:
	HTTP_Entity* entity;
};

void HTTP_Entity::DeliverBody(int len, const char* data, int trailing_CRLF)
	{
	if ( encoding == GZIP || encoding == DEFLATE )
		{
		zip::ZIP_Analyzer::Method method =
			encoding == GZIP ?
				zip::ZIP_Analyzer::GZIP : zip::ZIP_Analyzer::DEFLATE;

		if ( ! zip )
			{
			// We don't care about the direction here.
			zip = new zip::ZIP_Analyzer(
				http_message->MyHTTP_Analyzer()->Conn(),
						false, method);
			zip->SetOutputHandler(new UncompressedOutput(this));
			}

		zip->NextStream(len, (const u_char*) data, false);
		}
	else
		DeliverBodyClear(len, data, trailing_CRLF);
	}

void HTTP_Entity::DeliverBodyClear(int len, const char* data, int trailing_CRLF)
	{
	bool new_data = (body_length == 0);

	body_length += len;
	if ( trailing_CRLF )
		body_length += 2;

	if ( deliver_body )
		MIME_Entity::Deliver(len, data, trailing_CRLF);

	Rule::PatternType rule =
		http_message->IsOrig() ?
			Rule::HTTP_REQUEST_BODY : Rule::HTTP_REPLY_BODY;

	http_message->MyHTTP_Analyzer()->Conn()->
		Match(rule, (const u_char*) data, len,
			http_message->IsOrig(), new_data, false, new_data);

	// FIXME: buffer data for forwarding (matcher might match later).
	http_message->MyHTTP_Analyzer()->ForwardStream(len, (const u_char *) data,
		http_message->IsOrig());
	}

// Returns 1 if the undelivered bytes are completely within the body,
// otherwise returns 0.
int HTTP_Entity::Undelivered(int64_t len)
	{
	if ( DEBUG_http )
		{
		DEBUG_MSG("Content gap %" PRId64", expect_data_length %" PRId64 "\n",
			  len, expect_data_length);
		}

	// Don't propogate an entity (file) gap if we're still in the headers,
	// or the body length was declared to be zero.
	if ( (end_of_data && in_header) || body_length == 0 )
		return 0;

	if ( is_partial_content )
		{
		precomputed_file_id = file_mgr->Gap(body_length, len,
		              http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		              http_message->MyHTTP_Analyzer()->Conn(),
		              http_message->IsOrig(), precomputed_file_id);
		offset += len;
		}
	else
		precomputed_file_id = file_mgr->Gap(body_length, len,
		                  http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		                  http_message->MyHTTP_Analyzer()->Conn(),
		                  http_message->IsOrig(),
		                  precomputed_file_id);

	if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		{
		if ( chunked_transfer_state == EXPECT_CHUNK_DATA &&
		     expect_data_length >= len )
			{
			body_length += len;
			expect_data_length -= len;

			SetPlainDelivery(expect_data_length);
			if ( expect_data_length == 0 )
				chunked_transfer_state = EXPECT_CHUNK_DATA_CRLF;

			return 1;
			}
		else
			return 0;
		}

	else if ( content_length >= 0 )
		{
		if ( expect_data_length >= len )
			{
			body_length += len;
			expect_data_length -= len;

			SetPlainDelivery(expect_data_length);

			if ( expect_data_length <= 0 )
				EndOfData();

			return 1;
			}

		else
			return 0;
		}

	return 0;
	}

void HTTP_Entity::SubmitData(int len, const char* buf)
	{
	if ( deliver_body )
		MIME_Entity::SubmitData(len, buf);

	if ( send_size && ( encoding == GZIP || encoding == DEFLATE ) )
		// Auto-decompress in DeliverBody invalidates sizes derived from headers
		send_size = false;

	if ( is_partial_content )
		{
		if ( send_size && instance_length > 0 )
			precomputed_file_id = file_mgr->SetSize(instance_length,
			                  http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
			                  http_message->MyHTTP_Analyzer()->Conn(),
			                  http_message->IsOrig(), precomputed_file_id);

		precomputed_file_id = file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len, offset,
		                 http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		                 http_message->MyHTTP_Analyzer()->Conn(),
		                 http_message->IsOrig(), precomputed_file_id);

		offset += len;
		}
	else
		{
		if ( send_size && content_length > 0 )
			precomputed_file_id = file_mgr->SetSize(content_length,
			                  http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
			                  http_message->MyHTTP_Analyzer()->Conn(),
			                  http_message->IsOrig(),
			                  precomputed_file_id);

		precomputed_file_id = file_mgr->DataIn(reinterpret_cast<const u_char*>(buf),
		                 len,
		                 http_message->MyHTTP_Analyzer()->GetAnalyzerTag(),
		                 http_message->MyHTTP_Analyzer()->Conn(),
		                 http_message->IsOrig(),
		                 precomputed_file_id);
		}

	send_size = false;
	}

void HTTP_Entity::SetPlainDelivery(int64_t length)
	{
	ASSERT(length >= 0);
	ASSERT(length == 0 || ! in_header);

	http_message->SetPlainDelivery(length);

	// If we skip HTTP data, the skipped part will appear as
	// 'undelivered' data, so we do not need to adjust
	// expect_data_length.
	}

void HTTP_Entity::SubmitHeader(mime::MIME_Header* h)
	{
	if ( mime::istrequal(h->get_name(), "content-length") )
		{
		data_chunk_t vt = h->get_value_token();
		if ( ! mime::is_null_data_chunk(vt) )
			{
			int64_t n;
			if ( atoi_n(vt.length, vt.data, 0, 10, n) )
				{
				content_length = n;

				if ( is_partial_content && range_length != content_length )
					{
					// Possible evasion attempt.
					http_message->Weird("HTTP_range_not_matching_len");

					// Take the maximum of both lengths to avoid evasions.
					if ( range_length > content_length )
						content_length = range_length;
					}
				}
			else
				content_length = 0;
			}
		}

	// Figure out content-length for HTTP 206 Partial Content response
	else if ( mime::istrequal(h->get_name(), "content-range") &&
		      http_message->MyHTTP_Analyzer()->HTTP_ReplyCode() == 206 )
		{
		data_chunk_t vt = h->get_value_token();
		string byte_unit(vt.data, vt.length);
		vt = h->get_value_after_token();
		string byte_range(vt.data, vt.length);
		byte_range.erase(remove(byte_range.begin(), byte_range.end(), ' '),
		                 byte_range.end());

		if ( byte_unit != "bytes" )
			{
			http_message->Weird("HTTP_content_range_unknown_byte_unit");
			return;
			}

		size_t p = byte_range.find("/");
		if ( p == string::npos )
			{
			http_message->Weird("HTTP_content_range_cannot_parse");
			return;
			}

		string byte_range_resp_spec = byte_range.substr(0, p);
		string instance_length_str = byte_range.substr(p + 1);

		p = byte_range_resp_spec.find("-");
		if ( p == string::npos )
			{
			http_message->Weird("HTTP_content_range_cannot_parse");
			return;
			}

		string first_byte_pos = byte_range_resp_spec.substr(0, p);
		string last_byte_pos = byte_range_resp_spec.substr(p + 1);

		if ( DEBUG_http )
			DEBUG_MSG("Parsed Content-Range: %s %s-%s/%s\n", byte_unit.c_str(),
		              first_byte_pos.c_str(), last_byte_pos.c_str(),
		              instance_length_str.c_str());

		int64_t f, l;
		atoi_n(first_byte_pos.size(), first_byte_pos.c_str(), 0, 10, f);
		atoi_n(last_byte_pos.size(), last_byte_pos.c_str(), 0, 10, l);
		int64_t len = l - f + 1;

		if ( DEBUG_http )
			DEBUG_MSG("Content-Range length = %" PRId64"\n", len);

		if ( len > 0 )
			{
			if ( instance_length_str != "*" )
				{
				if ( ! atoi_n(instance_length_str.size(),
				              instance_length_str.c_str(), 0, 10,
				              instance_length) )
					instance_length = 0;
				}

			is_partial_content = true;
			offset = f;
			range_length = len;

			if ( content_length > 0 )
				{
				if ( content_length != range_length )
					{
					// Possible evasion attempt.
					http_message->Weird("HTTP_range_not_matching_len");

					// Take the maximum of both lengths to avoid evasions.
					if ( range_length > content_length )
						content_length = range_length;
					}
				}
			else
				content_length = range_length;
			}
		else
			{
			http_message->Weird("HTTP_non_positive_content_range");
			return;
			}
		}

	else if ( mime::istrequal(h->get_name(), "transfer-encoding") )
		{
		double http_version = 0;
		if (http_message->analyzer->GetRequestOngoing())
			http_version = http_message->analyzer->GetRequestVersion();
		else // reply_ongoing
			http_version = http_message->analyzer->GetReplyVersion();

		data_chunk_t vt = h->get_value_token();
		if ( mime::istrequal(vt, "chunked") && http_version == 1.1 )
			chunked_transfer_state = BEFORE_CHUNK;
		}

	else if ( mime::istrequal(h->get_name(), "content-encoding") )
		{
		data_chunk_t vt = h->get_value_token();
		if ( mime::istrequal(vt, "gzip") || mime::istrequal(vt, "x-gzip") )
			encoding = GZIP;
		if ( mime::istrequal(vt, "deflate") )
			encoding = DEFLATE;
		}

	MIME_Entity::SubmitHeader(h);
	}

void HTTP_Entity::SubmitAllHeaders()
	{
	// in_header should be set to false when SubmitAllHeaders() is called.
	ASSERT(! in_header);

	if ( DEBUG_http )
		DEBUG_MSG("%.6f end of headers\n", network_time);

	if ( Parent() &&
	     Parent()->MIMEContentType() == mime::CONTENT_TYPE_MULTIPART )
		{
		// Don't treat single \r or \n characters in the multipart body content
		// as lines because the MIME_Entity code will implicitly add back a
		// \r\n for each line it receives.  We do this instead of setting
		// plain delivery mode for the content line analyzer because
		// the size of the content to deliver "plainly" may be unknown
		// and just leaving it in that mode indefinitely screws up the
		// detection of multipart boundaries.
		http_message->content_line->SupressWeirds(true);
		http_message->content_line->SetCRLFAsEOL(0);
		}

	// The presence of a message-body in a request is signaled by
	// the inclusion of a Content-Length or Transfer-Encoding
	// header field in the request's message-headers.
	if ( chunked_transfer_state == EXPECT_CHUNK_TRAILER )
		{
		http_message->SubmitTrailingHeaders(headers);
		chunked_transfer_state = EXPECT_NOTHING;
		EndOfData();
		return;
		}

	MIME_Entity::SubmitAllHeaders();

	if ( expect_body == HTTP_BODY_NOT_EXPECTED )
		{
		EndOfData();
		return;
		}

	if ( content_type == mime::CONTENT_TYPE_MULTIPART ||
	     content_type == mime::CONTENT_TYPE_MESSAGE )
		{
		// Do nothing.
		// Make sure that we check for multiple/message contents first,
		// because we do not have to turn on .
		if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
			{
			http_message->Weird(
				"HTTP_chunked_transfer_for_multipart_message");
			}
		}

	else if ( chunked_transfer_state != NON_CHUNKED_TRANSFER )
		chunked_transfer_state = EXPECT_CHUNK_SIZE;

	else if ( content_length >= 0 )
		{
		if ( content_length > 0 )
			{
			expect_data_length = content_length;
			SetPlainDelivery(content_length);
			}
		else
			EndOfData(); // handle the case that content-length = 0
		}

	// Turn plain delivery on permanently for compressed bodies without
	// content-length headers or if connection is to be closed afterwards
	// anyway.
	else if ( http_message->MyHTTP_Analyzer()->IsConnectionClose ()
		  || encoding == GZIP || encoding == DEFLATE
		 )
		{
		// FIXME: Using INT_MAX is kind of a hack here.  Better
		// would be to make -1 as special value interpreted as
		// "until the end of the connection".
		expect_data_length = INT_MAX;
		SetPlainDelivery(INT_MAX);
		}

	else
		{
		if ( expect_body != HTTP_BODY_EXPECTED )
			// there is no body
			EndOfData();
		}
	}

HTTP_Message::HTTP_Message(HTTP_Analyzer* arg_analyzer,
				tcp::ContentLine_Analyzer* arg_cl, bool arg_is_orig,
				int expect_body, int64_t init_header_length)
: MIME_Message (arg_analyzer)
	{
	analyzer = arg_analyzer;
	content_line = arg_cl;
	is_orig = arg_is_orig;

	current_entity = 0;
	top_level = new HTTP_Entity(this, 0, expect_body);
	entity_data_buffer = 0;
	BeginEntity(top_level);

	start_time = network_time;
	body_length = 0;
	content_gap_length = 0;
	header_length = init_header_length;
	}

HTTP_Message::~HTTP_Message()
	{
	delete top_level;
	delete [] entity_data_buffer;
	}

Val* HTTP_Message::BuildMessageStat(const int interrupted, const char* msg)
	{
	RecordVal* stat = new RecordVal(http_message_stat);
	int field = 0;
	stat->Assign(field++, new Val(start_time, TYPE_TIME));
	stat->Assign(field++, new Val(interrupted, TYPE_BOOL));
	stat->Assign(field++, new StringVal(msg));
	stat->Assign(field++, new Val(body_length, TYPE_COUNT));
	stat->Assign(field++, new Val(content_gap_length, TYPE_COUNT));
	stat->Assign(field++, new Val(header_length, TYPE_COUNT));
	return stat;
	}

void HTTP_Message::Done(const int interrupted, const char* detail)
	{
	if ( finished )
		return;

	MIME_Message::Done();

	// DEBUG_MSG("%.6f HTTP message done.\n", network_time);
	top_level->EndOfData();

	if ( is_orig || MyHTTP_Analyzer()->HTTP_ReplyCode() != 206 )
		{
		// multipart/byteranges may span multiple connections, so don't EOF.
		HTTP_Entity* he = dynamic_cast<HTTP_Entity*>(top_level);

		if ( he && ! he->FileID().empty() )
			file_mgr->EndOfFile(he->FileID());
		else
			file_mgr->EndOfFile(MyHTTP_Analyzer()->GetAnalyzerTag(),
			                    MyHTTP_Analyzer()->Conn(), is_orig);
		}

	if ( http_message_done )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(BuildMessageStat(interrupted, detail));
		GetAnalyzer()->ConnectionEvent(http_message_done, vl);
		}

	MyHTTP_Analyzer()->HTTP_MessageDone(is_orig, this);
	}

int HTTP_Message::Undelivered(int64_t len)
	{
	HTTP_Entity* e = current_entity ? current_entity
	                                : static_cast<HTTP_Entity*>(top_level);

	if ( e && e->Undelivered(len) )
		{
		content_gap_length += len;
		return 1;
		}

	return 0;
	}

void HTTP_Message::BeginEntity(mime::MIME_Entity* entity)
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: begin entity (%d)\n", network_time, is_orig);

	current_entity = (HTTP_Entity*) entity;

	if ( http_begin_entity )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		analyzer->ConnectionEvent(http_begin_entity, vl);
		}
	}

void HTTP_Message::EndEntity(mime::MIME_Entity* entity)
	{
	if ( DEBUG_http )
		DEBUG_MSG("%.6f: end entity (%d)\n", network_time, is_orig);

	body_length += ((HTTP_Entity*) entity)->BodyLength();
	header_length += ((HTTP_Entity*) entity)->HeaderLength();

	if ( http_end_entity )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		analyzer->ConnectionEvent(http_end_entity, vl);
		}

	current_entity = (HTTP_Entity*) entity->Parent();

	if ( entity->Parent() &&
	     entity->Parent()->MIMEContentType() == mime::CONTENT_TYPE_MULTIPART )
		{
		content_line->SupressWeirds(false);
		content_line->SetCRLFAsEOL();
		}

	// It is necessary to call Done when EndEntity is triggered by
	// SubmitAllHeaders (through EndOfData).
	if ( entity == top_level )
		Done();

	else if ( is_orig || MyHTTP_Analyzer()->HTTP_ReplyCode() != 206 )
		{
		HTTP_Entity* he = dynamic_cast<HTTP_Entity*>(entity);

		if ( he && ! he->FileID().empty() )
			file_mgr->EndOfFile(he->FileID());
		else
			file_mgr->EndOfFile(MyHTTP_Analyzer()->GetAnalyzerTag(),
			                    MyHTTP_Analyzer()->Conn(), is_orig);
		}
	}

void HTTP_Message::SubmitHeader(mime::MIME_Header* h)
	{
	MyHTTP_Analyzer()->HTTP_Header(is_orig, h);
	}

void HTTP_Message::SubmitAllHeaders(mime::MIME_HeaderList& hlist)
	{
	if ( http_all_headers )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(BuildHeaderTable(hlist));
		analyzer->ConnectionEvent(http_all_headers, vl);
		}

	if ( http_content_type )
		{
		StringVal* ty = current_entity->ContentType();
		StringVal* subty = current_entity->ContentSubType();
		ty->Ref();
		subty->Ref();

		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(ty);
		vl->append(subty);
		analyzer->ConnectionEvent(http_content_type, vl);
		}
	}

void HTTP_Message::SubmitTrailingHeaders(mime::MIME_HeaderList& /* hlist */)
	{
	// Do nothing for now.
	}

void HTTP_Message::SubmitData(int len, const char* buf)
	{
	if ( http_entity_data )
		MyHTTP_Analyzer()->HTTP_EntityData(is_orig,
		        new BroString(reinterpret_cast<const u_char*>(buf), len, 0));
	}

int HTTP_Message::RequestBuffer(int* plen, char** pbuf)
	{
	if ( ! entity_data_buffer )
		entity_data_buffer = new char[http_entity_data_delivery_size];

	*plen = http_entity_data_delivery_size;
	*pbuf = entity_data_buffer;
	return 1;
	}

void HTTP_Message::SubmitAllData()
	{
	// This marks the end of message
	}

void HTTP_Message::SubmitEvent(int event_type, const char* detail)
	{
	const char* category = "";

	switch ( event_type ) {
	case mime::MIME_EVENT_ILLEGAL_FORMAT:
		category = "illegal format";
		break;

	case mime::MIME_EVENT_ILLEGAL_ENCODING:
		category = "illegal encoding";
		break;

	case mime::MIME_EVENT_CONTENT_GAP:
		category = "content gap";
		break;

	default:
		reporter->AnalyzerError(MyHTTP_Analyzer(),
		                                "unrecognized HTTP message event");
		return;
	}

	MyHTTP_Analyzer()->HTTP_Event(category, detail);
	}

void HTTP_Message::SetPlainDelivery(int64_t length)
	{
	content_line->SetPlainDelivery(length);

	if ( length > 0 && BifConst::skip_http_data )
		content_line->SkipBytesAfterThisLine(length);
	}

void HTTP_Message::SkipEntityData()
	{
	if ( current_entity )
		current_entity->SkipBody();
	}

void HTTP_Message::Weird(const char* msg)
	{
	analyzer->Weird(msg);
	}

HTTP_Analyzer::HTTP_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("HTTP", conn)
	{
	num_requests = num_replies = 0;
	num_request_lines = num_reply_lines = 0;
	request_version = reply_version = 0.0;	// unknown version
	keep_alive = 0;
	connection_close = 0;

	request_message = reply_message = 0;
	request_state = EXPECT_REQUEST_LINE;
	reply_state = EXPECT_REPLY_LINE;

	request_ongoing = 0;
	request_method = request_URI = 0;
	unescaped_URI = 0;

	reply_ongoing = 0;
	reply_code = 0;
	reply_reason_phrase = 0;

	connect_request = false;
	pia = 0;
	upgraded = false;
	upgrade_connection = false;
	upgrade_protocol.clear();

	content_line_orig = new tcp::ContentLine_Analyzer(conn, true);
	AddSupportAnalyzer(content_line_orig);

	content_line_resp = new tcp::ContentLine_Analyzer(conn, false);
	content_line_resp->SetSkipPartial(true);
	AddSupportAnalyzer(content_line_resp);
	}

HTTP_Analyzer::~HTTP_Analyzer()
	{
	Unref(request_method);
	Unref(request_URI);
	Unref(unescaped_URI);
	Unref(reply_reason_phrase);
	}

void HTTP_Analyzer::Done()
	{
	if ( IsFinished() )
		return;

	tcp::TCP_ApplicationAnalyzer::Done();

	RequestMade(1, "message interrupted when connection done");
	ReplyMade(1, "message interrupted when connection done");

	delete request_message;
	request_message = 0;

	delete reply_message;
	reply_message = 0;

	GenStats();

	while ( ! unanswered_requests.empty() )
		{
		Unref(unanswered_requests.front());
		unanswered_requests.pop();
		}

	file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), true);

	/* TODO: this might be nice to have, but reply code is cleared by now.
	if ( HTTP_ReplyCode() != 206 )
		// multipart/byteranges may span multiple connections
		file_mgr->EndOfFile(GetAnalyzerTag(), Conn(), false);
	*/
	}

void HTTP_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( TCP() && TCP()->IsPartial() )
		return;

	if ( upgraded )
		return;

	if ( pia )
		{
		// There will be a PIA instance if this connection has been identified
		// as a connect proxy.
		ForwardStream(len, data, is_orig);
		return;
		}

	const char* line = reinterpret_cast<const char*>(data);
	const char* end_of_line = line + len;

	tcp::ContentLine_Analyzer* content_line =
		is_orig ? content_line_orig : content_line_resp;

	if ( content_line->IsPlainDelivery() )
		{
		if ( is_orig )
			{
			if ( request_message )
				request_message->Deliver(len, line, 0);
			else
				Weird("unexpected_client_HTTP_data");
			}
		else
			{
			if ( reply_message )
				reply_message->Deliver(len, line, 0);
			else
				Weird("unexpected_server_HTTP_data");
			}
		return;
		}

	// HTTP_Event("HTTP line", new_string_val(length, line));

	if ( is_orig )
		{
		++num_request_lines;

		switch ( request_state ) {
		case EXPECT_REQUEST_LINE:
			{
			int res = HTTP_RequestLine(line, end_of_line);

			if ( res < 0 )
				return;

			else if ( res > 0 )
				{
				++num_requests;

				if ( ! keep_alive && num_requests > 1 )
					Weird("unexpected_multiple_HTTP_requests");

				request_state = EXPECT_REQUEST_MESSAGE;
				request_ongoing = 1;
				unanswered_requests.push(request_method->Ref());
				HTTP_Request();
				InitHTTPMessage(content_line, request_message,
						is_orig, HTTP_BODY_MAYBE, len);
				}

			else
				{
				if ( ! RequestExpected() )
					HTTP_Event("crud_trailing_HTTP_request",
						   mime::new_string_val(line, end_of_line));
				else
					{
					// We do see HTTP requests with a
					// trailing EOL that's not accounted
					// for by the content-length. This
					// will lead to a call to this method
					// with len==0 while we are expecting
					// a new request. Since HTTP servers
					// handle such requests gracefully,
					// we should do so as well.
					if ( len == 0 )
					    Weird("empty_http_request");
					else
						{
						ProtocolViolation("not a http request line");
						request_state = EXPECT_REQUEST_NOTHING;
						}
					}
				}
			}
			break;

		case EXPECT_REQUEST_MESSAGE:
			request_message->Deliver(len, line, 1);
			break;

		case EXPECT_REQUEST_TRAILER:
			break;

		case EXPECT_REQUEST_NOTHING:
			break;
		}
		}
	else
		{ // HTTP reply
		switch ( reply_state ) {
		case EXPECT_REPLY_LINE:
			if ( HTTP_ReplyLine(line, end_of_line) )
				{
				++num_replies;

				if ( ! unanswered_requests.empty() )
					ProtocolConfirmation();

				reply_state = EXPECT_REPLY_MESSAGE;
				reply_ongoing = 1;

				HTTP_Reply();

				if ( connect_request && reply_code != 200 )
					// Request failed, do not set up tunnel.
					connect_request = false;

				InitHTTPMessage(content_line,
						reply_message, is_orig,
						ExpectReplyMessageBody(),
						len);
				}
			else
				{
				if ( line != end_of_line )
					{
					ProtocolViolation("not a http reply line");
					reply_state = EXPECT_REPLY_NOTHING;
					}
				}

			break;

		case EXPECT_REPLY_MESSAGE:
			reply_message->Deliver(len, line, 1);

			if ( connect_request && len == 0 )
				{
				// End of message header reached, set up
				// tunnel decapsulation.
				pia = new pia::PIA_TCP(Conn());

				if ( AddChildAnalyzer(pia) )
					{
					pia->FirstPacket(true, 0);
					pia->FirstPacket(false, 0);

					// This connection has transitioned to no longer
					// being http and the content line support analyzers
					// need to be removed.
					RemoveSupportAnalyzer(content_line_orig);
					RemoveSupportAnalyzer(content_line_resp);
					}

				else
					// AddChildAnalyzer() will have deleted PIA.
					pia = 0;
				}

			break;

		case EXPECT_REPLY_TRAILER:
			break;

		case EXPECT_REPLY_NOTHING:
			break;
		}
		}
	}

void HTTP_Analyzer::Undelivered(uint64 seq, int len, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

	// DEBUG_MSG("Undelivered from %"PRIu64": %d bytes\n", seq, length);

	HTTP_Message* msg =
		is_orig ? request_message : reply_message;

	tcp::ContentLine_Analyzer* content_line =
		is_orig ? content_line_orig : content_line_resp;

	if ( ! content_line->IsSkippedContents(seq, len) )
		{
		if ( msg )
			msg->SubmitEvent(mime::MIME_EVENT_CONTENT_GAP,
				fmt("seq=%" PRIu64", len=%d", seq, len));
		}

	// Check if the content gap falls completely within a message body
	if ( msg && msg->Undelivered(len) )
		// If so, we are safe to skip the content and go on parsing
		return;

	// Otherwise stop parsing the connection
	if ( is_orig )
		{
		// Stop parsing reply messages too, because whether a
		// reply contains a body may depend on knowing the
		// request method

		RequestMade(1, "message interrupted by a content gap");
		ReplyMade(1, "message interrupted by a content gap");

		content_line->SetSkipDeliveries(1);
		content_line->SetSkipDeliveries(1);
		}
	else
		{
		ReplyMade(1, "message interrupted by a content gap");
		content_line->SetSkipDeliveries(1);
		}
	}

void HTTP_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);

	// DEBUG_MSG("%.6f eof\n", network_time);

	if ( is_orig )
		RequestMade(0, "message ends as connection contents are completely delivered");
	else
		ReplyMade(0, "message ends as connection contents are completely delivered");
	}

void HTTP_Analyzer::ConnectionFinished(int half_finished)
	{
	tcp::TCP_ApplicationAnalyzer::ConnectionFinished(half_finished);

	// DEBUG_MSG("%.6f connection finished\n", network_time);
	RequestMade(1, "message ends as connection is finished");
	ReplyMade(1, "message ends as connection is finished");
	}

void HTTP_Analyzer::ConnectionReset()
	{
	tcp::TCP_ApplicationAnalyzer::ConnectionReset();

	RequestMade(1, "message interrupted by RST");
	ReplyMade(1, "message interrupted by RST");
	}

void HTTP_Analyzer::PacketWithRST()
	{
	tcp::TCP_ApplicationAnalyzer::PacketWithRST();

	RequestMade(1, "message interrupted by RST");
	ReplyMade(1, "message interrupted by RST");
	}

void HTTP_Analyzer::GenStats()
	{
	if ( http_stats )
		{
		RecordVal* r = new RecordVal(http_stats_rec);
		r->Assign(0, new Val(num_requests, TYPE_COUNT));
		r->Assign(1, new Val(num_replies, TYPE_COUNT));
		r->Assign(2, new Val(request_version, TYPE_DOUBLE));
		r->Assign(3, new Val(reply_version, TYPE_DOUBLE));

		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(r);

		// DEBUG_MSG("%.6f http_stats\n", network_time);
		ConnectionEvent(http_stats, vl);
		}
	}

const char* HTTP_Analyzer::PrefixMatch(const char* line,
				const char* end_of_line, const char* prefix)
	{
	while ( *prefix && line < end_of_line && *prefix == *line )
		{
		++prefix;
		++line;
		}

	if ( *prefix )
		// It didn't match.
		return 0;

	return line;
	}

const char* HTTP_Analyzer::PrefixWordMatch(const char* line,
				const char* end_of_line, const char* prefix)
	{
	if ( (line = PrefixMatch(line, end_of_line, prefix)) == 0 )
		return 0;

	const char* orig_line = line;
	line = skip_whitespace(line, end_of_line);

	if ( line == orig_line )
		// Word didn't end at prefix.
		return 0;

	return line;
	}

static bool is_HTTP_token_char(char c)
	{
	return c > 31 && c != 127 &&      // CTL per RFC 2616.
	        c != ' ' && c != '\t' &&  // Separators.
		c != '(' && c != ')' && c != '<' && c != '>' && c != '@' &&
		c != ',' && c != ';' && c != ':' && c != '\\' && c != '"' &&
		c != '/' && c != '[' && c != ']' && c != '?' && c != '=' &&
		c != '{' && c != '}';
	}

static const char* get_HTTP_token(const char* s, const char* e)
	{
	while ( s < e && is_HTTP_token_char(*s) )
		++s;

	return s;
	}


int HTTP_Analyzer::HTTP_RequestLine(const char* line, const char* end_of_line)
	{
	const char* rest = 0;
	const char* end_of_method = get_HTTP_token(line, end_of_line);

	if ( end_of_method == line )
		{
		// something went wrong with get_HTTP_token
		// perform a weak test to see if the string "HTTP/"
		// is found at the end of the RequestLine
		if ( end_of_line - 9 >= line && strncasecmp(end_of_line - 9, " HTTP/", 6) == 0 )
			goto bad_http_request_with_version;

		goto error;
	}

	rest = skip_whitespace(end_of_method, end_of_line);

	if ( rest == end_of_method )
		goto error;

	request_method = new StringVal(end_of_method - line, line);

	if ( ! ParseRequest(rest, end_of_line) )
		{
		reporter->AnalyzerError(this, "HTTP ParseRequest failed");
		return -1;
		}

	Conn()->Match(Rule::HTTP_REQUEST,
			(const u_char*) unescaped_URI->AsString()->Bytes(),
			unescaped_URI->AsString()->Len(), true, true, true, true);

	return 1;

bad_http_request_with_version:
	reporter->Weird(Conn(), "bad_HTTP_request_with_version");
	return 0;

error:
	reporter->Weird(Conn(), "bad_HTTP_request");
	return 0;
	}

int HTTP_Analyzer::ParseRequest(const char* line, const char* end_of_line)
	{
	const char* end_of_uri;
	const char* version_start;
	const char* version_end;

	for ( end_of_uri = line; end_of_uri < end_of_line; ++end_of_uri )
		{
		if ( ! is_reserved_URI_char(*end_of_uri) &&
		     ! is_unreserved_URI_char(*end_of_uri) &&
		     *end_of_uri != '%' )
			break;
		}

	if ( end_of_uri >= end_of_line && PrefixMatch(line, end_of_line, "HTTP/") )
		{
		Weird("missing_HTTP_uri");
		end_of_uri = line; // Leave URI empty.
		}

	for ( version_start = end_of_uri; version_start < end_of_line; ++version_start )
		{
		end_of_uri = version_start;
		version_start = skip_whitespace(version_start, end_of_line);
		if ( PrefixMatch(version_start, end_of_line, "HTTP/") )
			break;
		}

	if ( version_start >= end_of_line )
		{
		// If no version is found
		SetVersion(request_version, 0.9);
		}
	else
		{
		if ( version_start + 8 <= end_of_line )
			{
			version_start += 5; // "HTTP/"
			SetVersion(request_version,
					HTTP_Version(end_of_line - version_start,
							version_start));

			version_end = version_start + 3;
			if ( skip_whitespace(version_end, end_of_line) != end_of_line )
				HTTP_Event("crud after HTTP version is ignored",
					   mime::new_string_val(line, end_of_line));
			}
		else
			HTTP_Event("bad_HTTP_version", mime::new_string_val(line, end_of_line));
		}

	// NormalizeURI(line, end_of_uri);

	request_URI = new StringVal(end_of_uri - line, line);
	unescaped_URI = new StringVal(unescape_URI((const u_char*) line,
					(const u_char*) end_of_uri, this));

	return 1;
	}

// Only recognize [0-9][.][0-9].
double HTTP_Analyzer::HTTP_Version(int len, const char* data)
	{
	if ( len >= 3 &&
	     data[0] >= '0' && data[0] <= '9' &&
	     data[1] == '.' &&
	     data[2] >= '0' && data[2] <= '9' )
		{
		return double(data[0] - '0') + 0.1 * double(data[2] - '0');
		}
	else
		{
	        HTTP_Event("bad_HTTP_version", mime::new_string_val(len, data));
		return 0;
		}
	}

void HTTP_Analyzer::SetVersion(double& version, double new_version)
	{
	if ( version == 0.0 )
		version = new_version;

	else if ( version != new_version )
		Weird("HTTP_version_mismatch");

	if ( version > 1.05 )
		keep_alive = 1;
	}

void HTTP_Analyzer::HTTP_Event(const char* category, const char* detail)
	{
	HTTP_Event(category, new StringVal(detail));
	}

void HTTP_Analyzer::HTTP_Event(const char* category, StringVal* detail)
	{
	if ( http_event )
		{
		val_list* vl = new val_list();
		vl->append(BuildConnVal());
		vl->append(new StringVal(category));
		vl->append(detail);

		// DEBUG_MSG("%.6f http_event\n", network_time);
		ConnectionEvent(http_event, vl);
		}
	else
		delete detail;
	}

StringVal* HTTP_Analyzer::TruncateURI(StringVal* uri)
	{
	const BroString* str = uri->AsString();

	if ( truncate_http_URI >= 0 && str->Len() > truncate_http_URI )
		{
		u_char* s = new u_char[truncate_http_URI + 4];
		memcpy(s, str->Bytes(), truncate_http_URI);
		memcpy(s + truncate_http_URI, "...", 4);
		return new StringVal(new BroString(1, s, truncate_http_URI+3));
		}
	else
		{
		Ref(uri);
		return uri;
		}
	}

void HTTP_Analyzer::HTTP_Request()
	{
	ProtocolConfirmation();

	const char* method = (const char*) request_method->AsString()->Bytes();
	int method_len = request_method->AsString()->Len();

	if ( strncasecmp(method, "CONNECT", method_len) == 0 )
		connect_request = true;

	if ( http_request )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());

		Ref(request_method);
		vl->append(request_method);
		vl->append(TruncateURI(request_URI->AsStringVal()));
		vl->append(TruncateURI(unescaped_URI->AsStringVal()));

		vl->append(new StringVal(fmt("%.1f", request_version)));
		// DEBUG_MSG("%.6f http_request\n", network_time);
		ConnectionEvent(http_request, vl);
		}
	}

void HTTP_Analyzer::HTTP_Reply()
	{
	if ( http_reply )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new StringVal(fmt("%.1f", reply_version)));
		vl->append(new Val(reply_code, TYPE_COUNT));
		if ( reply_reason_phrase )
			vl->append(reply_reason_phrase->Ref());
		else
			vl->append(new StringVal("<empty>"));
		ConnectionEvent(http_reply, vl);
		}
	else
		{
		Unref(reply_reason_phrase);
		reply_reason_phrase = 0;
		}
	}

void HTTP_Analyzer::RequestMade(const int interrupted, const char* msg)
	{
	if ( ! request_ongoing )
		return;

	request_ongoing = 0;

	if ( request_message )
		request_message->Done(interrupted, msg);

	// DEBUG_MSG("%.6f request made\n", network_time);

	Unref(request_method);
	Unref(unescaped_URI);
	Unref(request_URI);

	request_method = request_URI = unescaped_URI = 0;

	num_request_lines = 0;

	if ( interrupted )
		request_state = EXPECT_REQUEST_NOTHING;
	else
		request_state = EXPECT_REQUEST_LINE;
	}

void HTTP_Analyzer::ReplyMade(const int interrupted, const char* msg)
	{
	if ( ! reply_ongoing )
		return;

	reply_ongoing = 0;

	// DEBUG_MSG("%.6f reply made\n", network_time);

	if ( reply_message )
		reply_message->Done(interrupted, msg);

	// 1xx replies do not indicate the final response to a request,
	// so don't pop an unanswered request in that case.
	if ( (reply_code < 100 || reply_code >= 200) && ! unanswered_requests.empty() )
		{
		Unref(unanswered_requests.front());
		unanswered_requests.pop();
		}

	if ( reply_reason_phrase )
		{
		Unref(reply_reason_phrase);
		reply_reason_phrase = 0;
		}

	// unanswered requests = 1 because there is no pop after 101.
	if ( reply_code == 101 && unanswered_requests.size() == 1 && upgrade_connection &&
	     upgrade_protocol.size() )
		{
		// Upgraded connection that switches immediately - e.g. websocket.
		upgraded = true;
		RemoveSupportAnalyzer(content_line_orig);
		RemoveSupportAnalyzer(content_line_resp);

		if ( http_connection_upgrade )
			{
			val_list* vl = new val_list();
			vl->append(BuildConnVal());
			vl->append(new StringVal(upgrade_protocol));
			ConnectionEvent(http_connection_upgrade, vl);
			}
		}

	reply_code = 0;
	upgrade_connection = false;
	upgrade_protocol.clear();

	if ( interrupted || upgraded )
		reply_state = EXPECT_REPLY_NOTHING;
	else
		reply_state = EXPECT_REPLY_LINE;
	}

void HTTP_Analyzer::RequestClash(Val* /* clash_val */)
	{
	Weird("multiple_HTTP_request_elements");

	// Flush out old values.
	RequestMade(1, "request clash");
	}

const BroString* HTTP_Analyzer::UnansweredRequestMethod()
	{
	return unanswered_requests.empty() ? 0 : unanswered_requests.front()->AsString();
	}

int HTTP_Analyzer::HTTP_ReplyLine(const char* line, const char* end_of_line)
	{
	const char* rest;

	if ( ! (rest = PrefixMatch(line, end_of_line, "HTTP/")) )
		{
		// ##TODO: some server replies with an HTML document
		// without a status line and a MIME header, when the
		// request is malformed.
		HTTP_Event("bad_HTTP_reply", mime::new_string_val(line, end_of_line));
		return 0;
		}

	SetVersion(reply_version, HTTP_Version(end_of_line - rest, rest));

	for ( ; rest < end_of_line; ++rest )
		if ( mime::is_lws(*rest) )
			break;

	if ( rest >= end_of_line )
		{
		HTTP_Event("HTTP_reply_code_missing",
				mime::new_string_val(line, end_of_line));
		return 0;
		}

	rest = skip_whitespace(rest, end_of_line);

	if ( rest + 3 > end_of_line )
		{
		HTTP_Event("HTTP_reply_code_missing",
			mime::new_string_val(line, end_of_line));
		return 0;
		}

	reply_code = HTTP_ReplyCode(rest);

	for ( rest += 3; rest < end_of_line; ++rest )
		if ( mime::is_lws(*rest) )
			break;

	if ( rest >= end_of_line )
		{
		HTTP_Event("HTTP_reply_reason_phrase_missing",
			mime::new_string_val(line, end_of_line));
		// Tolerate missing reason phrase?
		return 1;
		}

	rest = skip_whitespace(rest, end_of_line);
	reply_reason_phrase =
		new StringVal(end_of_line - rest, (const char *) rest);

	return 1;
	}

int HTTP_Analyzer::HTTP_ReplyCode(const char* code_str)
	{
	if ( isdigit(code_str[0]) && isdigit(code_str[1]) && isdigit(code_str[2]) )
		return	(code_str[0] - '0') * 100 +
			(code_str[1] - '0') * 10 +
			(code_str[2] - '0');
	else
		return 0;
	}

int HTTP_Analyzer::ExpectReplyMessageBody()
	{
	// RFC 2616:
	//
	//     For response messages, whether or not a message-body is included with
	//     a message is dependent on both the request method and the response
	//     status code (section 6.1.1). All responses to the HEAD request method
	//     MUST NOT include a message-body, even though the presence of entity-
	//     header fields might lead one to believe they do. All 1xx
	//     (informational), 204 (no content), and 304 (not modified) responses
	//     MUST NOT include a message-body. All other responses do include a
	//     message-body, although it MAY be of zero length.

	const BroString* method = UnansweredRequestMethod();

	if ( method && strncasecmp((const char*) (method->Bytes()), "HEAD", method->Len()) == 0 )
		return HTTP_BODY_NOT_EXPECTED;

	if ( (reply_code >= 100 && reply_code < 200) ||
	     reply_code == 204 || reply_code == 304 )
		return HTTP_BODY_NOT_EXPECTED;

	return HTTP_BODY_EXPECTED;
	}

void HTTP_Analyzer::HTTP_Header(int is_orig, mime::MIME_Header* h)
	{
#if 0
	// ### Only call ParseVersion if we're tracking versions:
	if ( istrequal(h->get_name(), "server") )
		ParseVersion(h->get_value(),
				(is_orig ? Conn()->OrigAddr() : Conn()->RespAddr()), false);

	else if ( istrequal(h->get_name(), "user-agent") )
		ParseVersion(h->get_value(),
				(is_orig ? Conn()->OrigAddr() : Conn()->RespAddr()), true);
#endif

	// To be "liberal", we only look at "keep-alive" on the client
	// side, and if seen assume the connection to be persistent.
	// This seems fairly safe - at worst, the client does indeed
	// send additional requests, and the server ignores them.
	if ( is_orig && mime::istrequal(h->get_name(), "connection") )
		{
		if ( mime::istrequal(h->get_value_token(), "keep-alive") )
			keep_alive = 1;
		}

	if ( ! is_orig &&
	     mime::istrequal(h->get_name(), "connection") )
		{
		if ( mime::istrequal(h->get_value_token(), "close") )
			connection_close = 1;
		else if ( mime::istrequal(h->get_value_token(), "upgrade") )
			upgrade_connection = true;
		}

	if ( ! is_orig &&
	     mime::istrequal(h->get_name(), "upgrade") )
	     upgrade_protocol.assign(h->get_value_token().data, h->get_value_token().length);

	if ( http_header )
		{
		Rule::PatternType rule =
			is_orig ?  Rule::HTTP_REQUEST_HEADER :
					Rule::HTTP_REPLY_HEADER;

		data_chunk_t hd_name = h->get_name();
		data_chunk_t hd_value = h->get_value();

		Conn()->Match(rule, (const u_char*) hd_name.data, hd_name.length,
				is_orig, true, false, true);
		Conn()->Match(rule, (const u_char*) ": ", 2, is_orig,
				false, false, false);
		Conn()->Match(rule, (const u_char*) hd_value.data, hd_value.length,
				is_orig, false, true, false);

		val_list* vl = new val_list();
		vl->append(BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(mime::new_string_val(h->get_name())->ToUpper());
		vl->append(mime::new_string_val(h->get_value()));
		if ( DEBUG_http )
			DEBUG_MSG("%.6f http_header\n", network_time);
		ConnectionEvent(http_header, vl);
		}
	}

void HTTP_Analyzer::ParseVersion(data_chunk_t ver, const IPAddr& host,
				bool user_agent)
	{
	int len = ver.length;
	const char* data = ver.data;

	if ( software_unparsed_version_found )
		Conn()->UnparsedVersionFoundEvent(host, data, len, this);

	// The RFC defines:
	//
	//	product		= token ["/" product-version]
	//	product-version = token
	//	Server		= "Server" ":" 1*( product | comment )

	int offset;
	data_chunk_t product, product_version;
	int num_version = 0;

	while ( len > 0 )
		{
		// Skip white space.
		while ( len && mime::is_lws(*data) )
			{
			++data;
			--len;
			}

		// See if a comment is coming next. For User-Agent,
		// we parse it, too.
		if ( user_agent && len && *data == '(' )
			{
			// Find end of comment.
			const char* data_start = data;
			const char* eoc =
				data + mime::MIME_skip_lws_comments(len, data);

			// Split into parts.
			// (This may get confused by nested comments,
			// but we ignore this for now.)
			const char* eot;
			++data;
			while ( 1 )
				{
				// Eat spaces.
				while ( data < eoc && mime::is_lws(*data) )
					++data;

				// Find end of token.
				for ( eot = data;
				      eot < eoc && *eot != ';' && *eot != ')';
				      ++eot )
					;

				if ( eot == eoc )
					break;

				// Delete spaces at end of token.
				for ( ; eot > data && mime::is_lws(*(eot-1)); --eot )
					;

				if ( data != eot && software_version_found )
					Conn()->VersionFoundEvent(host, data, eot - data, this);
				data = eot + 1;
				}

			len -= eoc - data_start;
			data = eoc;
			continue;
			}

		offset = mime::MIME_get_slash_token_pair(len, data,
						&product, &product_version);
		if ( offset < 0 )
			{
			// I guess version detection is best-effort,
			// so we do not complain in the final version
			if ( num_version == 0 )
				HTTP_Event("bad_HTTP_version",
						mime::new_string_val(len, data));

			// Try to simply skip next token.
			offset = mime::MIME_get_token(len, data, &product);
			if ( offset < 0 )
				break;

			len -= offset;
			data += offset;
			}

		else
			{
			len -= offset;
			data += offset;

			int version_len =
				product.length + 1 + product_version.length;

			char* version_str = new char[version_len+1];
			char* s = version_str;

			memcpy(s, product.data, product.length);

			s += product.length;
			*(s++) = '/';

			memcpy(s, product_version.data, product_version.length);

			s += product_version.length;
			*s = 0;

			if ( software_version_found )
				Conn()->VersionFoundEvent(host,	version_str,
							version_len, this);

			delete [] version_str;
			++num_version;
			}
		}
	}

void HTTP_Analyzer::HTTP_EntityData(int is_orig, BroString* entity_data)
	{
	if ( http_entity_data )
		{
		val_list* vl = new val_list();
		vl->append(BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(new Val(entity_data->Len(), TYPE_COUNT));
		vl->append(new StringVal(entity_data));
		ConnectionEvent(http_entity_data, vl);
		}
	else
		delete entity_data;
	}

// Calls request/reply done
void HTTP_Analyzer::HTTP_MessageDone(int is_orig, HTTP_Message* /* message */)
	{
	if ( is_orig )
		RequestMade(0, "message ends normally");
	else
		ReplyMade(0, "message ends normally");
	}

void HTTP_Analyzer::InitHTTPMessage(tcp::ContentLine_Analyzer* cl, HTTP_Message*& message,
		bool is_orig, int expect_body, int64_t init_header_length)
	{
	if ( message )
		{
		if ( ! message->Finished() )
			Weird("HTTP_overlapping_messages");

		delete message;
		}

	// DEBUG_MSG("%.6f init http message\n", network_time);
	message = new HTTP_Message(this, cl, is_orig, expect_body,
					init_header_length);
	}

void HTTP_Analyzer::SkipEntityData(int is_orig)
	{
	HTTP_Message* msg = is_orig ? request_message : reply_message;

	if ( msg )
		msg->SkipEntityData();
	}

int analyzer::http::is_reserved_URI_char(unsigned char ch)
	{ // see RFC 3986 (definition of URI)
	return strchr(":/?#[]@!$&'()*+,;=", ch) != 0;
	}

int analyzer::http::is_unreserved_URI_char(unsigned char ch)
	{ // see RFC 3986 (definition of URI)
	return isalnum(ch) || strchr("-_.!~*\'()", ch) != 0;
	}

void analyzer::http::escape_URI_char(unsigned char ch, unsigned char*& p)
	{
	*p++ = '%';
	*p++ = encode_hex((ch >> 4) & 0xf);
	*p++ = encode_hex(ch & 0xf);
	}

BroString* analyzer::http::unescape_URI(const u_char* line, const u_char* line_end,
			analyzer::Analyzer* analyzer)
	{
	byte_vec decoded_URI = new u_char[line_end - line + 1];
	byte_vec URI_p = decoded_URI;

	while ( line < line_end )
		{
		if ( *line == '%' )
			{
			++line;

			if ( line == line_end )
				{
				*URI_p++ = '%';
				if ( analyzer )
					analyzer->Weird("illegal_%_at_end_of_URI");
				break;
				}

			else if ( line + 1 == line_end )
				{
				// % + one character at end of line. Log weird
				// and just add to unescpaped URI.
				*URI_p++ = '%';
				*URI_p++ = *line;
				if ( analyzer )
					analyzer->Weird("partial_escape_at_end_of_URI");
				break;
				}

			else if ( *line == '%' )
				{
				// Double '%' might be either due to
				// software bug, or more likely, an
				// evasion (e.g. used by Nimda).
				// *URI_p++ = '%';
				if ( analyzer )
					analyzer->Weird("double_%_in_URI");
				--line;	// ignore the first '%'
				}

			else if ( isxdigit(line[0]) && isxdigit(line[1]) )
				{
				*URI_p++ = (decode_hex(line[0]) << 4) +
					   decode_hex(line[1]);
				++line; // place line at the last hex digit
				}

			else if ( line_end - line >= 5 &&
			          line[0] == 'u' &&
			          isxdigit(line[1]) &&
			          isxdigit(line[2]) &&
			          isxdigit(line[3]) &&
			          isxdigit(line[4]) )
				{
				// Decode escaping like this: %u00AE
				// The W3C rejected escaping this way, and
				// there is no RFC that specifies it.
				// Appparently there is some software doing
				// this sort of 4 byte unicode encoding anyway.
				// Likely causing an increase in it's use is
				// the third edition of the ECMAScript spec
				// having functions for encoding and decoding
				// data in this format.

				// If the first byte is null, let's eat it.
				// It could just be ASCII encoded into this
				// unicode escaping structure.
				if ( ! (line[1] == '0' && line[2] == '0' ) )
					*URI_p++ = (decode_hex(line[1]) << 4) +
					            decode_hex(line[2]);

				*URI_p++ = (decode_hex(line[3]) << 4) +
					    decode_hex(line[4]);

				line += 4;
				}

			else
				{
				if ( analyzer )
					analyzer->Weird("unescaped_%_in_URI");
				*URI_p++ = '%';	// put back initial '%'
				*URI_p++ = *line;	// take char w/o interp.
				}
			}

		else
			*URI_p++ = *line;

		++line;
		}

	URI_p[0] = 0;

	return new BroString(1, decoded_URI, URI_p - decoded_URI);
	}
