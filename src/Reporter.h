// See the file "COPYING" in the main distribution directory for copyright.

#ifndef REPORTER_H
#define REPORTER_H

#include <stdarg.h>

#include <list>
#include <utility>
#include <string>
#include <map>
#include <unordered_set>
#include <unordered_map>

#include "util.h"
#include "EventHandler.h"
#include "IPAddr.h"

namespace analyzer { class Analyzer; }
class Connection;
class Location;
class Reporter;

// One cannot raise this exception directly, go through the
// Reporter's methods instead.

class ReporterException {
protected:
	friend class Reporter;
	ReporterException()	{}
};

class InterpreterException : public ReporterException {
protected:
	friend class Reporter;
	InterpreterException()	{}
};

#define FMT_ATTR __attribute__((format(printf, 2, 3))) // sic! 1st is "this" I guess.

class Reporter {
public:
	using IPPair = std::pair<IPAddr, IPAddr>;
	using WeirdCountMap = std::unordered_map<std::string, uint64>;
	using WeirdFlowMap = std::map<IPPair, WeirdCountMap>;
	using WeirdSet = std::unordered_set<std::string>;

	Reporter();
	~Reporter();

	// Initialize reporter-sepcific options	that are defined in script-layer.
	void InitOptions();

	// Report an informational message, nothing that needs specific
	// attention.
	void Info(const char* fmt, ...) FMT_ATTR;

	// Report a warning that may indicate a problem.
	void Warning(const char* fmt, ...) FMT_ATTR;

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	void Error(const char* fmt, ...) FMT_ATTR;

	// Returns the number of errors reported so far.
	int Errors()	{ return errors; }

	// Report a fatal error. Bro will terminate after the message has been
	// reported.
	void FatalError(const char* fmt, ...) FMT_ATTR;

	// Report a fatal error. Bro will terminate after the message has been
	// reported and always generate a core dump.
	void FatalErrorWithCore(const char* fmt, ...) FMT_ATTR;

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	void ExprRuntimeError(const Expr* expr, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	void RuntimeError(const Location* location, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

	// Report a traffic weirdness, i.e., an unexpected protocol situation
	// that may lead to incorrectly processing a connnection.
	void Weird(const char* name);	// Raises net_weird().
	void Weird(Connection* conn, const char* name, const char* addl = "");	// Raises conn_weird().
	void Weird(const IPAddr& orig, const IPAddr& resp, const char* name);	// Raises flow_weird().

	// Syslog a message. This methods does nothing if we're running
	// offline from a trace.
	void Syslog(const char* fmt, ...) FMT_ATTR;

	// Report about a potential internal problem. Bro will continue
	// normally.
	void InternalWarning(const char* fmt, ...) FMT_ATTR;

	// Report an internal program error. Bro will terminate with a core
	// dump after the message has been reported.
	void InternalError(const char* fmt, ...) FMT_ATTR;

	// Report an analyzer error. That analyzer will be set to not process
	// any further input, but Bro otherwise continues normally.
	void AnalyzerError(analyzer::Analyzer* a, const char* fmt, ...) __attribute__((format(printf, 3, 4)));;

	// Toggle whether non-fatal messages should be reported through the
	// scripting layer rather on standard output. Fatal errors are always
	// reported via stderr.
	void ReportViaEvents(bool arg_via_events)	 { via_events = arg_via_events; }

	// Associates the given location with subsequent output. We create a
	// stack of location so that the most recent is always the one that
	// will be assumed to be the current one. The pointer must remain
	// valid until the location is popped.
	void PushLocation(const Location* location)
		{ locations.push_back(std::pair<const Location*, const Location*>(location, 0)); }

	void PushLocation(const Location* loc1, const Location* loc2)
		{ locations.push_back(std::pair<const Location*, const Location*>(loc1, loc2)); }

	// Removes the top-most location information from stack.
	void PopLocation()
		{ locations.pop_back(); }

	// Signals that we're entering processing an error handler event.
	void BeginErrorHandler()	{ ++in_error_handler; }

	// Signals that we're done processing an error handler event.
	void EndErrorHandler()	{ --in_error_handler; }

	/**
	 * Reset/cleanup state tracking for a "net" weird.
	 */
	void ResetNetWeird(const std::string& name);

	/**
	 * Reset/cleanup state tracking for a "flow" weird.
	 */
	void ResetFlowWeird(const IPAddr& orig, const IPAddr& resp);

	/**
	 * Return the total number of weirds generated (counts weirds before
	 * any rate-limiting occurs).
	 */
	uint64 GetWeirdCount() const
		{ return weird_count; }

	/**
	 * Return number of weirds generated per weird type/name (counts weirds
	 * before any rate-limiting occurs).
	 */
	const WeirdCountMap& GetWeirdsByType() const
		{ return weird_count_by_type; }

	/**
	 * Gets the weird sampling whitelist.
	 */
	WeirdSet GetWeirdSamplingWhitelist() const
		{
		return weird_sampling_whitelist;
		}

	/**
	 * Sets the weird sampling whitelist.
	 *
	 * @param weird_sampling_whitelist New weird sampling whitelist.
	 */
	void SetWeirdSamplingWhitelist(const WeirdSet& weird_sampling_whitelist)
		{
		this->weird_sampling_whitelist = weird_sampling_whitelist;
		}

	/**
	 * Gets the current weird sampling threshold.
	 *
	 * @return weird sampling threshold.
	 */
	uint64 GetWeirdSamplingThreshold() const
		{
		return weird_sampling_threshold;
		}

	/**
	 * Sets the current weird sampling threshold.
	 *
	 * @param weird_sampling_threshold New weird sampling threshold.
	 */
	void SetWeirdSamplingThreshold(uint64 weird_sampling_threshold)
		{
		this->weird_sampling_threshold = weird_sampling_threshold;
		}

	/**
	 * Gets the current weird sampling rate.
	 *
	 * @return weird sampling rate.
	 */
	uint64 GetWeirdSamplingRate() const
		{
		return weird_sampling_rate;
		}

	/**
	 * Sets the weird sampling rate.
	 *
	 * @param weird_sampling_rate New weird sampling rate.
	 */
	void SetWeirdSamplingRate(uint64 weird_sampling_rate)
		{
		this->weird_sampling_rate = weird_sampling_rate;
		}

	/**
	 * Gets the current weird sampling duration.
	 *
	 * @return weird sampling duration.
	 */
	double GetWeirdSamplingDuration() const
		{
		return weird_sampling_duration;
		}

	/**
	 * Sets the current weird sampling duration. Please note that
	 * this will not delete already running timers.
	 *
	 * @param weird_sampling_duration New weird sampling duration.
	 */
	void SetWeirdSamplingDuration(double weird_sampling_duration)
		{
		this->weird_sampling_duration = weird_sampling_duration;
		}

private:
	void DoLog(const char* prefix, EventHandlerPtr event, FILE* out,
		   Connection* conn, val_list* addl, bool location, bool time,
		   const char* postfix, const char* fmt, va_list ap) __attribute__((format(printf, 10, 0)));

	// The order if addl, name needs to be like that since fmt_name can
	// contain format specifiers
	void WeirdHelper(EventHandlerPtr event, Val* conn_val, const char* addl, const char* fmt_name, ...) __attribute__((format(printf, 5, 6)));;
	void WeirdFlowHelper(const IPAddr& orig, const IPAddr& resp, const char* fmt_name, ...) __attribute__((format(printf, 4, 5)));;
	void UpdateWeirdStats(const char* name);
	inline bool WeirdOnSamplingWhiteList(const char* name)
		{ return weird_sampling_whitelist.find(name) != weird_sampling_whitelist.end(); }
	bool PermitNetWeird(const char* name);
	bool PermitFlowWeird(const char* name, const IPAddr& o, const IPAddr& r);

	int errors;
	bool via_events;
	int in_error_handler;
	bool info_to_stderr;
	bool warnings_to_stderr;
	bool errors_to_stderr;

	std::list<std::pair<const Location*, const Location*> > locations;

	uint64 weird_count;
	WeirdCountMap weird_count_by_type;
	WeirdCountMap net_weird_state;
	WeirdFlowMap flow_weird_state;

	WeirdSet weird_sampling_whitelist;
	uint64 weird_sampling_threshold;
	uint64 weird_sampling_rate;
	double weird_sampling_duration;

};

extern Reporter* reporter;

#endif
