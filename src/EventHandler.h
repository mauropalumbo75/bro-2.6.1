// Capsulates local and remote event handlers.

#ifndef EVENTHANDLER
#define EVENTHANDLER

#include <assert.h>
#include <unordered_set>
#include <string>
#include "List.h"
#include "BroList.h"

class Func;
class FuncType;
class Serializer;
class SerialInfo;
class UnserialInfo;

class EventHandler {
public:
	explicit EventHandler(const char* name);
	~EventHandler();

	const char* Name()	{ return name; }
	Func* LocalHandler()	{ return local; }
	FuncType* FType(bool check_export = true);

	void SetLocalHandler(Func* f);

	void AddRemoteHandler(SourceID peer);
	void RemoveRemoteHandler(SourceID peer);

	void AutoPublish(std::string topic)
		{
		auto_publish.insert(std::move(topic));
		}

	void AutoUnpublish(const std::string& topic)
		{
		auto_publish.erase(topic);
		}

	void Call(val_list* vl, bool no_remote = false);

	// Returns true if there is at least one local or remote handler.
	explicit operator  bool() const;

	void SetUsed()	{ used = true; }
	bool Used()	{ return used; }

	// Handlers marked as error handlers will not be called recursively to
	// avoid infinite loops if they trigger a similar error themselves.
	void SetErrorHandler()	{ error_handler = true; }
	bool ErrorHandler()	{ return error_handler; }

	void SetEnable(bool arg_enable)	{ enabled = arg_enable; }

	// Flags the event as interesting even if there is no body defined. In
	// particular, this will then still pass the event on to plugins.
	void SetGenerateAlways()	{ generate_always = true; }
	bool GenerateAlways()	{ return generate_always; }

	// We don't serialize the handler(s) itself here, but
	// just the reference to it.
	bool Serialize(SerialInfo* info) const;
	static EventHandler* Unserialize(UnserialInfo* info);

private:
	void NewEvent(val_list* vl);	// Raise new_event() meta event.

	const char* name;
	Func* local;
	FuncType* type;
	bool used;		// this handler is indeed used somewhere
	bool enabled;
	bool error_handler;	// this handler reports error messages.
	bool generate_always;

	declare(List, SourceID);
	typedef List(SourceID) receiver_list;
	receiver_list receivers;

	std::unordered_set<std::string> auto_publish;
};

// Encapsulates a ptr to an event handler to overload the boolean operator.
class EventHandlerPtr {
public:
	EventHandlerPtr(EventHandler* p = 0)		{ handler = p; }
	EventHandlerPtr(const EventHandlerPtr& h)	{ handler = h.handler; }

	const EventHandlerPtr& operator=(EventHandler* p)
		{ handler = p; return *this; }
	const EventHandlerPtr& operator=(const EventHandlerPtr& h)
		{ handler = h.handler; return *this; }

	bool operator==(const EventHandlerPtr& h) const
		{ return handler == h.handler; }

	EventHandler* Ptr()	{ return handler; }

	explicit operator bool() const	{ return handler && *handler; }
	EventHandler* operator->()	{ return handler; }
	const EventHandler* operator->() const	{ return handler; }

private:
	EventHandler* handler;
};

#endif
