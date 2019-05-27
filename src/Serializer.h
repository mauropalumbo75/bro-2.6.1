#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <map>
#include <list>
#include <pcap.h>

#include "ID.h"
#include "List.h"
#include "Expr.h"
#include "ChunkedIO.h"
#include "SerializationFormat.h"
#include "StateAccess.h"
#include "PriorityQueue.h"
#include "SerialInfo.h"
#include "IP.h"
#include "Timer.h"
#include "iosource/IOSource.h"
#include "Reporter.h"

class SerializationCache;
class SerialInfo;

class Connection;
class Timer;
class Packet;

class Serializer {
public:
	// Currently ID serialization is the only method which may suspend.
	bool Serialize(SerialInfo* info, const ID& id);
	bool Serialize(SerialInfo* info, const char* func, val_list* args);
	bool Serialize(SerialInfo* info, const StateAccess& s);
	bool Serialize(SerialInfo* info, const Connection& c);
	bool Serialize(SerialInfo* info, const Timer& t);
	bool Serialize(SerialInfo* info, const Packet& p);

	// Access to the current cache.
	SerializationCache* Cache()	{ return current_cache; }
	void SetCache(SerializationCache* cache)
		{ current_cache = cache; }

	// Input/output methods.

#define DECLARE_READ(type) \
	bool Read(type* v, const char* tag)	{ return format->Read(v, tag); }

#define DECLARE_WRITE(type) \
	bool Write(type v, const char* tag)	\
		{ return format->Write(v, tag); }

#define DECLARE_IO(type)	\
	DECLARE_READ(type)	\
	DECLARE_WRITE(type)

	DECLARE_IO(int)
	DECLARE_IO(uint16)
	DECLARE_IO(uint32)
	DECLARE_IO(int64)
	DECLARE_IO(uint64)
	DECLARE_IO(char)
	DECLARE_IO(bool)
	DECLARE_IO(double)

	bool Read(char** str, int* len, const char* tag)
		{ return format->Read(str, len, tag); }
	bool Read(const char** str, int* len, const char* tag)
		// This cast is ok.
		{ return format->Read(const_cast<char**>(str), len, tag); }

	bool Read(string* s, const char* tag);
	bool Read(IPAddr* a, const char* tag)	{ return format->Read(a, tag); }
	bool Read(IPPrefix* p, const char* tag)	{ return format->Read(p, tag); }

	bool Write(const char* s, const char* tag)
		{ return format->Write(s, tag); }
	bool Write(const char* buf, int len, const char* tag)
		{ return format->Write(buf, len, tag); }
	bool Write(const string& s, const char* tag)
		{ return format->Write(s.data(), s.size(), tag); }
	bool Write(const IPAddr& a, const char* tag)	{ return format->Write(a, tag); }
	bool Write(const IPPrefix& p, const char* tag)	{ return format->Write(p, tag); }

	bool WriteOpenTag(const char* tag)
		{ return format->WriteOpenTag(tag); }
	bool WriteCloseTag(const char* tag)
		{ return format->WriteCloseTag(tag); }

	bool WriteSeparator()	{ return format->WriteSeparator(); }

	void Error(const char* msg);
	void Warning(const char* msg);

	void SetErrorDescr(const char* descr)
		{ delete [] error_descr; error_descr = copy_string(descr); }

protected:
	// Format defaults to binary serialization.
	explicit Serializer(SerializationFormat* format = 0);
	virtual ~Serializer();

	// Reads next object.
	// If 'block' is true, wait until an object can be read.
	// Returns 0 if no more object available, -1 on error.
	int Unserialize(UnserialInfo* info, bool block = false);

	// Callback for error messages.
	virtual void ReportError(const char* msg) = 0;

	// Callbacks for unserialized objects.

	// id points to ID in global scope, val is unserialized value.
	virtual void GotID(ID* id, Val* val) = 0;
	virtual void GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args) = 0;
	virtual void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args) = 0;
	virtual void GotStateAccess(StateAccess* s) = 0;
	virtual void GotTimer(Timer* t) = 0;
	virtual void GotConnection(Connection* c) = 0;
	virtual void GotPacket(Packet* packet) = 0;

	// Magic to recognize state files.
	static const uint32 MAGIC = 0x42525354;

	// This will be increased whenever there is an incompatible change
	// in the data format.
	static const uint32 DATA_FORMAT_VERSION = 26;

	ChunkedIO* io;

private:
	bool StartSerialization(SerialInfo* info, const char* descr, char tag);
	bool EndSerialization(SerialInfo* info);

	bool UnserializeID(UnserialInfo* info);
	bool UnserializeCall(UnserialInfo* info);
	bool UnserializeStateAccess(UnserialInfo* info);
	bool UnserializeTimer(UnserialInfo* info);
	bool UnserializeConnection(UnserialInfo* info);
	bool UnserializePacket(UnserialInfo* info);

	SerializationFormat* format;
	SerializationCache* current_cache;
	const char* error_descr;	// used in error messages
};



// We maintain an LRU-cache for some of the objects which have already been
// serialized. For the cache, we need two types of IDs: TransientIDs (defined
// in SerialObj.cc) uniquely reference an object during the lifetime of a
// process.  PermanentIDs uniquely reference an object within a serialization.

class SerializationCache {
public:
	typedef uint64 PermanentID;
	static const PermanentID NONE = 0;

	// If max_cache_size is greater than zero, we'll remove old entries
	// automatically if limit is reached (LRU expiration).
	explicit SerializationCache(unsigned int max_cache_size = 0);
	~SerializationCache();

	PermanentID Register(const SerialObj* obj, PermanentID pid,
				bool new_cache_strategy);

	const SerialObj* Lookup(PermanentID pid)
		{
		PIDMap::const_iterator i = pid_map.find(pid);
		if ( i == pid_map.end() )
			return 0;

		assert(i->second);
		MoveEntryToTail(i->second);
		return i->second->obj.serial;
		}

	PermanentID Lookup(const TransientID& tid)
		{
		TIDMap::const_iterator i = tid_map.find(tid.Value());
		if ( i == tid_map.end() )
			return 0;

		uint64 modified = i->second->obj.serial->LastModified();
		if ( modified == SerialObj::ALWAYS || modified > i->second->time )
			return 0;

		assert(i->second);
		MoveEntryToTail(i->second);
		return i->second->pid;
		}

	unsigned int GetMaxCacheSize() const	{ return max_cache_size; }
	void SetMaxCacheSize(unsigned int size)	{ max_cache_size = size; }

	// These methods have to be called at the start/end of the
	// serialization of an entity. The cache guarentees that objects
	// registered after Begin() remain valid until End() is called.
	// After End(), objects which are not derived from BroObj are
	// discarded; others *may* remain valid.
	void Begin(bool can_keep_in_cache)	{ End(can_keep_in_cache); }
	void End(bool can_keep_in_cache);

	void Clear();

private:

	struct CacheList;

	struct CacheEntry {
		union {
			const SerialObj* serial;
			const BroObj* bro;
		} obj;

		bool is_bro_obj;
		PermanentID pid;
		TransientID::ID tid;
		uint64 time;
		struct CacheList* cache;
		CacheEntry* prev;
		CacheEntry* next;

		SerialType stype;	// primarily for debugging
	};

	// We maintain two LRU-sorted lists, one for often-changing objects and
	// one for only rarely changing objects;
	struct CacheList {
		CacheEntry* head;
		CacheEntry* tail;
		unsigned int size;
	};

	void RemoveEntry(CacheEntry* e);
	void UnlinkEntry(CacheEntry* e);
	void MoveEntryToTail(CacheEntry* e);

	unsigned int max_cache_size;

	typedef map<PermanentID, CacheEntry*> PIDMap;
	typedef map<TransientID::ID, CacheEntry*> TIDMap;

	TIDMap tid_map;
	PIDMap pid_map;

	CacheList cache_stable;
	CacheList cache_unstable;

	// Objects in the cache which aren't derived from BroObj. These are
	// always stored in the unstable cache.
	typedef list<CacheEntry*> VolatileList;
	VolatileList volatiles;

	PermanentID next_id;
};

// A serializer for cloning objects.  Objects can be serialized into
// the serializer and unserialized into new objects.  An absolutely
// minimal implementation of Serializer!
class CloneSerializer : public Serializer {
public:
	explicit CloneSerializer(SerializationFormat* format = 0) : Serializer(format) { }
	~CloneSerializer() override
		{ }

protected:
	void ReportError(const char* msg) override { reporter->Error("%s", msg); }
	void GotID(ID* id, Val* val) override { }
	void GotEvent(const char* name, double time, EventHandlerPtr event, val_list* args) override { }
	void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args) override { }
	void GotStateAccess(StateAccess* s) override { delete s; }
	void GotTimer(Timer* t) override { }
	void GotConnection(Connection* c) override { }
	void GotPacket(Packet* packet) override { }
};

// Write values/events to file or fd.
class FileSerializer : public Serializer {
public:
	explicit FileSerializer(SerializationFormat* format = 0);
	~FileSerializer() override;

	// Opens the file for serialization.
	bool Open(const char* file, bool pure = false);
	bool Close();

	// Reads the file.
	bool Read(UnserialInfo* info, const char* file, bool header = true);

protected:
	void ReportError(const char* msg) override;
	void GotID(ID* id, Val* val) override;
	void GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args) override;
	void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args) override;
	void GotStateAccess(StateAccess* s) override;
	void GotTimer(Timer* t) override;
	void GotConnection(Connection* c) override;
	void GotPacket(Packet* packet) override;

	bool OpenFile(const char* file, bool readonly, bool should_exist = false);
	void CloseFile();
	bool ReadFile(const char* file);
	bool PrepareForWriting();
	bool ReadHeader(UnserialInfo* info = 0);

	SerializationCache cache;
	const char* file;
	int fd;
};

// Abstract interface class for external sources providing a stream of events.
class EventSource {
public:
	virtual ~EventSource() { }

	// Returns time of the oldest event (0 if none available).
	virtual double NextTimestamp(double* local_network_time) = 0;

	// Dispatches the oldest event and removes it.
	virtual void DispatchNextEvent() = 0;

	// Returns true if there are more events to expect from this source.
	virtual bool IsActive() = 0;
};

// Plays a file of events back.
class EventPlayer : public FileSerializer, public iosource::IOSource {
public:
	explicit EventPlayer(const char* file);
	~EventPlayer() override;

	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	                    iosource::FD_Set* except) override;
	double NextTimestamp(double* local_network_time) override;
	void Process() override;
	const char* Tag() override { return "EventPlayer"; }

protected:
	void GotID(ID* id, Val* val) override {}
	void GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args) override;
	void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args) override;

	double stream_time;	// time of first captured event
	double replay_time;	// network time of replay start

	// Next event waiting to be dispatched.
	double ne_time;
	EventHandlerPtr ne_handler;
	val_list* ne_args;

};

extern FileSerializer* event_serializer;
extern FileSerializer* state_serializer;

#endif
