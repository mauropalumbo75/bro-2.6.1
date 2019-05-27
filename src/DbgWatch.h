// Structures and methods for implementing watches in the Bro debugger.

#ifndef dbgwatch_h
#define dbgwatch_h

#include "Debug.h"

class DbgWatch {
public:
	explicit DbgWatch(BroObj* var_to_watch);
	explicit DbgWatch(Expr* expr_to_watch);
	~DbgWatch();

protected:
	BroObj* var;
	Expr* expr;
};

#endif
