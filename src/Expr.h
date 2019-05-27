// See the file "COPYING" in the main distribution directory for copyright.

#ifndef expr_h
#define expr_h

// BRO expressions.

#include "BroList.h"
#include "ID.h"
#include "Timer.h"
#include "Val.h"
#include "Debug.h"
#include "EventHandler.h"
#include "TraverseTypes.h"

typedef enum {
	EXPR_ANY = -1,
	EXPR_NAME, EXPR_CONST,
	EXPR_CLONE,
	EXPR_INCR, EXPR_DECR,
	EXPR_NOT, EXPR_COMPLEMENT,
	EXPR_POSITIVE, EXPR_NEGATE,
	EXPR_ADD, EXPR_SUB, EXPR_ADD_TO, EXPR_REMOVE_FROM,
	EXPR_TIMES, EXPR_DIVIDE, EXPR_MOD,
	EXPR_AND, EXPR_OR, EXPR_XOR,
	EXPR_AND_AND, EXPR_OR_OR,
	EXPR_LT, EXPR_LE, EXPR_EQ, EXPR_NE, EXPR_GE, EXPR_GT,
	EXPR_COND,
	EXPR_REF,
	EXPR_ASSIGN,
	EXPR_MATCH,
	EXPR_INDEX,
	EXPR_FIELD, EXPR_HAS_FIELD,
	EXPR_RECORD_CONSTRUCTOR,
	EXPR_TABLE_CONSTRUCTOR,
	EXPR_SET_CONSTRUCTOR,
	EXPR_VECTOR_CONSTRUCTOR,
	EXPR_FIELD_ASSIGN,
	EXPR_IN,
	EXPR_LIST,
	EXPR_CALL,
	EXPR_EVENT,
	EXPR_SCHEDULE,
	EXPR_ARITH_COERCE,
	EXPR_RECORD_COERCE,
	EXPR_TABLE_COERCE,
	EXPR_VECTOR_COERCE,
	EXPR_SIZE,
	EXPR_FLATTEN,
	EXPR_CAST,
	EXPR_IS,
#define NUM_EXPRS (int(EXPR_IS) + 1)
} BroExprTag;

extern const char* expr_name(BroExprTag t);

class Stmt;
class Frame;
class ListExpr;
class NameExpr;
class AssignExpr;
class CallExpr;
class EventExpr;


class Expr : public BroObj {
public:
	BroType* Type() const		{ return type; }
	BroExprTag Tag() const	{ return tag; }

	~Expr() override;

	Expr* Ref()			{ ::Ref(this); return this; }

	// Evaluates the expression and returns a corresponding Val*,
	// or nil if the expression's value isn't fixed.
	virtual Val* Eval(Frame* f) const = 0;

	// Same, but the context is that we are adding an element
	// into the given aggregate of the given type.  Note that
	// return type is void since it's updating an existing
	// value, rather than creating a new one.
	virtual void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f)
			const;

	// Assign to the given value, if appropriate.
	virtual void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN);

	// Returns the type corresponding to this expression interpreted
	// as an initialization.  The type should be Unref()'d when done
	// using it.  Returns nil if the initialization is illegal.
	virtual BroType* InitType() const;

	// Returns true if this expression, interpreted as an initialization,
	// constitutes a record element, false otherwise.  If the TypeDecl*
	// is non-nil and the expression is a record element, fills in the
	// TypeDecl with a description of the element.
	virtual int IsRecordElement(TypeDecl* td) const;

	// Returns a value corresponding to this expression interpreted
	// as an initialization, or nil if the expression is inconsistent
	// with the given type.  If "aggr" is non-nil, then this expression
	// is an element of the given aggregate, and it is added to it
	// accordingly.
	virtual Val* InitVal(const BroType* t, Val* aggr) const;

	// True if the expression has no side effects, false otherwise.
	virtual int IsPure() const;

	// True if the expression is a constant, false otherwise.
	int IsConst() const	{ return tag == EXPR_CONST; }

	// True if the expression is in error (to alleviate error propagation).
	int IsError() const	{ return type && type->Tag() == TYPE_ERROR; }

	// Mark expression as in error.
	void SetError()		{ SetType(error_type()); }
	void SetError(const char* msg);

	// Returns the expression's constant value, or complains
	// if it's not a constant.
	inline Val* ExprVal() const;

	// True if the expression is a constant zero, false otherwise.
	int IsZero() const
		{
		return IsConst() && ExprVal()->IsZero();
		}

	// True if the expression is a constant one, false otherwise.
	int IsOne() const
		{
		return IsConst() && ExprVal()->IsOne();
		}

	// True if the expression supports the "add" or "delete" operations,
	// false otherwise.
	virtual int CanAdd() const;
	virtual int CanDel() const;

	virtual void Add(Frame* f);	// perform add operation
	virtual void Delete(Frame* f);	// perform delete operation

	// Return the expression converted to L-value form.  If expr
	// cannot be used as an L-value, reports an error and returns
	// the current value of expr (this is the default method).
	virtual Expr* MakeLvalue();

	// Marks the expression as one requiring (or at least appearing
	// with) parentheses.  Used for pretty-printing.
	void MarkParen()		{ paren = 1; }
	int IsParen() const		{ return paren; }

	const ListExpr* AsListExpr() const
		{
		CHECK_TAG(tag, EXPR_LIST, "ExprVal::AsListExpr", expr_name)
		return (const ListExpr*) this;
		}

	ListExpr* AsListExpr()
		{
		CHECK_TAG(tag, EXPR_LIST, "ExprVal::AsListExpr", expr_name)
		return (ListExpr*) this;
		}

	const NameExpr* AsNameExpr() const
		{
		CHECK_TAG(tag, EXPR_NAME, "ExprVal::AsNameExpr", expr_name)
		return (const NameExpr*) this;
		}

	NameExpr* AsNameExpr()
		{
		CHECK_TAG(tag, EXPR_NAME, "ExprVal::AsNameExpr", expr_name)
		return (NameExpr*) this;
		}

	const AssignExpr* AsAssignExpr() const
		{
		CHECK_TAG(tag, EXPR_ASSIGN, "ExprVal::AsAssignExpr", expr_name)
		return (const AssignExpr*) this;
		}

	AssignExpr* AsAssignExpr()
		{
		CHECK_TAG(tag, EXPR_ASSIGN, "ExprVal::AsAssignExpr", expr_name)
		return (AssignExpr*) this;
		}

	void Describe(ODesc* d) const override;

	bool Serialize(SerialInfo* info) const;
	static Expr* Unserialize(UnserialInfo* info, BroExprTag want = EXPR_ANY);

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

protected:
	Expr()	{ type = 0; }
	explicit Expr(BroExprTag arg_tag);

	virtual void ExprDescribe(ODesc* d) const = 0;
	void AddTag(ODesc* d) const;

	// Puts the expression in canonical form.
	virtual void Canonicize();

	void SetType(BroType* t);

	// Reports the given error and sets the expression's type to
	// TYPE_ERROR.
	void ExprError(const char msg[]);

	DECLARE_ABSTRACT_SERIAL(Expr);

	BroExprTag tag;
	BroType* type;

	int paren;
};

class NameExpr : public Expr {
public:
	explicit NameExpr(ID* id, bool const_init = false);
	~NameExpr() override;

	ID* Id() const		{ return id; }

	Val* Eval(Frame* f) const override;
	void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN) override;
	Expr* MakeLvalue() override;
	int IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	NameExpr()	{ id = 0; }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(NameExpr);

	ID* id;
	bool in_const_init;
};

class ConstExpr : public Expr {
public:
	explicit ConstExpr(Val* val);
	~ConstExpr() override;

	Val* Value() const	{ return val; }

	Val* Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	ConstExpr()	{ val = 0; }

	void ExprDescribe(ODesc* d) const override;
	DECLARE_SERIAL(ConstExpr);

	Val* val;
};

class UnaryExpr : public Expr {
public:
	Expr* Op() const	{ return op; }

	// UnaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	Val* Eval(Frame* f) const override;

	int IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	UnaryExpr()	{ op = 0; }

	UnaryExpr(BroExprTag arg_tag, Expr* arg_op);
	~UnaryExpr() override;

	void ExprDescribe(ODesc* d) const override;

	// Returns the expression folded using the given constant.
	virtual Val* Fold(Val* v) const;

	DECLARE_SERIAL(UnaryExpr);

	Expr* op;
};

class BinaryExpr : public Expr {
public:
	Expr* Op1() const	{ return op1; }
	Expr* Op2() const	{ return op2; }

	int IsPure() const override;

	// BinaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	Val* Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	BinaryExpr()	{ op1 = op2 = 0; }

	BinaryExpr(BroExprTag arg_tag, Expr* arg_op1, Expr* arg_op2)
	    : Expr(arg_tag), op1(arg_op1), op2(arg_op2)
		{
		if ( ! (arg_op1 && arg_op2) )
			return;
		if ( op1->IsError() || op2->IsError() )
			SetError();
		}
	~BinaryExpr() override;

	// Returns the expression folded using the given constants.
	virtual Val* Fold(Val* v1, Val* v2) const;

	// Same for when the constants are strings.
	virtual Val* StringFold(Val* v1, Val* v2) const;

	// Same for when the constants are patterns.
	virtual Val* PatternFold(Val* v1, Val* v2) const;

	// Same for when the constants are sets.
	virtual Val* SetFold(Val* v1, Val* v2) const;

	// Same for when the constants are addresses or subnets.
	virtual Val* AddrFold(Val* v1, Val* v2) const;
	virtual Val* SubNetFold(Val* v1, Val* v2) const;

	int BothConst() const	{ return op1->IsConst() && op2->IsConst(); }

	// Exchange op1 and op2.
	void SwapOps();

	// Promote the operands to the given type tag, if necessary.
	void PromoteOps(TypeTag t);

	// Promote the expression to the given type tag (i.e., promote
	// operands and also set expression's type).
	void PromoteType(TypeTag t, bool is_vector);

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(BinaryExpr);

	Expr* op1;
	Expr* op2;
};

class CloneExpr : public UnaryExpr {
public:
	explicit CloneExpr(Expr* op);
	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	CloneExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(CloneExpr);
};

class IncrExpr : public UnaryExpr {
public:
	IncrExpr(BroExprTag tag, Expr* op);

	Val* Eval(Frame* f) const override;
	Val* DoSingleEval(Frame* f, Val* v) const;
	int IsPure() const override;

protected:
	friend class Expr;
	IncrExpr()	{ }

	DECLARE_SERIAL(IncrExpr);
};

class ComplementExpr : public UnaryExpr {
public:
	explicit ComplementExpr(Expr* op);

protected:
	friend class Expr;
	ComplementExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(ComplementExpr);
};

class NotExpr : public UnaryExpr {
public:
	explicit NotExpr(Expr* op);

protected:
	friend class Expr;
	NotExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(NotExpr);
};

class PosExpr : public UnaryExpr {
public:
	explicit PosExpr(Expr* op);

protected:
	friend class Expr;
	PosExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(PosExpr);
};

class NegExpr : public UnaryExpr {
public:
	explicit NegExpr(Expr* op);

protected:
	friend class Expr;
	NegExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(NegExpr);
};

class SizeExpr : public UnaryExpr {
public:
	explicit SizeExpr(Expr* op);
	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	SizeExpr()	{ }

	Val* Fold(Val* v) const override;
	DECLARE_SERIAL(SizeExpr);
};

class AddExpr : public BinaryExpr {
public:
	AddExpr(Expr* op1, Expr* op2);
	void Canonicize() override;

protected:
	friend class Expr;
	AddExpr()	{ }

	DECLARE_SERIAL(AddExpr);

};

class AddToExpr : public BinaryExpr {
public:
	AddToExpr(Expr* op1, Expr* op2);
	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	AddToExpr()	{ }

	DECLARE_SERIAL(AddToExpr);
};

class RemoveFromExpr : public BinaryExpr {
public:
	RemoveFromExpr(Expr* op1, Expr* op2);
	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	RemoveFromExpr()	{ }

	DECLARE_SERIAL(RemoveFromExpr);
};

class SubExpr : public BinaryExpr {
public:
	SubExpr(Expr* op1, Expr* op2);

protected:
	friend class Expr;
	SubExpr()	{ }

	DECLARE_SERIAL(SubExpr);

};

class TimesExpr : public BinaryExpr {
public:
	TimesExpr(Expr* op1, Expr* op2);
	void Canonicize() override;

protected:
	friend class Expr;
	TimesExpr()	{ }

	DECLARE_SERIAL(TimesExpr);

};

class DivideExpr : public BinaryExpr {
public:
	DivideExpr(Expr* op1, Expr* op2);

protected:
	friend class Expr;
	DivideExpr()	{ }

	Val* AddrFold(Val* v1, Val* v2) const override;

	DECLARE_SERIAL(DivideExpr);

};

class ModExpr : public BinaryExpr {
public:
	ModExpr(Expr* op1, Expr* op2);

protected:
	friend class Expr;
	ModExpr()	{ }

	DECLARE_SERIAL(ModExpr);
};

class BoolExpr : public BinaryExpr {
public:
	BoolExpr(BroExprTag tag, Expr* op1, Expr* op2);

	Val* Eval(Frame* f) const override;
	Val* DoSingleEval(Frame* f, Val* v1, Expr* op2) const;

protected:
	friend class Expr;
	BoolExpr()	{ }

	DECLARE_SERIAL(BoolExpr);
};

class BitExpr : public BinaryExpr {
public:
	BitExpr(BroExprTag tag, Expr* op1, Expr* op2);

protected:
	friend class Expr;
	BitExpr()	{ }

	DECLARE_SERIAL(BitExpr);
};

class EqExpr : public BinaryExpr {
public:
	EqExpr(BroExprTag tag, Expr* op1, Expr* op2);
	void Canonicize() override;

protected:
	friend class Expr;
	EqExpr()	{ }

	Val* Fold(Val* v1, Val* v2) const override;

	DECLARE_SERIAL(EqExpr);
};

class RelExpr : public BinaryExpr {
public:
	RelExpr(BroExprTag tag, Expr* op1, Expr* op2);
	void Canonicize() override;

protected:
	friend class Expr;
	RelExpr()	{ }

	DECLARE_SERIAL(RelExpr);
};

class CondExpr : public Expr {
public:
	CondExpr(Expr* op1, Expr* op2, Expr* op3);
	~CondExpr() override;

	const Expr* Op1() const	{ return op1; }
	const Expr* Op2() const	{ return op2; }
	const Expr* Op3() const	{ return op3; }

	Val* Eval(Frame* f) const override;
	int IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	CondExpr()	{ op1 = op2 = op3 = 0; }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(CondExpr);

	Expr* op1;
	Expr* op2;
	Expr* op3;
};

class RefExpr : public UnaryExpr {
public:
	explicit RefExpr(Expr* op);

	void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN) override;
	Expr* MakeLvalue() override;

protected:
	friend class Expr;
	RefExpr()	{ }

	DECLARE_SERIAL(RefExpr);
};

class AssignExpr : public BinaryExpr {
public:
	// If val is given, evaluating this expression will always yield the val
	// yet still perform the assignment.  Used for triggers.
	AssignExpr(Expr* op1, Expr* op2, int is_init, Val* val = 0, attr_list* attrs = 0);
	~AssignExpr() override { Unref(val); }

	Val* Eval(Frame* f) const override;
	void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f) const override;
	BroType* InitType() const override;
	int IsRecordElement(TypeDecl* td) const override;
	Val* InitVal(const BroType* t, Val* aggr) const override;
	int IsPure() const override;

protected:
	friend class Expr;
	AssignExpr()	{ }

	bool TypeCheck(attr_list* attrs = 0);
	bool TypeCheckArithmetics(TypeTag bt1, TypeTag bt2);

	DECLARE_SERIAL(AssignExpr);

	int is_init;
	Val* val;	// optional
};

class IndexExpr : public BinaryExpr {
public:
	IndexExpr(Expr* op1, ListExpr* op2, bool is_slice = false);

	int CanAdd() const override;
	int CanDel() const override;

	void Add(Frame* f) override;
	void Delete(Frame* f) override;

	void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN) override;
	Expr* MakeLvalue() override;

	// Need to override Eval since it can take a vector arg but does
	// not necessarily return a vector.
	Val* Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	IndexExpr()	{ }

	Val* Fold(Val* v1, Val* v2) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(IndexExpr);
};

class FieldExpr : public UnaryExpr {
public:
	FieldExpr(Expr* op, const char* field_name);
	~FieldExpr() override;

	int Field() const	{ return field; }
	const char* FieldName() const	{ return field_name; }

	int CanDel() const override;

	void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN) override;
	void Delete(Frame* f) override;

	Expr* MakeLvalue() override;

protected:
	friend class Expr;
	FieldExpr()	{ field_name = 0; td = 0; }

	Val* Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(FieldExpr);

	const char* field_name;
	const TypeDecl* td;
	int field; // -1 = attributes
};

// "rec?$fieldname" is true if the value of $fieldname in rec is not nil.
// "rec?$$attrname" is true if the attribute attrname is not nil.
class HasFieldExpr : public UnaryExpr {
public:
	HasFieldExpr(Expr* op, const char* field_name);
	~HasFieldExpr() override;

	const char* FieldName() const	{ return field_name; }

protected:
	friend class Expr;
	HasFieldExpr()	{ field_name = 0; }

	Val* Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(HasFieldExpr);

	const char* field_name;
	int field;
};

class RecordConstructorExpr : public UnaryExpr {
public:
	explicit RecordConstructorExpr(ListExpr* constructor_list);
	~RecordConstructorExpr() override;

protected:
	friend class Expr;
	RecordConstructorExpr()	{ }

	Val* InitVal(const BroType* t, Val* aggr) const override;
	Val* Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(RecordConstructorExpr);
};

class TableConstructorExpr : public UnaryExpr {
public:
	TableConstructorExpr(ListExpr* constructor_list, attr_list* attrs,
	                     BroType* arg_type = 0);
	~TableConstructorExpr() override { Unref(attrs); }

	Attributes* Attrs() { return attrs; }

	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	TableConstructorExpr()	{ }

	Val* InitVal(const BroType* t, Val* aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(TableConstructorExpr);

	Attributes* attrs;
};

class SetConstructorExpr : public UnaryExpr {
public:
	SetConstructorExpr(ListExpr* constructor_list, attr_list* attrs,
	                   BroType* arg_type = 0);
	~SetConstructorExpr() override { Unref(attrs); }

	Attributes* Attrs() { return attrs; }

	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	SetConstructorExpr()	{ }

	Val* InitVal(const BroType* t, Val* aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(SetConstructorExpr);

	Attributes* attrs;
};

class VectorConstructorExpr : public UnaryExpr {
public:
	explicit VectorConstructorExpr(ListExpr* constructor_list, BroType* arg_type = 0);

	Val* Eval(Frame* f) const override;

protected:
	friend class Expr;
	VectorConstructorExpr()	{ }

	Val* InitVal(const BroType* t, Val* aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(VectorConstructorExpr);
};

class FieldAssignExpr : public UnaryExpr {
public:
	FieldAssignExpr(const char* field_name, Expr* value);

	const char* FieldName() const	{ return field_name.c_str(); }

	void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f) const override;
	int IsRecordElement(TypeDecl* td) const override;

protected:
	friend class Expr;
	FieldAssignExpr()	{ }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(FieldAssignExpr);

	string field_name;
};

class ArithCoerceExpr : public UnaryExpr {
public:
	ArithCoerceExpr(Expr* op, TypeTag t);

protected:
	friend class Expr;
	ArithCoerceExpr()	{ }

	Val* FoldSingleVal(Val* v, InternalTypeTag t) const;
	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(ArithCoerceExpr);
};

class RecordCoerceExpr : public UnaryExpr {
public:
	RecordCoerceExpr(Expr* op, RecordType* r);
	~RecordCoerceExpr() override;

protected:
	friend class Expr;
	RecordCoerceExpr()	{ map = 0; }

	Val* InitVal(const BroType* t, Val* aggr) const override;
	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(RecordCoerceExpr);

	// For each super-record slot, gives subrecord slot with which to
	// fill it.
	int* map;
	int map_size;	// equivalent to Type()->AsRecordType()->NumFields()
};

class TableCoerceExpr : public UnaryExpr {
public:
	TableCoerceExpr(Expr* op, TableType* r);
	~TableCoerceExpr() override;

protected:
	friend class Expr;
	TableCoerceExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(TableCoerceExpr);
};

class VectorCoerceExpr : public UnaryExpr {
public:
	VectorCoerceExpr(Expr* op, VectorType* v);
	~VectorCoerceExpr() override;

protected:
	friend class Expr;
	VectorCoerceExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(VectorCoerceExpr);
};

// An internal operator for flattening array indices that are records
// into a list of individual values.
class FlattenExpr : public UnaryExpr {
public:
	explicit FlattenExpr(Expr* op);

protected:
	friend class Expr;
	FlattenExpr()	{ }

	Val* Fold(Val* v) const override;

	DECLARE_SERIAL(FlattenExpr);

	int num_fields;
};

class EventHandler;

class ScheduleTimer : public Timer {
public:
	ScheduleTimer(EventHandlerPtr event, val_list* args, double t,
			TimerMgr* tmgr);
	~ScheduleTimer() override;

	void Dispatch(double t, int is_expire) override;

protected:
	EventHandlerPtr event;
	val_list* args;
	TimerMgr* tmgr;
};

class ScheduleExpr : public Expr {
public:
	ScheduleExpr(Expr* when, EventExpr* event);
	~ScheduleExpr() override;

	int IsPure() const override;

	Val* Eval(Frame* f) const override;

	Expr* When() const	{ return when; }
	EventExpr* Event() const	{ return event; }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	ScheduleExpr()	{ when = 0; event = 0; }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(ScheduleExpr);

	Expr* when;
	EventExpr* event;
};

class InExpr : public BinaryExpr {
public:
	InExpr(Expr* op1, Expr* op2);

protected:
	friend class Expr;
	InExpr()	{ }

	Val* Fold(Val* v1, Val* v2) const override;

	DECLARE_SERIAL(InExpr);

};

class CallExpr : public Expr {
public:
	CallExpr(Expr* func, ListExpr* args, bool in_hook = false);
	~CallExpr() override;

	Expr* Func() const	{ return func; }
	ListExpr* Args() const	{ return args; }

	int IsPure() const override;

	Val* Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	CallExpr()	{ func = 0; args = 0; }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(CallExpr);

	Expr* func;
	ListExpr* args;
};

class EventExpr : public Expr {
public:
	EventExpr(const char* name, ListExpr* args);
	~EventExpr() override;

	const char* Name() const	{ return name.c_str(); }
	ListExpr* Args() const		{ return args; }
	EventHandlerPtr Handler()  const	{ return handler; }

	Val* Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Expr;
	EventExpr()	{ args = 0; }

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(EventExpr);

	string name;
	EventHandlerPtr handler;
	ListExpr* args;
};

class ListExpr : public Expr {
public:
	ListExpr();
	explicit ListExpr(Expr* e);
	~ListExpr() override;

	void Append(Expr* e);

	const expr_list& Exprs() const	{ return exprs; }
	expr_list& Exprs()		{ return exprs; }

	// True if the entire list represents pure values.
	int IsPure() const override;

	// True if the entire list represents constant values.
	int AllConst() const;

	Val* Eval(Frame* f) const override;

	BroType* InitType() const override;
	Val* InitVal(const BroType* t, Val* aggr) const override;
	Expr* MakeLvalue() override;
	void Assign(Frame* f, Val* v, Opcode op = OP_ASSIGN) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	Val* AddSetInit(const BroType* t, Val* aggr) const;

	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(ListExpr);

	expr_list exprs;
};


class RecordAssignExpr : public ListExpr {
public:
	RecordAssignExpr(Expr* record, Expr* init_list, int is_init);

	Val* Eval(Frame* f) const override	{ return ListExpr::Eval(f); }

protected:
	friend class Expr;
	RecordAssignExpr()	{ }

	DECLARE_SERIAL(RecordAssignExpr);
};

class CastExpr : public UnaryExpr {
public:
	CastExpr(Expr* op, BroType* t);

protected:
	friend class Expr;
	CastExpr()	{ }

	Val* Eval(Frame* f) const override;
	void ExprDescribe(ODesc* d) const override;

	DECLARE_SERIAL(CastExpr);
};

class IsExpr : public UnaryExpr {
public:
	IsExpr(Expr* op, BroType* t);
	virtual ~IsExpr();

protected:
	friend class Expr;
	IsExpr()	{ }

	Val* Fold(Val* v) const override;
	void ExprDescribe(ODesc* d) const override;
	DECLARE_SERIAL(IsExpr);

private:
	BroType* t;
};

inline Val* Expr::ExprVal() const
	{
	if ( ! IsConst() )
		BadTag("ExprVal::Val", expr_name(tag), expr_name(EXPR_CONST));
	return ((ConstExpr*) this)->Value();
	}

// Decides whether to return an AssignExpr or a RecordAssignExpr.
Expr* get_assign_expr(Expr* op1, Expr* op2, int is_init);

// Type-check the given expression(s) against the given type(s).  Complain
// if the expression cannot match the given type, returning 0.  If it can
// match, promote it as necessary (modifying the ref parameter accordingly)
// and return 1.
//
// The second, third, and fourth forms are for promoting a list of
// expressions (which is updated in place) to either match a list of
// types or a single type.
//
// Note, the type is not "const" because it can be ref'd.
extern int check_and_promote_expr(Expr*& e, BroType* t);
extern int check_and_promote_exprs(ListExpr*& elements, TypeList* types);
extern int check_and_promote_args(ListExpr*& args, RecordType* types);
extern int check_and_promote_exprs_to_type(ListExpr*& elements, BroType* type);

// Returns a ListExpr simplified down to a list a values, or a nil
// pointer if they couldn't all be reduced.
val_list* eval_list(Frame* f, const ListExpr* l);

// Returns true if e1 is "greater" than e2 - here "greater" is just
// a heuristic, used with commutative operators to put them into
// a canonical form.
extern int expr_greater(const Expr* e1, const Expr* e2);

// Return constants of the given type.
Expr* make_zero(BroType* t);
Expr* make_one(BroType* t);

// True if the given Val* has a vector type
inline bool is_vector(Expr* e)	{ return e->Type()->Tag() == TYPE_VECTOR; }

#endif
