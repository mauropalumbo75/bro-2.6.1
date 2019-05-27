#ifndef pac_exttype_h
#define pac_exttype_h

#include "pac_type.h"

// ExternType represent external C++ types that are not defined in
// PAC specification (therefore they cannot appear in data layout
// spefication, e.g., in a record field). The type name is copied
// literally to the compiled code.

class ExternType : public Type
{
public:
	enum EXTType { PLAIN, NUMBER, POINTER };
	ExternType(const ID *id, EXTType ext_type)
		: Type(EXTERN),
		  id_(id),
		  ext_type_(ext_type) {}

	bool DefineValueVar() const;
	string DataTypeStr() const;
	int StaticSize(Env *env) const;
	bool ByteOrderSensitive() const;

	string EvalMember(const ID *member_id) const;
	bool IsNumericType() const		{ return ext_type_ == NUMBER; }
	bool IsPointerType() const		{ return ext_type_ == POINTER; }

	void GenInitCode(Output *out_cc, Env *env);

protected:
	void DoGenParseCode(Output *out, Env *env, const DataPtr& data, int flags);
	void GenDynamicSize(Output *out, Env *env, const DataPtr& data);

	Type *DoClone() const;

private:
	const ID *id_;
	EXTType ext_type_;

public:
	static void static_init();
};

#define EXTERNTYPE(name, ctype, exttype) extern ExternType *extern_type_##name;
#include "pac_externtype.def"
#undef EXTERNTYPE

#endif  // pac_exttype_h
