// See the file "COPYING" in the main distribution directory for copyright.

#include "bro-config.h"

#include "Expr.h"
#include "Event.h"
#include "Frame.h"
#include "File.h"
#include "Reporter.h"
#include "NetVar.h"
#include "Stmt.h"
#include "Scope.h"
#include "Var.h"
#include "Debug.h"
#include "Traverse.h"
#include "Trigger.h"
#include "RemoteSerializer.h"

const char* stmt_name(BroStmtTag t)
	{
	static const char* stmt_names[int(NUM_STMTS)] = {
		"alarm", // Does no longer exist, but kept for keeping enums consistent.
		"print", "event", "expr", "if", "when", "switch",
		"for", "next", "break", "return", "add", "delete",
		"list", "bodylist",
		"<init>", "fallthrough", "while",
		"null",
	};

	return stmt_names[int(t)];
	}

Stmt::Stmt(BroStmtTag arg_tag)
	{
	tag = arg_tag;
	breakpoint_count = 0;
	last_access = 0;
	access_count = 0;

	SetLocationInfo(&start_location, &end_location);
	}

Stmt::~Stmt()
	{
	}

bool Stmt::SetLocationInfo(const Location* start, const Location* end)
	{
	if ( ! BroObj::SetLocationInfo(start, end) )
		return false;

	// Update the Filemap of line number -> statement mapping for
	// breakpoints (Debug.h).
	Filemap* map_ptr = (Filemap*) g_dbgfilemaps.Lookup(location->filename);
	if ( ! map_ptr )
		return false;

	Filemap& map = *map_ptr;

	StmtLocMapping* new_mapping = new StmtLocMapping(GetLocationInfo(), this);

	// Optimistically just put it at the end.
	map.push_back(new_mapping);

	int curr_idx = map.length() - 1;
	if ( curr_idx == 0 )
		return true;

	// In case it wasn't actually lexically last, bubble it to the
	// right place.
	while ( map[curr_idx - 1]->StartsAfter(map[curr_idx]) )
		{
		StmtLocMapping t = *map[curr_idx - 1];
		*map[curr_idx - 1] = *map[curr_idx];
		*map[curr_idx] = t;
		curr_idx--;
		}

	return true;
	}

int Stmt::IsPure() const
	{
	return 0;
	}

void Stmt::Describe(ODesc* d) const
	{
	if ( ! d->IsReadable() || Tag() != STMT_EXPR )
		AddTag(d);
	}

void Stmt::AddTag(ODesc* d) const
	{
	if ( d->IsBinary() )
		d->Add(int(Tag()));
	else
		d->Add(stmt_name(Tag()));
	d->SP();
	}

void Stmt::DescribeDone(ODesc* d) const
	{
	if ( d->IsReadable() && ! d->IsShort() )
		d->Add(";");
	}

void Stmt::AccessStats(ODesc* d) const
	{
	if ( d->IncludeStats() )
		{
		d->Add("(@");
		d->Add(last_access ? fmt_access_time(last_access) : "<never>");
		d->Add(" #");
		d->Add(access_count);
		d->Add(")");
		d->NL();
		}
	}

bool Stmt::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Stmt* Stmt::Unserialize(UnserialInfo* info, BroStmtTag want)
	{
	Stmt* stmt = (Stmt*) SerialObj::Unserialize(info, SER_STMT);

	if ( want != STMT_ANY && stmt->tag != want )
		{
		info->s->Error("wrong stmt type");
		Unref(stmt);
		return 0;
		}

	return stmt;
	}

bool Stmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_STMT, BroObj);

	return SERIALIZE(char(tag)) && SERIALIZE(last_access)
			&& SERIALIZE(access_count);
	}

bool Stmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	char c;
	if ( ! UNSERIALIZE(&c) )
		return 0;

	tag = BroStmtTag(c);

	return UNSERIALIZE(&last_access) && UNSERIALIZE(&access_count);
	}


ExprListStmt::ExprListStmt(BroStmtTag t, ListExpr* arg_l)
: Stmt(t)
	{
	l = arg_l;

	const expr_list& e = l->Exprs();
	loop_over_list(e, i)
		{
		const BroType* t = e[i]->Type();
		if ( ! t || t->Tag() == TYPE_VOID )
			Error("value of type void illegal");
		}

	SetLocationInfo(arg_l->GetLocationInfo());
	}

ExprListStmt::~ExprListStmt()
	{
	Unref(l);
	}

Val* ExprListStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	last_access = network_time;
	flow = FLOW_NEXT;

	val_list* vals = eval_list(f, l);
	if ( vals )
		{
		Val* result = DoExec(vals, flow);
		delete_vals(vals);
		return result;
		}
	else
		return 0;
	}

void ExprListStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	l->Describe(d);
	DescribeDone(d);
	}

void ExprListStmt::PrintVals(ODesc* d, val_list* vals, int offset) const
	{
	describe_vals(vals, d, offset);
	}

bool ExprListStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EXPR_LIST_STMT, Stmt);
	return l->Serialize(info);
	}

bool ExprListStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	l = (ListExpr*) Expr::Unserialize(info, EXPR_LIST);
	return l != 0;
	}

TraversalCode ExprListStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	const expr_list& e = l->Exprs();
	loop_over_list(e, i)
		{
		tc = e[i]->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

static BroFile* print_stdout = 0;

Val* PrintStmt::DoExec(val_list* vals, stmt_flow_type& /* flow */) const
	{
	RegisterAccess();

	if ( ! print_stdout )
		print_stdout = new BroFile(stdout);

	BroFile* f = print_stdout;
	int offset = 0;

	if ( vals->length() > 0 && (*vals)[0]->Type()->Tag() == TYPE_FILE )
		{
		f = (*vals)[0]->AsFile();
		if ( ! f->IsOpen() )
			return 0;

		++offset;
		}

	bool ph = print_hook && f->IsPrintHookEnabled();

	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;

	if ( ! (suppress_local_output && ph) )
		{
		if ( f->IsRawOutput() )
			{
			ODesc d(DESC_READABLE);
			d.SetFlush(0);
			d.SetStyle(style);

			PrintVals(&d, vals, offset);
			f->Write(d.Description(), d.Len());
			}
		else
			{
			ODesc d(DESC_READABLE, f);
			d.SetFlush(0);
			d.SetStyle(style);

			PrintVals(&d, vals, offset);
			f->Write("\n", 1);
			}
		}

	if ( ph )
		{
		ODesc d(DESC_READABLE);
		d.SetStyle(style);
		PrintVals(&d, vals, offset);

		if ( print_hook )
			{
			val_list* vl = new val_list(2);
			::Ref(f);
			vl->append(new Val(f));
			vl->append(new StringVal(d.Len(), d.Description()));

			// Note, this doesn't do remote printing.
			mgr.Dispatch(new Event(print_hook, vl), true);
			}

		if ( remote_serializer )
			remote_serializer->SendPrintHookEvent(f, d.Description(), d.Len());
		}

	return 0;
	}

IMPLEMENT_SERIAL(PrintStmt, SER_PRINT_STMT);

bool PrintStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_PRINT_STMT, ExprListStmt);
	return true;
	}

bool PrintStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprListStmt);
	return true;
	}

ExprStmt::ExprStmt(Expr* arg_e) : Stmt(STMT_EXPR)
	{
	e = arg_e;
	if ( e && e->IsPure() )
		Warn("expression value ignored");

	SetLocationInfo(arg_e->GetLocationInfo());
	}

ExprStmt::ExprStmt(BroStmtTag t, Expr* arg_e) : Stmt(t)
	{
	e = arg_e;

	if ( e )
		SetLocationInfo(e->GetLocationInfo());
	}

ExprStmt::~ExprStmt()
	{
	Unref(e);
	}

Val* ExprStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	Val* v = e->Eval(f);

	if ( v )
		{
		Val* ret_val = DoExec(f, v, flow);
		Unref(v);
		return ret_val;
		}
	else
		return 0;
	}

Val* ExprStmt::DoExec(Frame* /* f */, Val* /* v */, stmt_flow_type& /* flow */) const
	{
	return 0;
	}

int ExprStmt::IsPure() const
	{
	return ! e || e->IsPure();
	}

void ExprStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() && Tag() == STMT_IF )
		d->Add("(");
	e->Describe(d);

	if ( Tag() == STMT_IF || Tag() == STMT_SWITCH )
		{
		if ( d->IsReadable() )
			{
			if ( Tag() == STMT_IF )
				d->Add(")");
			d->SP();
			}
		}
	else
		DescribeDone(d);
	}

TraversalCode ExprStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	if ( e )
		{
		tc = e->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(ExprStmt, SER_EXPR_STMT);

bool ExprStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EXPR_STMT, Stmt);
	SERIALIZE_OPTIONAL(e);
	return true;
	}

bool ExprStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	UNSERIALIZE_OPTIONAL(e, Expr::Unserialize(info));
	return true;
	}

IfStmt::IfStmt(Expr* test, Stmt* arg_s1, Stmt* arg_s2) : ExprStmt(STMT_IF, test)
	{
	s1 = arg_s1;
	s2 = arg_s2;

	if ( ! e->IsError() && ! IsBool(e->Type()->Tag()) )
		e->Error("conditional in test must be boolean");

	const Location* loc1 = arg_s1->GetLocationInfo();
	const Location* loc2 = arg_s2->GetLocationInfo();
	SetLocationInfo(loc1, loc2);
	}

IfStmt::~IfStmt()
	{
	Unref(s1);
	Unref(s2);
	}

Val* IfStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	// Treat 0 as false, but don't require 1 for true.
	Stmt* do_stmt = v->IsZero() ? s2 : s1;

	f->SetNextStmt(do_stmt);

	if ( ! pre_execute_stmt(do_stmt, f) )
		{ // ### Abort or something
		}

	Val* result = do_stmt->Exec(f, flow);

	if ( ! post_execute_stmt(do_stmt, f, result, &flow) )
		{ // ### Abort or something
		}

	return result;
	}

int IfStmt::IsPure() const
	{
	return e->IsPure() && s1->IsPure() && s2->IsPure();
	}

void IfStmt::Describe(ODesc* d) const
	{
	ExprStmt::Describe(d);

	d->PushIndent();
	s1->AccessStats(d);
	s1->Describe(d);
	d->PopIndent();

	if ( d->IsReadable() )
		{
		if ( s2->Tag() != STMT_NULL )
			{
			d->Add("else");
			d->PushIndent();
			s2->AccessStats(d);
			s2->Describe(d);
			d->PopIndent();
			}
		}
	else
		s2->Describe(d);
	}

TraversalCode IfStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Condition is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = TrueBranch()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = FalseBranch()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(IfStmt, SER_IF_STMT);

bool IfStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_IF_STMT, ExprStmt);
	return s1->Serialize(info) && s2->Serialize(info);
	}

bool IfStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);
	s1 = Stmt::Unserialize(info);
	if ( ! s1 )
		return false;

	s2 = Stmt::Unserialize(info);
	return s2 != 0;
	}

static BroStmtTag get_last_stmt_tag(const Stmt* stmt)
	{
	if ( ! stmt )
		return STMT_NULL;

	if ( stmt->Tag() != STMT_LIST )
		return stmt->Tag();

	const StmtList* stmts = stmt->AsStmtList();
	int len = stmts->Stmts().length();

	if ( len == 0 )
		return STMT_LIST;

	return get_last_stmt_tag(stmts->Stmts()[len - 1]);
	}

Case::Case(ListExpr* arg_expr_cases, id_list* arg_type_cases, Stmt* arg_s)
	: expr_cases(arg_expr_cases), type_cases(arg_type_cases), s(arg_s)
	{
	BroStmtTag t = get_last_stmt_tag(Body());

	if ( t != STMT_BREAK && t != STMT_FALLTHROUGH && t != STMT_RETURN )
		Error("case block must end in break/fallthrough/return statement");
	}

Case::~Case()
	{
	Unref(expr_cases);
	Unref(s);

	loop_over_list((*type_cases), i)
		Unref((*type_cases)[i]);

	delete type_cases;
	}

void Case::Describe(ODesc* d) const
	{
	if ( ! (expr_cases || type_cases) )
		{
		if ( ! d->IsBinary() )
			d->Add("default:");

		d->AddCount(0);

		d->PushIndent();
		Body()->AccessStats(d);
		Body()->Describe(d);
		d->PopIndent();

		return;
		}

	if ( ! d->IsBinary() )
		d->Add("case");

	if ( expr_cases )
		{
		const expr_list& e = expr_cases->Exprs();

		d->AddCount(e.length());

		loop_over_list(e, i)
			{
			if ( i > 0 && d->IsReadable() )
				d->Add(",");

			d->SP();
			e[i]->Describe(d);
			}
		}

	if ( type_cases )
		{
		const id_list& t = *type_cases;

		d->AddCount(t.length());

		loop_over_list(t, i)
			{
			if ( i > 0 && d->IsReadable() )
				d->Add(",");

			d->SP();
			d->Add("type");
			d->SP();
			t[i]->Type()->Describe(d);

			if ( t[i]->Name() )
				{
				d->SP();
				d->Add("as");
				d->SP();
				d->Add(t[i]->Name());
				}
			}
		}

	if ( d->IsReadable() )
		d->Add(":");

	d->PushIndent();
	Body()->AccessStats(d);
	Body()->Describe(d);
	d->PopIndent();
	}

TraversalCode Case::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc;

	if ( expr_cases )
		{
		tc = expr_cases->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	if ( type_cases )
		{
		// No traverse support for types.
		}

	tc = s->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	return TC_CONTINUE;
	}

bool Case::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Case* Case::Unserialize(UnserialInfo* info)
	{
	return (Case*) SerialObj::Unserialize(info, SER_CASE);
	}

IMPLEMENT_SERIAL(Case, SER_CASE);

bool Case::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_CASE, BroObj);

	if ( ! expr_cases->Serialize(info) )
		return false;

	id_list empty;
	id_list* types = (type_cases ? type_cases : &empty);

	if ( ! SERIALIZE(types->length()) )
		return false;

	loop_over_list((*types), i)
		{
		if ( ! (*types)[i]->Serialize(info) )
			return false;
		}

	return this->s->Serialize(info);
	}

bool Case::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	expr_cases = (ListExpr*) Expr::Unserialize(info, EXPR_LIST);
	if ( ! expr_cases )
		return false;

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	type_cases = new id_list;

	while ( len-- )
		{
		ID* id = ID::Unserialize(info);
		if ( ! id )
			return false;

		type_cases->append(id);
		}

	this->s = Stmt::Unserialize(info);
	return this->s != 0;
	}

static void int_del_func(void* v)
	{
	delete (int*) v;
	}

void SwitchStmt::Init()
	{
	TypeList* t = new TypeList();
	t->Append(e->Type()->Ref());
	comp_hash = new CompositeHash(t);
	Unref(t);

	case_label_value_map.SetDeleteFunc(int_del_func);
	}

SwitchStmt::SwitchStmt(Expr* index, case_list* arg_cases) :
	ExprStmt(STMT_SWITCH, index), cases(arg_cases), default_case_idx(-1)
	{
	Init();

	bool have_exprs = false;
	bool have_types = false;

	loop_over_list(*cases, i)
		{
		Case* c = (*cases)[i];
		ListExpr* le = c->ExprCases();
		id_list* tl = c->TypeCases();

		if ( le )
			{
			have_exprs = true;

			if ( ! is_atomic_type(e->Type()) )
				e->Error("switch expression must be of an atomic type when cases are expressions");

			if ( ! le->Type()->AsTypeList()->AllMatch(e->Type(), false) )
				{
				le->Error("case expression type differs from switch type", e);
				continue;
				}

			expr_list& exprs = le->Exprs();

			loop_over_list(exprs, j)
				{
				if ( ! exprs[j]->IsConst() )
					{
					Expr* expr = exprs[j];

					switch ( expr->Tag() ) {
					// Simplify trivial unary plus/minus expressions on consts.
					case EXPR_NEGATE:
						{
						NegExpr* ne = (NegExpr*)(expr);

						if ( ne->Op()->IsConst() )
							Unref(exprs.replace(j, new ConstExpr(ne->Eval(0))));
						}
						break;

					case EXPR_POSITIVE:
						{
						PosExpr* pe = (PosExpr*)(expr);

						if ( pe->Op()->IsConst() )
							Unref(exprs.replace(j, new ConstExpr(pe->Eval(0))));
						}
						break;

					case EXPR_NAME:
						{
						NameExpr* ne = (NameExpr*)(expr);

						if ( ne->Id()->IsConst() )
							{
							Val* v = ne->Eval(0);

							if ( v )
								Unref(exprs.replace(j, new ConstExpr(v)));
							}
						}
						break;

					default:
						break;
					}
					}

				if ( ! exprs[j]->IsConst() )
					exprs[j]->Error("case label expression isn't constant");
				else
					{
					if ( ! AddCaseLabelValueMapping(exprs[j]->ExprVal(), i) )
						exprs[j]->Error("duplicate case label");
					}
				}
			}

		else if ( tl )
			{
			have_types = true;

			loop_over_list((*tl), j)
				{
				BroType* ct = (*tl)[j]->Type();

	   			if ( ! can_cast_value_to_type(e->Type(), ct) )
					{
					c->Error("cannot cast switch expression to case type");
					continue;
					}

				if ( ! AddCaseLabelTypeMapping((*tl)[j], i) )
					{
					c->Error("duplicate case label");
					continue;
					}
				}
			}

		else
			{
			if ( default_case_idx != -1 )
				c->Error("multiple default labels", (*cases)[default_case_idx]);
			else
				default_case_idx = i;
			}
		}

	if ( have_exprs && have_types )
		Error("cannot mix cases with expressions and types");

	}

SwitchStmt::~SwitchStmt()
	{
	loop_over_list(*cases, i)
		Unref((*cases)[i]);

	delete cases;
	delete comp_hash;
	}

bool SwitchStmt::AddCaseLabelValueMapping(const Val* v, int idx)
	{
	HashKey* hk = comp_hash->ComputeHash(v, 1);

	if ( ! hk )
		{
		reporter->PushLocation(e->GetLocationInfo());
		reporter->InternalError("switch expression type mismatch (%s/%s)",
		    type_name(v->Type()->Tag()), type_name(e->Type()->Tag()));
		}

	int* label_idx = case_label_value_map.Lookup(hk);

	if ( label_idx )
		{
		delete hk;
		return false;
		}

	case_label_value_map.Insert(hk, new int(idx));
	delete hk;
	return true;
	}

bool SwitchStmt::AddCaseLabelTypeMapping(ID* t, int idx)
	{
	for ( auto i : case_label_type_list )
		{
		if ( same_type(i.first->Type(), t->Type()) )
			return false;
		}

	auto e = std::make_pair(t, idx);
	case_label_type_list.push_back(e);

	return true;
	}

std::pair<int, ID*> SwitchStmt::FindCaseLabelMatch(const Val* v) const
	{
	int label_idx = -1;
	ID* label_id = 0;

	// Find matching expression cases.
	if ( case_label_value_map.Length() )
		{
		HashKey* hk = comp_hash->ComputeHash(v, 1);

		if ( ! hk )
			{
			reporter->PushLocation(e->GetLocationInfo());
			reporter->Error("switch expression type mismatch (%s/%s)",
					type_name(v->Type()->Tag()), type_name(e->Type()->Tag()));
			return std::make_pair(-1, nullptr);
			}

		if ( auto i = case_label_value_map.Lookup(hk) )
			label_idx = *i;

		delete hk;
		}

	// Find matching type cases.
	for ( auto i : case_label_type_list )
		{
		auto id = i.first;
		auto type = id->Type();

		if ( can_cast_value_to_type(v, type) )
			{
			label_idx = i.second;
			label_id = id;
			break;
			}
		}

	if ( label_idx < 0 )
		return std::make_pair(default_case_idx, nullptr);
	else
		return std::make_pair(label_idx, label_id);
	}

Val* SwitchStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	Val* rval = 0;

	auto m = FindCaseLabelMatch(v);
	int matching_label_idx = m.first;
	ID* matching_id = m.second;

	if ( matching_label_idx == -1 )
		return 0;

	for ( int i = matching_label_idx; i < cases->length(); ++i )
		{
		const Case* c = (*cases)[i];

		if ( matching_id )
			{
			auto cv = cast_value_to_type(v, matching_id->Type());
			f->SetElement(matching_id->Offset(), cv);
			}

		flow = FLOW_NEXT;
		rval = c->Body()->Exec(f, flow);

		if ( flow == FLOW_BREAK  || flow == FLOW_RETURN )
			break;
		}

	if ( flow != FLOW_RETURN )
		flow = FLOW_NEXT;

	return rval;
	}

int SwitchStmt::IsPure() const
	{
	if ( ! e->IsPure() )
		return 0;

	loop_over_list(*cases, i)
		{
		Case* c = (*cases)[i];
		if ( ! c->ExprCases()->IsPure() || ! c->Body()->IsPure() )
			return 0;
		}

	return 1;
	}

void SwitchStmt::Describe(ODesc* d) const
	{
	ExprStmt::Describe(d);

	if ( ! d->IsBinary() )
		d->Add("{");

	d->PushIndent();
	d->AddCount(cases->length());
	loop_over_list(*cases, i)
		(*cases)[i]->Describe(d);
	d->PopIndent();

	if ( ! d->IsBinary() )
		d->Add("}");
	d->NL();
	}

TraversalCode SwitchStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Index is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	loop_over_list(*cases, i)
		{
		tc = (*cases)[i]->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(SwitchStmt, SER_SWITCH_STMT);

bool SwitchStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SWITCH_STMT, ExprStmt);

	if ( ! SERIALIZE(cases->length()) )
		return false;

	loop_over_list((*cases), i)
		if ( ! (*cases)[i]->Serialize(info) )
			return false;

	if ( ! SERIALIZE(default_case_idx) )
		return false;

	return true;
	}

bool SwitchStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);

	Init();

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	while ( len-- )
		{
		Case* c = Case::Unserialize(info);
		if ( ! c )
			return false;

		cases->append(c);
		}

	if ( ! UNSERIALIZE(&default_case_idx) )
		return false;

	loop_over_list(*cases, i)
		{
		const ListExpr* le = (*cases)[i]->ExprCases();

		if ( ! le )
			continue;

		const expr_list& exprs = le->Exprs();

		loop_over_list(exprs, j)
			{
			if ( ! AddCaseLabelValueMapping(exprs[j]->ExprVal(), i) )
				return false;
			}
		}

	return true;
	}

AddStmt::AddStmt(Expr* arg_e) : ExprStmt(STMT_ADD, arg_e)
	{
	if ( ! e->CanAdd() )
		Error("illegal add statement");
	}

int AddStmt::IsPure() const
	{
	return 0;
	}

Val* AddStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	e->Add(f);
	return 0;
	}


TraversalCode AddStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Argument is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(AddStmt, SER_ADD_STMT);

bool AddStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ADD_STMT, ExprStmt);
	return true;
	}

bool AddStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);
	return true;
	}

DelStmt::DelStmt(Expr* arg_e) : ExprStmt(STMT_DELETE, arg_e)
	{
	if ( e->IsError() )
		return;

	if ( ! e->CanDel() )
		Error("illegal delete statement");
	}

int DelStmt::IsPure() const
	{
	return 0;
	}

Val* DelStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	e->Delete(f);
	return 0;
	}

TraversalCode DelStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Argument is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(DelStmt, SER_DEL_STMT);

bool DelStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_DEL_STMT, ExprStmt);
	return true;
	}

bool DelStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);
	return true;
	}

EventStmt::EventStmt(EventExpr* arg_e) : ExprStmt(STMT_EVENT, arg_e)
	{
	event_expr = arg_e;
	}

Val* EventStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	val_list* args = eval_list(f, event_expr->Args());

	if ( args )
		mgr.QueueEvent(event_expr->Handler(), args);

	flow = FLOW_NEXT;

	return 0;
	}

TraversalCode EventStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Event is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(EventStmt, SER_EVENT_STMT);

bool EventStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EVENT_STMT, ExprStmt);
	return event_expr->Serialize(info);
	}

bool EventStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);

	event_expr = (EventExpr*) Expr::Unserialize(info, EXPR_EVENT);
	return event_expr != 0;
	}

WhileStmt::WhileStmt(Expr* arg_loop_condition, Stmt* arg_body)
	: loop_condition(arg_loop_condition), body(arg_body)
	{
	if ( ! loop_condition->IsError() &&
	     ! IsBool(loop_condition->Type()->Tag()) )
		loop_condition->Error("while conditional must be boolean");
	}

WhileStmt::~WhileStmt()
	{
	Unref(loop_condition);
	Unref(body);
	}

int WhileStmt::IsPure() const
	{
	return loop_condition->IsPure() && body->IsPure();
	}

void WhileStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	loop_condition->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();
	d->PushIndent();
	body->AccessStats(d);
	body->Describe(d);
	d->PopIndent();
	}

TraversalCode WhileStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = loop_condition->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = body->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

Val* WhileStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	Val* rval = 0;

	for ( ; ; )
		{
		Val* cond = loop_condition->Eval(f);

		if ( ! cond )
			break;

		bool cont = cond->AsBool();
		Unref(cond);

		if ( ! cont )
			break;

		flow = FLOW_NEXT;
		rval = body->Exec(f, flow);

		if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
			break;
		}

	if ( flow == FLOW_LOOP || flow == FLOW_BREAK )
		flow = FLOW_NEXT;

	return rval;
	}

IMPLEMENT_SERIAL(WhileStmt, SER_WHILE_STMT);

bool WhileStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_WHILE_STMT, Stmt);

	if ( ! loop_condition->Serialize(info) )
		return false;

	return body->Serialize(info);
	}

bool WhileStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	loop_condition = Expr::Unserialize(info);

	if ( ! loop_condition )
		return false;

	body = Stmt::Unserialize(info);
	return body != 0;
	}

ForStmt::ForStmt(id_list* arg_loop_vars, Expr* loop_expr)
: ExprStmt(STMT_FOR, loop_expr)
	{
	loop_vars = arg_loop_vars;
	body = 0;

	if ( e->Type()->Tag() == TYPE_TABLE )
		{
		const type_list* indices = e->Type()->AsTableType()->IndexTypes();
		if ( indices->length() != loop_vars->length() )
			{
			e->Error("wrong index size");
			return;
			}

		for ( int i = 0; i < indices->length(); i++ )
			{
			BroType* ind_type = (*indices)[i]->Ref();

			if ( (*loop_vars)[i]->Type() )
				{
				if ( ! same_type((*loop_vars)[i]->Type(), ind_type) )
					(*loop_vars)[i]->Type()->Error("type clash in iteration", ind_type);
				}

			else
				{
				delete add_local((*loop_vars)[i],
						ind_type->Ref(), INIT_NONE,
						0, 0, VAR_REGULAR);
				}
			}
		}

	else if ( e->Type()->Tag() == TYPE_VECTOR )
		{
		if ( loop_vars->length() != 1 )
			{
			e->Error("iterating over a vector requires only a single index type");
			return;
			}

		BroType* t = (*loop_vars)[0]->Type();
		if ( ! t )
			delete add_local((*loop_vars)[0], base_type(TYPE_INT),
						INIT_NONE, 0, 0, VAR_REGULAR);

		else if ( ! IsIntegral(t->Tag()) )
			{
			e->Error("vector index in \"for\" loop must be integral");
			return;
			}
		}

	else if ( e->Type()->Tag() == TYPE_STRING )
		{
		if ( loop_vars->length() != 1 )
			{
			e->Error("iterating over a string requires only a single index type");
			return;
			}

		BroType* t = (*loop_vars)[0]->Type();
		if ( ! t )
			delete add_local((*loop_vars)[0],
					base_type(TYPE_STRING),
					INIT_NONE, 0, 0, VAR_REGULAR);

		else if ( t->Tag() != TYPE_STRING )
			{
			e->Error("string index in \"for\" loop must be string");
			return;
			}
		}
	else
		e->Error("target to iterate over must be a table, set, vector, or string");
	}

ForStmt::~ForStmt()
	{
	loop_over_list(*loop_vars, i)
		Unref((*loop_vars)[i]);
	delete loop_vars;

	Unref(body);
	}

Val* ForStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	Val* ret = 0;

	if ( v->Type()->Tag() == TYPE_TABLE )
		{
		TableVal* tv = v->AsTableVal();
		const PDict(TableEntryVal)* loop_vals = tv->AsTable();

		if ( ! loop_vals->Length() )
			return 0;

		HashKey* k;
		IterCookie* c = loop_vals->InitForIteration();
		while ( loop_vals->NextEntry(k, c) )
			{
			ListVal* ind_lv = tv->RecoverIndex(k);
			delete k;

			for ( int i = 0; i < ind_lv->Length(); i++ )
				f->SetElement((*loop_vars)[i]->Offset(), ind_lv->Index(i)->Ref());
			Unref(ind_lv);

			flow = FLOW_NEXT;
			ret = body->Exec(f, flow);

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				{
				// If we broke or returned from inside a for loop,
				// the cookie may still exist.
				loop_vals->StopIteration(c);
				break;
				}
			}
		}

	else if ( v->Type()->Tag() == TYPE_VECTOR )
		{
		VectorVal* vv = v->AsVectorVal();

		for ( int i = 0; i <= int(vv->Size()); ++i )
			{
			// Skip unassigned vector indices.
			if ( ! vv->Lookup(i) )
				continue;

			// Set the loop variable to the current index, and make
			// another pass over the loop body.
			f->SetElement((*loop_vars)[0]->Offset(),
					new Val(i, TYPE_INT));
			flow = FLOW_NEXT;
			ret = body->Exec(f, flow);

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				break;
			}
		}
	else if ( v->Type()->Tag() == TYPE_STRING )
		{
		StringVal* sval = v->AsStringVal();

		for ( int i = 0; i < sval->Len(); ++i )
			{
			f->SetElement((*loop_vars)[0]->Offset(),
					new StringVal(1, (const char*) sval->Bytes() + i));
			flow = FLOW_NEXT;
			ret = body->Exec(f, flow);

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				break;
			}
		}

	else
		e->Error("Invalid type in for-loop execution");

	if ( flow == FLOW_LOOP )
		flow = FLOW_NEXT;	// last iteration exited with a "next"

	if ( flow == FLOW_BREAK )
		flow = FLOW_NEXT;	// we've now finished the "break"

	return ret;
	}

int ForStmt::IsPure() const
	{
	return e->IsPure() && body->IsPure();
	}

void ForStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	if ( loop_vars->length() )
		d->Add("[");

	loop_over_list(*loop_vars, i)
		{
		(*loop_vars)[i]->Describe(d);
		if ( i > 0 )
			d->Add(",");
		}

	if ( loop_vars->length() )
		d->Add("]");

	if ( d->IsReadable() )
		d->Add(" in ");

	e->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();

	d->PushIndent();
	body->AccessStats(d);
	body->Describe(d);
	d->PopIndent();
	}

TraversalCode ForStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	loop_over_list(*loop_vars, i)
		{
		tc = (*loop_vars)[i]->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = LoopExpr()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = LoopBody()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(ForStmt, SER_FOR_STMT);

bool ForStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FOR_STMT, ExprStmt);

	if ( ! SERIALIZE(loop_vars->length()) )
		return false;

	loop_over_list((*loop_vars), i)
		{
		if ( ! (*loop_vars)[i]->Serialize(info) )
			return false;
		}

	return body->Serialize(info);
	}

bool ForStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	loop_vars = new id_list;

	while ( len-- )
		{
		ID* id = ID::Unserialize(info);
		if ( ! id )
			return false;

		loop_vars->append(id);
		}

	body = Stmt::Unserialize(info);
	return body != 0;
	}

Val* NextStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_LOOP;
	return 0;
	}

int NextStmt::IsPure() const
	{
	return 1;
	}

void NextStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode NextStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(NextStmt, SER_NEXT_STMT);

bool NextStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_NEXT_STMT, Stmt);
	return true;
	}

bool NextStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	return true;
	}

Val* BreakStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_BREAK;
	return 0;
	}

int BreakStmt::IsPure() const
	{
	return 1;
	}

void BreakStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode BreakStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(BreakStmt, SER_BREAK_STMT);

bool BreakStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BREAK_STMT, Stmt);
	return true;
	}

bool BreakStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	return true;
	}

Val* FallthroughStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_FALLTHROUGH;
	return 0;
	}

int FallthroughStmt::IsPure() const
	{
	return 1;
	}

void FallthroughStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode FallthroughStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(FallthroughStmt, SER_FALLTHROUGH_STMT);

bool FallthroughStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FALLTHROUGH_STMT, Stmt);
	return true;
	}

bool FallthroughStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	return true;
	}

ReturnStmt::ReturnStmt(Expr* arg_e) : ExprStmt(STMT_RETURN, arg_e)
	{
	Scope* s = current_scope();

	if ( ! s || ! s->ScopeID() )
		{
		Error("return statement outside of function/event");
		return;
		}

	FuncType* ft = s->ScopeID()->Type()->AsFuncType();
	BroType* yt = ft->YieldType();

	if ( s->ScopeID()->DoInferReturnType() )
		{
		if ( e )
			{
			ft->SetYieldType(e->Type());
			s->ScopeID()->SetInferReturnType(false);
			}
		}

	else if ( ! yt || yt->Tag() == TYPE_VOID )
		{
		if ( e )
			Error("return statement cannot have an expression");
		}

	else if ( ! e )
		{
		if ( ft->Flavor() != FUNC_FLAVOR_HOOK )
			Error("return statement needs expression");
		}

	else
		(void) check_and_promote_expr(e, yt);
	}

Val* ReturnStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_RETURN;

	if ( e )
		return e->Eval(f);
	else
		return 0;
	}

void ReturnStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	if ( ! d->IsReadable() )
		d->Add(e != 0);

	if ( e )
		{
		if ( ! d->IsBinary() )
			d->Add("(");
		e->Describe(d);
		if ( ! d->IsBinary() )
			d->Add(")");
		}

	DescribeDone(d);
	}

IMPLEMENT_SERIAL(ReturnStmt, SER_RETURN_STMT);

bool ReturnStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RETURN_STMT, ExprStmt);
	return true;
	}

bool ReturnStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ExprStmt);
	return true;
	}

StmtList::StmtList() : Stmt(STMT_LIST)
	{
	}

StmtList::~StmtList()
	{
	loop_over_list(stmts, i)
		Unref(stmts[i]);
	}

Val* StmtList::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	loop_over_list(stmts, i)
		{
		f->SetNextStmt(stmts[i]);

		if ( ! pre_execute_stmt(stmts[i], f) )
			{ // ### Abort or something
			}

		Val* result = stmts[i]->Exec(f, flow);

		if ( ! post_execute_stmt(stmts[i], f, result, &flow) )
			{ // ### Abort or something
			}

		if ( flow != FLOW_NEXT || result || f->HasDelayed() )
			return result;
		}

	return 0;
	}

int StmtList::IsPure() const
	{
	loop_over_list(stmts, i)
		if ( ! stmts[i]->IsPure() )
			return 0;
	return 1;
	}

void StmtList::Describe(ODesc* d) const
	{
	if ( ! d->IsReadable() )
		{
		AddTag(d);
		d->AddCount(stmts.length());
		}

	if ( stmts.length() == 0 )
		DescribeDone(d);

	else
		{
		if ( ! d->IsBinary() )
			{
			d->Add("{ ");
			d->NL();
			}

		loop_over_list(stmts, i)
			{
			stmts[i]->Describe(d);
			d->NL();
			}

		if ( ! d->IsBinary() )
			d->Add("}");
		}
	}

TraversalCode StmtList::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	loop_over_list(stmts, i)
		{
		tc = stmts[i]->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(StmtList, SER_STMT_LIST);

bool StmtList::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_STMT_LIST, Stmt);

	if ( ! SERIALIZE(stmts.length()) )
		return false;

	loop_over_list(stmts, i)
		if ( ! stmts[i]->Serialize(info) )
			return false;

	return true;
	}

bool StmtList::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	while ( len-- )
		{
		Stmt* stmt = Stmt::Unserialize(info);
		if ( ! stmt )
			return false;

		stmts.append(stmt);
		}

	return true;
	}


Val* EventBodyList::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	loop_over_list(stmts, i)
		{
		f->SetNextStmt(stmts[i]);

		// Ignore the return value, since there shouldn't be
		// any; and ignore the flow, since we still execute
		// all of the event bodies even if one of them does
		// a FLOW_RETURN.
		if ( ! pre_execute_stmt(stmts[i], f) )
			{ // ### Abort or something
			}

		Val* result = stmts[i]->Exec(f, flow);

		if ( ! post_execute_stmt(stmts[i], f, result, &flow) )
			{ // ### Abort or something
			}
		}

	// Simulate a return so the hooks operate properly.
	stmt_flow_type ft = FLOW_RETURN;
	(void) post_execute_stmt(f->GetNextStmt(), f, 0, &ft);

	return 0;
	}

void EventBodyList::Describe(ODesc* d) const
	{
	if ( d->IsReadable() && stmts.length() > 0 )
		{
		loop_over_list(stmts, i)
			{
			if ( ! d->IsBinary() )
				{
				d->Add("{");
				d->PushIndent();
				stmts[i]->AccessStats(d);
				}

			stmts[i]->Describe(d);

			if ( ! d->IsBinary() )
				{
				d->Add("}");
				d->PopIndent();
				}
			}
		}

	else
		StmtList::Describe(d);
	}

IMPLEMENT_SERIAL(EventBodyList, SER_EVENT_BODY_LIST);

bool EventBodyList::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EVENT_BODY_LIST, StmtList);
	return SERIALIZE(topmost);
	}

bool EventBodyList::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(StmtList);
	return UNSERIALIZE(&topmost);
	}

InitStmt::~InitStmt()
	{
	loop_over_list(*inits, i)
		Unref((*inits)[i]);

	delete inits;
	}

Val* InitStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	loop_over_list(*inits, i)
		{
		ID* aggr = (*inits)[i];
		BroType* t = aggr->Type();

		Val* v = 0;

		switch ( t->Tag() ) {
		case TYPE_RECORD:
			v = new RecordVal(t->AsRecordType());
			break;
		case TYPE_VECTOR:
			v = new VectorVal(t->AsVectorType());
			break;
		case TYPE_TABLE:
			v = new TableVal(t->AsTableType(), aggr->Attrs());
			break;
		default:
			break;
		}

		f->SetElement(aggr->Offset(), v);
		}

	return 0;
	}

void InitStmt::Describe(ODesc* d) const
	{
	AddTag(d);

	if ( ! d->IsReadable() )
		d->AddCount(inits->length());

	loop_over_list(*inits, i)
		{
		if ( ! d->IsBinary() && i > 0 )
			d->AddSP(",");

		(*inits)[i]->Describe(d);
		}

	DescribeDone(d);
	}

TraversalCode InitStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	loop_over_list(*inits, i)
		{
		tc = (*inits)[i]->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(InitStmt, SER_INIT_STMT);

bool InitStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_INIT_STMT, Stmt);

	if ( ! SERIALIZE(inits->length()) )
		return false;

	loop_over_list((*inits), i)
		{
		if ( ! (*inits)[i]->Serialize(info) )
			return false;
		}

	return true;
	}

bool InitStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	inits = new id_list;

	while ( len-- )
		{
		ID* id = ID::Unserialize(info);
		if ( ! id )
			return false;
		inits->append(id);
		}
	return true;
	}


Val* NullStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	return 0;
	}

int NullStmt::IsPure() const
	{
	return 1;
	}

void NullStmt::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		DescribeDone(d);
	else
		AddTag(d);
	}

TraversalCode NullStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(NullStmt, SER_NULL_STMT);

bool NullStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_NULL_STMT, Stmt);
	return true;
	}

bool NullStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);
	return true;
	}

WhenStmt::WhenStmt(Expr* arg_cond, Stmt* arg_s1, Stmt* arg_s2,
			Expr* arg_timeout, bool arg_is_return)
: Stmt(STMT_WHEN)
	{
	assert(arg_cond);
	assert(arg_s1);

	cond = arg_cond;
	s1 = arg_s1;
	s2 = arg_s2;
	timeout = arg_timeout;
	is_return = arg_is_return;

	if ( ! cond->IsError() && ! IsBool(cond->Type()->Tag()) )
		cond->Error("conditional in test must be boolean");

	if ( timeout )
		{
		if ( timeout->IsError() )
			return;

		TypeTag bt = timeout->Type()->Tag();
		if ( bt != TYPE_TIME && bt != TYPE_INTERVAL )
			cond->Error("when timeout requires a time or time interval");
		}
	}

WhenStmt::~WhenStmt()
	{
	Unref(cond);
	Unref(s1);
	Unref(s2);
	}

Val* WhenStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	::Ref(cond);
	::Ref(s1);
	if ( s2 )
		::Ref(s2);
	if ( timeout )
		::Ref(timeout);

	// The new trigger object will take care of its own deletion.
	new Trigger(cond, s1, s2, timeout, f, is_return, location);

	return 0;
	}

int WhenStmt::IsPure() const
	{
	return cond->IsPure() && s1->IsPure() && (! s2 || s2->IsPure());
	}

void WhenStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	cond->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();
	d->PushIndent();
	s1->AccessStats(d);
	s1->Describe(d);
	d->PopIndent();

	if ( s2 )
		{
		if ( d->IsReadable() )
			{
			d->SP();
			d->Add("timeout");
			d->SP();
			timeout->Describe(d);
			d->SP();
			d->PushIndent();
			s2->AccessStats(d);
			s2->Describe(d);
			d->PopIndent();
			}
		else
			s2->Describe(d);
		}
	}

TraversalCode WhenStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cond->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = s1->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	if ( s2 )
		{
		tc = s2->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IMPLEMENT_SERIAL(WhenStmt, SER_WHEN_STMT);

bool WhenStmt::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_WHEN_STMT, Stmt);

	if ( cond->Serialize(info) && s1->Serialize(info) )
		return false;

	SERIALIZE_OPTIONAL(s2);
	SERIALIZE_OPTIONAL(timeout);

	return true;
	}

bool WhenStmt::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Stmt);

	cond = Expr::Unserialize(info);
	if ( ! cond )
		return false;

	s1 = Stmt::Unserialize(info);
	if ( ! s1 )
		return false;

	UNSERIALIZE_OPTIONAL(s2, Stmt::Unserialize(info));
	UNSERIALIZE_OPTIONAL(timeout, Expr::Unserialize(info));

	return true;
	}
