# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b %INPUT
# @TEST-EXEC: btest-bg-wait 60

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	r.a	r.b	r.c	
#types	int	bool	string	string	string
1	T	a	b	c
2	T	a	b	c
3	F	ba	bb	bc
4	T	bb	bd	-
5	F	a	b	c
6	T	a	b	c
7	T	a	b	c
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Sub: record {
	a: string;
	aa: string &optional;
	b : string;
	bb: string &optional;
	c: string &optional;
	d: string &optional;
};

type Val: record {
	i: int;
	b: bool;
	notb: bool &optional;
	r: Sub;
};

event servers(desc: Input::EventDescription, tpe: Input::Event, item: Val)
	{
	print outfile, item;
	}

event bro_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_event([$source="../input.log", $name="input", $fields=Val, $ev=servers]);
	}

event Input::end_of_data(name: string, source: string)
	{
	Input::remove("input");
	close(outfile);
	terminate();
	}
