# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-wait 25

# @TEST-EXEC: btest-diff manager-1/.stdout
#
@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

global c = 0;

event do_observe()
	{
	print "do observe", c;
	SumStats::observe("test",
	                  [$str=cat(c)],
	                  [$num=c]
	                  );
	++c;
	schedule 0.1secs { do_observe() };
	}

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="test",
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1
	                             );

	SumStats::create([$name="test",
	                  $epoch=10secs,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return 2.0; },
	                  $threshold = 1.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  {
	                  local l = SumStats::get_last(result["test"]);
	                  print "test thresh crossed", l;

	                  if ( l[0]$num == 7 )
	                      terminate();
	                  }
	                 ]);
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node up", name;

	if ( Cluster::node == "worker-1" && name == "manager-1" )
		schedule 0.1secs { do_observe() };
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node down", name;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, id: string)
	{
	terminate();
	}
