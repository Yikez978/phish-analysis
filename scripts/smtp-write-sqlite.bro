# expanded from sql_logger.bro  original author: Scott Campbell Oct 1, 2013
# aashish sharma, Feb, 14, 2014 
#
# The database needs to be created before hand with the record type being
#  identical as the Log record type.

@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module SQLITE;

export {
	global db_loaded = 1;
        redef enum Log::ID += { LOG };

        type Log: record {
		ts: time ;    
		domain: string;
		} &log;

	redef Input::accept_unsupported_types = T;
	global sql_write: event(_domain: string);

	global http_reputation_db: string = "" ; 


	}

event sql_write(ds: string)
	{
	# since the database is living on the management node, we need to use a simple test 
	#  to avoid untold pain and suffering...
	#

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("SQL sql_write: WRITE %s", ds),0) ;
		Log::write(SQLITE::LOG, [ $ts=network_time(), $domain=ds ]);
		}
	}

event bro_init()
{
	# This will initialize a database at the $path location with table name $name. 
	# Will open to append in the event that data already exists there.
	# 
	#print fmt("Initializing sql logger ...");

        Log::remove_filter(SQLITE::LOG, "default");
        Log::create_stream(SQLITE::LOG, [$columns=Log]);

	
	local config_strings: table[string] of string = {
		["tablename"] = "http_fqdn"
		};

	local dir = @DIR; 
	http_reputation_db = fmt("%s/datastore/http_reputation_db", dir) ; 
	#http_reputation_db = fmt("/home/bro/datastore/http_reputation_db"); 

        local filter: Log::Filter = [$name="sql_a", $path=http_reputation_db, $writer=Log::WRITER_SQLITE, $config=config_strings];
        Log::add_filter(SQLITE::LOG, filter);
	
	event SQLITE::sql_write("myrandomraretestdomain.blah"); 

}

	

event bro_done()
{
	event SQLITE::sql_write("times.com"); 

} 
