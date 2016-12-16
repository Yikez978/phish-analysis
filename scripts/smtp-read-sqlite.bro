module Phish; 

export {

	global tmpset: set[string] &create_expire=1 mins; 

	global Phish::sqlite_line: event(description: Input::EventDescription, tpe: Input::Event, r: SQLITE::Log); 
	global sql_read: event(domain: string); 
}


event Phish::sql_read(host: string)
{


	if (host !in tmpset)
        {
		log_reporter(fmt("SQL READ: sql_read: %s", host),0); 
                add tmpset[host];

                Input::add_event( [
                        $source=SQLITE::http_reputation_db,
                        $name=host,
                        $fields=SQLITE::Log,
                        $ev=Phish::sqlite_line,
                        $want_record=T,
                        $config=table( ["query"] = fmt("select * from http_fqdn where domain='%s' ;", host) ),
                        $reader=Input::READER_SQLITE
                ]);
        }
} 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

event Phish::sqlite_line(description: Input::EventDescription, tpe: Input::Event, r: SQLITE::Log)
{
    	log_reporter(fmt("SQL READ: sqlite_line: returned: %s", r),0); 

	# populate bloomfilter with wellknown domain

	bloomfilter_add(Phish::uninterestig_fqdns, r$domain); 
	
	# clear up the rare domain table 
	delete http_fqdn[r$domain]; 
}


event Phish::process_smtp_urls(c: connection, url: string)
{
        local host = extract_host(url);

	event Phish::sql_read(host); 
}


event Input::end_of_data(name: string, source:string)
    {
    if ( source == SQLITE::http_reputation_db )
        Input::remove(name);
    }



event bro_init()
    {
        Input::add_event(
            [
            $source=SQLITE::http_reputation_db, 
            $name="http_fqdn",
            $fields=SQLITE::Log,
            $ev=sqlite_line,
            $want_record=T,
            $config=table(
                ["query"] = fmt("select * from http_fqdn;")
                ),
            $reader=Input::READER_SQLITE
            ]);
    }

@endif 
