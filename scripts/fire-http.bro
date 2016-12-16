module HTTP; 


event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	print fmt("event http_header: name: %s, value: %s", name, value);
	}

event http_request(c:connection, method:string, original_URI: string, unescaped_URI: string, version: string)
        {
	print fmt("event http_request: method: %s, Original_URI: %s, unescaped_URI: %s, version: %s", method, original_URI, unescaped_URI, version);
	}
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	print fmt("event http_reply");
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	print fmt("event http_all_headers: hlist: %s", hlist);
	}

event http_begin_entity(c: connection, is_orig: bool)
	{
	print fmt("event http_begin_entity");

	}

event http_end_entity(c: connection, is_orig: bool)
	{
	print fmt("event http_end_entity");
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	print fmt("event http_entity_data");
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) 
	{
	print fmt("event http_content_type");

	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) 
	{
	print fmt("event http_message_done: %s, %s %s %s", c$id, c$http, is_orig, stat);
	}

event http_event(c: connection, event_type: string, detail: string)
	{
	print fmt("event http_event");
	}

event http_stats(c: connection, stats: http_stats_rec)
	{
	print fmt("event http_stats");
	}

event http_signature_found(c: connection)
	{
	print fmt("event http_signature_found");
	}

event http_proxy_signature_found(c: connection)
	{
	print fmt("event http_proxy_signature_found");
	}


event log_http(rec: Info)
{
	print fmt ("event log http: %s", rec);
}
	
event bro_done()
        {
	print fmt("---------------------------------------------------------------");
	print fmt("Bro is done");
        }

