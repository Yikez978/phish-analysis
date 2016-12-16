module Phish;

export {

	    redef enum Log::ID += { Links_LOG };

	    type Info: record {
                # When the email was seen.
                ts:   time    &log;
                # Unique ID for the connection.
                uid:  string  &log;
                # Connection details.
                id:   conn_id &log;
                # url that was discovered.
		host: string &log &optional ; 
                url:  string  &log &optional;

        };

	 redef enum Notice::Type += {
		MsgBody, 
	}; 

	#global url_dotted_pattern: pattern = /href.*http:\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*\"/ ; 
	global url_dotted_pattern: pattern = /([^"#]+)/; 

	const url_regex = /^https?:\/\/([a-z0-9A-Z]+(:[a-zA-Z0-9]+)?@)?[-a-z0-9A-Z\-]+(\.[-a-z0-9A-Z\-]+)*((:[0-9]+)?)(\/[a-zA-Z0-9;:\/\.\-_+%~?&amp;@=#\(\)]*)?/ ;
	global suspicious_text_in_body: pattern &redef ;

	global log_smtp_urls: function(c:connection, url:string); 
} 

redef record connection += {
        smtp_url: Info &optional;
};


event bro_init() &priority=5
{
        Log::create_stream(Phish::Links_LOG, [$columns=Info]);

} 

event Phish::process_smtp_urls(c: connection, url: string)
{ 
	log_smtp_urls(c, url); 
	
} 

function log_smtp_urls(c:connection, url:string)
{
		local info: Info; 

		info$ts = c$smtp$ts;
               	info$uid = c$smtp$uid ;
                info$id = c$id ;
               	info$url = url;
		info$host = extract_host(url) ;  

              	c$smtp_url = info;
               
		Log::write(Phish::Links_LOG, c$smtp_url);
} 


event mime_all_data(c: connection, length: count, data: string) &priority=-5
{
	if (! c?$smtp) 
		return ;

	local urls = find_all_urls(data) ; 

	for (link in urls)
	{
		#log_smtp_urls(c, link);
		event Phish::process_smtp_urls(c, link);
	} 
                
	if ( suspicious_text_in_body in data && /[Cc][Ll][Ii][Cc][Kk] [Hh][Ee][Rr][Ee]/ in data)
        {
        	NOTICE([$note=MsgBody, $msg=fmt("Click Here seen in the email %s from  %s", link, c$smtp$uid), $conn=c]);
       	}
}
