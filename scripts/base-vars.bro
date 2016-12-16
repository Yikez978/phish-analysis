module Phish;
	
export {

	 global uninterestig_fqdns : opaque of bloomfilter ;
	
	        type fqdn_rec : record {
                days_visited: vector of time  ;
                num_requests: count &default=0 ;
                last_visited: time ;
                interesting: bool &default=T  ;
         } ;

        global http_fqdn: table[string] of fqdn_rec ;
	

	#########
	 type from_rec : record {
                days_sent: vector of time  ;
                email: set[string];
                emails_sent: count &default=0 ;
                emails_recv: count &default=0 ;
		num_clicks: count &default=0 ; 
                interesting: bool &default=F  ;
         } ;

        global smtp_from: table[string] of from_rec ;

        type from_name_rec : record {
                days_sent: vector of time  ;
                email: set[string];
                emails_sent: count &default=0 ;
                emails_recv: count &default=0 ;
		num_clicks: count &default=0 ; 
                interesting: bool &default=F  ;
         } ;


        global smtp_from_name: table[string] of from_name_rec ;

        type from_email_rec : record {
                days_sent: vector of time  ;
                name: set[string];
                emails_sent: count &default= 0 ;
                emails_recv: count &default=0 ;
		num_clicks: count &default=0 ; 
                interesting: bool &default=F  ;
         } ;

        global smtp_from_email: table[string] of from_email_rec;


	#### recording how many emails reach name/email gets 
	type recv_to_name: record{ 
                emails_recv: count &default=0 ;
	}; 
	
	global email_recv_to_name: table [string] of recv_to_name ; 

	type recv_to_address: record{ 
                emails_recv: count &default=0 ;
	}; 
	
	global email_recv_to_address: table [string] of recv_to_address ; 


		
        type smtp_rec: record {
                ts: time ;
                from: string ;
        } ;

	#############


	global extract_host : function(name: string): string; 
	global find_all_urls : function(s: string): string_set; 
	global find_all_urls_without_scheme : function(s: string): string_set ; 

	global process_smtp_urls: event(c: connection, url: string);
} 



function extract_host(name: string): string
{
        local split_on_slash = split_string(name, /\//);
        local num_slash = |split_on_slash|;

# ash
        return split_on_slash[2];
}

# Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
    {
    return find_all(s, url_regex);
    }


# Extracts URLs discovered in arbitrary text without
# the URL scheme included.
function find_all_urls_without_scheme(s: string): string_set
{
        local urls = find_all_urls(s);
        local return_urls: set[string] = set();
        for ( url in urls )
                {
                local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
                add return_urls[no_scheme];
                }

        return return_urls;
}

