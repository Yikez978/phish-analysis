module Phish ; 

#redef exit_only_after_terminate = T; 

export {

	global log_stats: event(); 
	
	global log_reporter: function (msg: string, debug: count); 

	redef Site::local_nets += { 128.3.0.0/16, 131.243.0.0/16, }; 
} 


function  log_reporter(msg: string, debug: count)
{
        #if (debug > 0 ) {
                #event reporter_info(network_time(), msg, peer_description);
        #}

        local DEBUG = 0 ;

if (DEBUG == 0) {
		@if ( ! Cluster::is_enabled())
			print fmt("%s", msg);
		@endif 
		event reporter_info(network_time(), msg, peer_description);

		}
}

@load ./base-vars.bro 
@load ./smtp-write-sqlite.bro
@load ./smtp-read-sqlite.bro

@load ./log-smtp-urls.bro 

@load ./smtp-sensitive-uris.bro                 
@load ./smtp-malicious-indicators.bro 

@load ./main-logic.bro 

@load ./rare-action-urls.bro                    
@load ./rare-action-email.bro
@load ./smtp-url-clicks.bro

@load ./http-sensitive_POSTs.bro
@load ./smtp-file-download.bro

@load ./configure-variables-in-this-file.bro    
@load ./smtp-analysis-notice-policy.bro

@load ./bro-done.bro 


#@load ./smtp-urls-log.bro 
#@load ./smtp-urls-click.bro 
#@load ./smtp-sensitive-uri.bro
#@load ./smtp-malicious-urls.bro 
#@load ./smtp-high-volume-sender-subjects.bro 

