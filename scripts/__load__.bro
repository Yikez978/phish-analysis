module Phish ; 

#redef exit_only_after_terminate = T; 
redef table_expire_interval = 1 secs ;
redef table_incremental_step=20000 ; 

@load ./base-vars.bro 

@load ./log-smtp-urls.bro 
@load ./log-clicked-urls.bro

@load ./smtp-sensitive-uris.bro                 
@load ./smtp-malicious-indicators.bro 

@load ./rare-action-urls.bro                    
@load ./rare-action-email.bro

@load ./distribute-smtp-urls-workers.bro
@load ./smtp-url-clicks.bro

@load ./main-logic.bro 

@load ./http-sensitive_POSTs.bro
@load ./smtp-file-download.bro

@load ./configure-variables-in-this-file.bro    
@load ./bro-done.bro 
@load ./smtp-analysis-notice-policy.bro

