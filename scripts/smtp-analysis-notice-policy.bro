hook Notice::policy(n: Notice::Info)
{

  if ( n$note == Phish::BogusSiteURL) 
   { add n$actions[Notice::ACTION_EMAIL];} 

}
