#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
  xbuf_t *reply = get_reply ( argv );

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }
  
  char *uid;
  int auth = is_member(argv, data, &uid);

  if ( ((int) get_env(argv, REQUEST_METHOD)) != 3 )
  {
    xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
    xbuf_repl(reply, "<!--title-->", "Register / Login - retwis-c");
    xbuf_repl(reply, "<!--register_form-->", LOGIN_FORM);
    return 200;
  }
  else
  {
    return login (argc, argv, data);
  }

  if(auth == true) free(uid);
  return 200;
}
