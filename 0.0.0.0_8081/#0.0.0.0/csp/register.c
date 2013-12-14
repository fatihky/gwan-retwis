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

  if(auth == true)
  {
    free(uid);
    static char redir[] = "Location: /?profile\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }

  if ( ((int) get_env(argv, REQUEST_METHOD)) != 3 )
  {
    xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
    xbuf_repl(reply, "<!--title-->", "Register - retwis-c");
    xbuf_repl(reply, "<!--register_form-->", REGISTER_FORM);
    xbuf_repl(reply, "<!--login_form-->", LOGIN_FORM);
    return 200;
  }
  else
  {
    return add_user (argc, argv, data, reply);
  }

  return 200;
}
