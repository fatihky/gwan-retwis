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
  
  char *uid = NULL;
  char *username = NULL;
  int auth = is_member(argv, data, &uid);

  get_arg("user=", &username, argc, argv);

  if(username == NULL && auth != true)
  {
    if(uid != NULL) free(uid);
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }

  xbuf_ncat(reply, data->followings_page->ptr, data->followings_page->len);
  xbuf_repl(reply, "<!--title-->", "<!--viewing_user's_username-->'s followings");

  if(username != NULL)
  {
    uid = get_uid_from_username(RA_, username);
  }

  if(uid == NULL)
  {
    free(uid);
    xbuf_empty(reply);
    return 404;
  }

  return get_followings_list(RA_, reply, uid);
}
