#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }
  
  char *uid;
  int auth = is_member(argv, data, &uid);

  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }
/**
    YOUR CODE GOES HERE
*/
  char   *to = "";
  char   *to_uid;
  size_t tmp_size;
  int    rep;
  xbuf_t *tmp;

  get_arg("to=", &to, argc, argv);
  tmp_size = strlen(to);
  if(tmp_size < 1) return 400; // Bad request
  to_uid = get_uid_from_username(argv, data, to);

  if(to_uid == NULL)
  {
    free(uid);
    return 503; // service unavailable
  }

  rep = follow(argv, data, uid, to_uid);

  tmp = (xbuf_t *) malloc(sizeof(xbuf_t));
  xbuf_init(tmp);
  xbuf_xcat(tmp, "Location: /?profile&user=%s&from_follow=%s\r\n"
  , to, rep == 0 ? "success" : "already_following");

  http_header(HEAD_ADD, tmp->ptr, tmp->len, argv);

  xbuf_free(tmp);
  free(tmp);
  free(uid);
  return 302;
}
