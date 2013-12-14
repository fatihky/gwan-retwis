#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
//  xbuf_t *reply = get_reply ( argv );

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }
  
  char *uid, *postid = "", *return_url="";
  int auth = is_member(argv, data, &uid);
  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }

  get_arg("postid=", &postid, argc, argv);
  get_arg("return_url=", &return_url, argc, argv);
  if(strlen(postid) == 0 || strlen(return_url) == 0)
    return 400; // bad request

  char *gecici = NULL;
  del_post (argv, data, uid, (u64)strtoll(postid, &gecici, 10));
  {
    unescape_html((u8 *)return_url);
    xbuf_t redir;

    xbuf_init(&redir);
    xbuf_xcat(&redir, "Location: /%s\r\n", return_url);
    http_header(HEAD_ADD, redir.ptr, redir.len, argv);
    xbuf_free(&redir);
  }

  free(uid);
  return 302;
}
