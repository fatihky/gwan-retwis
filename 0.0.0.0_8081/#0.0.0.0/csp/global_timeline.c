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

  xbuf_ncat(reply, data->main_page->ptr, data->main_page->len);
  xbuf_repl(reply, "<!--title-->", "Profile - retwis-c");
  xbuf_repl(reply, "<!--content-->", "welcome!<br/>[form]<br/>[timeline]");
  xbuf_repl(reply, "[form]", NEW_POST_FORM);

  xbuf_t *timeline = get_timeline(argv, data, NULL, 0, 30);
  xbuf_repl(reply, "[timeline]", timeline ? timeline->ptr : "You didn't send anything.</br>");
  printf("f: %s\n", timeline ? timeline->ptr : "You didn't send anything.</br>" );
  xbuf_free(timeline);

  if(auth == true) free(uid);
  return 200;
}
