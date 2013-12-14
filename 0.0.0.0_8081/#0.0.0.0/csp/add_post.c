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

/**
    YOUR CODE GOES HERE
*/

  if ( ((int) get_env(argv, REQUEST_METHOD)) != 3 )
  {
    static char redir[] = "Location: /\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }
  
  char *post = "";
  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }

  get_arg("post=", &post, argc, argv);
  if(strlen(post) < 1) goto fill_the_form;

  add_post (argv, data, uid, post, NULL);
  {
    static char redir[] = "Location: /?profile\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir), argv);
  }
  free(uid);
  return 302;

fill_the_form:
  xbuf_ncat(reply, data->profile_page->ptr, data->profile_page->len);
  xbuf_repl(reply, "<!--title-->", "Profile - retwis-c");
  xbuf_repl(reply, "<!--content-->", "welcome!</br>[form]</br>[posts]");
  xbuf_repl(reply, "[form]", NEW_POST_FORM);
  xbuf_repl(reply, "<!--form_errors-->", "You must fill the form and post again.");
  xbuf_t *timeline = get_timeline(argv, data, uid, 0, 30);
  xbuf_repl(reply, "[posts]", timeline ? timeline->ptr : "You didn't send anything.</br>");

  xbuf_free(timeline);
  free(timeline);
  free(uid);
  return 200;
}
