#include <stdio.h>
#include <teepee/teepee.h>
#include <stdlib.h>

int main()
{
  teepee_opts opts;
  opts.method = GET;
  opts.headers = malloc(sizeof(teepee_header));
  opts.headers[0] = (teepee_header) {"x-example-header", "true"};
  opts.header_size = 1;
  opts.data = NULL;
  opts.secure = 1;
  teepee_result *result = teepee("www.gnu.org", &opts);

  if (result->ok != 0) {
    teepee_error *error = result->error;

    printf("Request failed with code %d", error->code);
    printf("Error message: %s", error->message);
    free(opts.headers);
    free_teepee_result(result);
    return 1;
  }

  printf("Response: %s", result->body);
  free(opts.headers);
  free_teepee_result(result);
}
