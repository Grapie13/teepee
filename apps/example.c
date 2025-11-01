#include <stdio.h>
#include <teepee/teepee.h>

int main()
{
  teepee_result *result = teepee("www.gnu.org");

  if (result->ok != 0) {
    teepee_error *error = result->error;

    printf("Request failed with code %d", error->code);
    printf("Error message: %s", error->message);
    free_teepee_result(result);
    return 1;
  }

  printf("Response: %s", result->body);
  free_teepee_result(result);
}