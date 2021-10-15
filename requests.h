#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// authorization header and cookies can be set to NULL if not needed)
char *compute_get_request(char *host, char *url, char *query_params,
						  char* authorization,
						  char **cookies, int cookies_count);

// computes and returns a POST request string
// (cookies and authorization header can be NULL if not needed)
char *compute_post_request(char *host, char *url, char* authorization,
						   char* content_type, char **body_data,
						   int body_data_fields_count, char** cookies, int cookies_count);

// computes and return a DELETE request string
// (cookies and authorization header can be NULL if not needed)
char *compute_delete_request(char *host, char *url,
                             char* authorization,
                             char **cookies, int cookies_count);

#endif
