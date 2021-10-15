#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

// post register request to server
void register_command() {
    // read user data from stdin
    char username[50];
    char password[50];

    printf("username=");
    scanf("%s", username);
    printf("password=");
    scanf("%s", password);

    int sockfd;
    char* message;
    char* response;

    // construct json with client data
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *json_data = json_value_get_object(root_value);
    char* login_data = NULL;

    json_object_set_string(json_data, "username", username);
    json_object_set_string(json_data, "password", password);

    login_data = json_serialize_to_string_pretty(root_value);

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // get post request message
    message = compute_post_request("34.118.48.238",
                                   "/api/v1/tema/auth/register",
                                   NULL,
                                   "application/json",
                                   &login_data,
                                   1,
                                   NULL,
                                   0);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == BAD_REQUEST) {
        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);
    } else if (status_code == CREATED) {
        printf("user created\n");
    }

    // close server connection
    close_connection(sockfd);
    json_free_serialized_string(login_data);
    json_value_free(root_value);
    free(message);
    free(response);
}

// post login request to server
char* login_command() {
    // get user data from stdin
    char username[50];
    char password[50];

    printf("username=");
    scanf("%s", username);
    printf("password=");
    scanf("%s", password);

    int sockfd;
    char* message;
    char* response;
    char* session_cookie = NULL;

    // create json with user data
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *json_data = json_value_get_object(root_value);
    char* login_data = NULL;

    json_object_set_string(json_data, "username", username);
    json_object_set_string(json_data, "password", password);

    login_data = json_serialize_to_string_pretty(root_value);

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // get post request message
    message = compute_post_request("34.118.48.238",
                                   "/api/v1/tema/auth/login",
                                   NULL,
                                   "application/json",
                                   &login_data, 1,
                                   NULL, 0);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == BAD_REQUEST) {
        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);
    } else if (status_code == OK) {
        printf("you are logged in\n");

        // extract session cookie
        session_cookie = calloc(LINELEN, sizeof(char));
        char* cookie = strstr(response, "connect.sid=");

        if (cookie == NULL) {
            error("session cookie not found");
        } else {
            sscanf(cookie, "%s", session_cookie);
            session_cookie[strlen(session_cookie) - 1] = '\0';
        }
    }

    // close server connection
    close_connection(sockfd);
    json_free_serialized_string(login_data);
    json_value_free(root_value);
    free(message);
    free(response);

    return session_cookie;
}

// get access to library
char* enter_library(char* session_cookie) {
    int sockfd;
    char* message;
    char* response;
    char* jwt_token = NULL;

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // get request message
    message = compute_get_request("34.118.48.238",
                                   "/api/v1/tema/library/access",
                                   NULL,
                                   NULL,
                                   &session_cookie, 1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == FORBIDDEN ||
        status_code == BAD_REQUEST ||
        status_code == UNAUTHORIZED) {

        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);

    } else if (status_code == OK) {
        printf("entered library\n");

        // parse jwt token
        jwt_token = calloc(LINELEN, sizeof(char));

        char* token = NULL;
        char* payload = basic_extract_json_response(response);
        JSON_Value *json = json_parse_string(payload);
        token = (char*)json_object_get_string(json_object(json), "token");

        sprintf(jwt_token, "Bearer %s", token);
        json_value_free(json);
    }

    // close server connection
    close_connection(sockfd);
    free(message);
    free(response);

    return jwt_token;
}

// get information about all books
void get_books(char* session_cookie, char* jwt_token) {
    int sockfd;
    char* message;
    char* response;

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // get request message
    message = compute_get_request("34.118.48.238",
                                 "/api/v1/tema/library/books/",
                                 NULL,
                                 jwt_token,
                                 &session_cookie, 1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == FORBIDDEN) {
        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);
    } else if (status_code == OK) {
        printf("books in library:\n");
        char* books_info = strstr(response, "[");
        printf("%s\n", books_info);
    }

    // close server connection
    close_connection(sockfd);
    free(message);
    free(response);
}

// get information about a book with given id
void get_book(char* session_cookie, char* jwt_token) {
    int sockfd;
    char* message;
    char* response;

    // get id from stdin
    int id;
    printf("id=");
    scanf("%d", &id);

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    char url[50];
    sprintf(url, "/api/v1/tema/library/books/%d", id);

    // get request message
    message = compute_get_request("34.118.48.238",
                                 url,
                                 NULL,
                                 jwt_token,
                                 &session_cookie, 1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == FORBIDDEN ||
        status_code == NOT_FOUND ||
        status_code == UNAUTHORIZED) {

        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);

    } else if (status_code == OK) {
        printf("book information:\n");
        char* info = basic_extract_json_response(response);
        JSON_Value *json = json_parse_string(info);
        char* book_info = json_serialize_to_string_pretty(json);
        printf("%s\n", book_info);
        json_value_free(json);
    }

    // close server connection
    close_connection(sockfd);
    free(response);
    free(message);
}

// add book to library
void add_book(char* session_cookie, char* jwt_token) {
    int sockfd;
    char* message;
    char* response;

    char* buf = NULL;
    char* title = NULL;
    char* author = NULL;
    char* genre = NULL;
    char* publisher = NULL;
    int page_count;
    size_t read = 0;

    // get book info from stdin
    getline(&buf, &read, stdin);
    printf("title=");
    read = 0;
    getline(&title, &read, stdin);
    title[strlen(title) - 1] = '\0';
    printf("author=");
    read = 0;
    getline(&author, &read, stdin);
    author[strlen(author) - 1] = '\0';
    printf("genre=");
    read = 0;
    getline(&genre, &read, stdin);
    genre[strlen(genre) - 1] = '\0';
    printf("publisher=");
    read = 0;
    getline(&publisher, &read, stdin);
    publisher[strlen(publisher) - 1] = '\0';
    printf("page_count=");
    scanf("%d", &page_count);

    // construct json with book info
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *json_data = json_value_get_object(root_value);
    char* book_data = NULL;

    json_object_set_string(json_data, "title", title);
    json_object_set_string(json_data, "author", author);
    json_object_set_string(json_data, "genre", genre);
    json_object_set_string(json_data, "publisher", publisher);
    json_object_set_number(json_data, "page_count", page_count);

    book_data = json_serialize_to_string_pretty(root_value);

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // post request message
    message = compute_post_request("34.118.48.238",
                                   "/api/v1/tema/library/books/",
                                   jwt_token,
                                   "application/json",
                                   &book_data, 1,
                                   &session_cookie, 1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == FORBIDDEN ||
        status_code == BAD_REQUEST ||
        status_code == UNAUTHORIZED) {

        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);

    } else if (status_code == OK) {
        printf("book added\n");
    }

    // close server connection
    close_connection(sockfd);
    json_free_serialized_string(book_data);
    json_value_free(root_value);
    free(buf);
    free(title);
    free(author);
    free(publisher);
    free(genre);
    free(message);
    free(response);
}

// delete a book from libary with given id
void delete_book(char* session_cookie, char* jwt_token) {
    int sockfd;
    char* message;
    char* response;

    // get book id from stdin
    int id;
    printf("id=");
    scanf("%d", &id);

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    char url[50];
    sprintf(url, "/api/v1/tema/library/books/%d", id);

    // delete request message
    message = compute_delete_request("34.118.48.238",
                                     url,
                                     jwt_token,
                                     &session_cookie,
                                     1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == FORBIDDEN ||
        status_code == NOT_FOUND ||
        status_code == UNAUTHORIZED) {

        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);

    } else if (status_code == OK) {
        printf("book deleted\n");
    }

    // close server connection
    close_connection(sockfd);
    free(message);
    free(response);
}

// logout user
void logout(char* session_cookie) {
    int sockfd;
    char* message;
    char* response;

    // connect to server
    sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);

    // get request message
    message = compute_get_request("34.118.48.238",
                                  "/api/v1/tema/auth/logout",
                                  NULL,
                                  NULL,
                                  &session_cookie, 1);

    // send and receive response from server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // check for errors
    int status_code;
    sscanf(response, "%*s%d", &status_code);
    if (status_code == BAD_REQUEST || status_code == UNAUTHORIZED) {
        char* error_msg = basic_extract_json_response(response);
        printf("%s\n", error_msg);
    } else if (status_code == OK) {
        printf("you are logged out\n");
    }

    // close server connection
    close_connection(sockfd);
    free(message);
    free(response);
}

int main() {
    char client_command[20];
    char* session_cookie = NULL;
    char* jwt_token = NULL;

    while (1)
    {
        memset(client_command, 0, 20);
        scanf("%s", client_command);

        if (strcmp(client_command, "register") == 0) {
            register_command();
        }

        if (strcmp(client_command, "login") == 0) {
            session_cookie = login_command();
        }

        if (strcmp(client_command, "enter_library") == 0) {
            jwt_token = enter_library(session_cookie);
        }

        if (strcmp(client_command, "get_books") == 0) {
            get_books(session_cookie, jwt_token);
        }

        if (strcmp(client_command, "get_book") == 0) {
            get_book(session_cookie, jwt_token);
        }

        if (strcmp(client_command, "add_book") == 0) {
            add_book(session_cookie, jwt_token);
        }

        if (strcmp(client_command, "delete_book") == 0) {
            delete_book(session_cookie, jwt_token);
        }

        if (strcmp(client_command, "logout") == 0) {
            logout(session_cookie);
            if (session_cookie) {
                free(session_cookie);
                session_cookie = NULL;
            }

            if (jwt_token) {
                free(jwt_token);
                jwt_token = NULL;
            }
        }

        if (strcmp(client_command, "exit") == 0) {
            break;
        }
    }

    if (session_cookie) free(session_cookie);

    if (jwt_token) free(jwt_token);

    return 0;
}