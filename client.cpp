#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <bits/stdc++.h>
#include "helpers.h"
#include "requests.h"
#include "json.hpp"

namespace jason = nlohmann;

#define CRED_MAX_LEN 150

void handle_register();
void handle_login();
void handle_enter_library();
void handle_get_books();
void handle_get_book();
void handle_add_book();
void handle_delete_book();
void handle_logout();
void handle_exit();

const char auth_prompts[][15] = {
	"username",
	"password",
};

const char add_prompts[][15] = {
	"title",
	"author",
	"genre",
	"publisher",
	"page_count",
};

/*
 * Numele tuturor comenzilor recunoscute
 * de program
 */
const char commands[][20] = {
	"register",
	"login",
	"enter_library",
	"get_books",
	"get_book",
	"add_book",
	"delete_book",
	"logout",
	"exit",
};

/*
 * Indexul care corespunde comenzii in vectorul
 * de mai sus
 */
enum operations {
	REGISTER = 0,
	LOGIN = 1,
	ENTER_LIBRARY = 2,
	GET_BOOKS = 3,
	GET_BOOK = 4,
	ADD_BOOK = 5,
	DELETE_BOOK = 6,
	LOGOUT = 7,
	EXIT = 8,
};

/*
 * Vector cu pointeri la fiecare functie
 * care gestioneaza cate un tip de actiune
 */
void (*handlers[]) () = {
	handle_register,
	handle_login,
	handle_enter_library,
	handle_get_books,
	handle_get_book,
	handle_add_book,
	handle_delete_book,
	handle_logout,
	handle_exit,
};

const int nr_commands = sizeof(handlers) / sizeof(void (*)());
int server_running = 1;
int detected_error = 0;
char cookie[1024] = { 0 };
char jwt_token[1024] = { 0 };
int fd;

/**
 * @brief
 * Extrag din raspuns codul si pe baza lui
 * dau feedback utilizatorului
 * @param response
 * buffer-ul in care se afla raspunsul
 * @param op
 * Codul ultimei operatii efectuate
 * @return
 * 0 pentru succes, 1 pentru cod de eroare, 2 pentru
 * raspuns de eroare fara mesaj.
 */
int parse_response(char* response, operations op)
{
	int code;
	sscanf(response, "HTTP/1.1 %d", &code);
	if (code / 100 == 2) {
		printf("[%d]{ok} - Operatia \"%s\" s-a efectuat cu success.\n\n", code, commands[op]);
		return 0;
	}
	printf("[%d]{fail} - Operatia \"%s\" a esuat. Mesaj primit de la server:\n", code, commands[op]);
	char* p = basic_extract_json_response(response);
	if (p == NULL) {
		fprintf(stderr, "Mesaj invalid primit de la server\n");
		return 2;
	}
	auto resp = jason::json::parse(p);
	const std::string& err = resp.at("error");
	printf("\t\"%s\"\n\n", err.c_str());
	return 1;
}

/**
 * @brief
 * Creeaza un request http pe baza unui obiect de tip json
 * transmis ca parametru.
 * @param method
 * Metoda din request-ul http.
 * @param route
 * url-ul aferent request-ului.
 * @param header
 * Un obiect json in care sunt stocate campurile
 * din header si valorile lor.
 * @param payload
 * Continutul request-ului, acolo unde este necesar.
 * @return
 * Mesajul nou creat pe baza parametrilor.
 */
char* make_http_header(char* method, char* route, jason::ordered_json& header, char* payload) {
	char* message = (char*)calloc(BUFLEN, sizeof(char));
	char* line = (char*)calloc(LINELEN, sizeof(char));

	// alcatuiesc prima linie din request
	sprintf(line, "%s %s HTTP/1.1", method, route);
	compute_message(message, line);
	line[0] = 0;

	/*
	 * parcurg fiecare pereche cheie-valoare din json
	 * si alcatuiesc campurile din header pe baza lor
	 */
	for (const auto& item : header.items()) {
		strcat(line, item.key().c_str());
		strcat(line, ": ");
		if (item.value().is_string()) {
			std::string str = item.value();
			strcat(line, str.c_str());
		}
		compute_message(message, line);
		line[0] = 0;
	}
	compute_message(message, "");

	// adaug payload-ul daca exista
	if (payload != NULL) {
		strcat(message, payload);
	}
	free(line);
	return message;
}

/**
 * @brief
 * Afiseaza prompt-uri pentru utilizator,
 * citeste input-ul si salveaza datele introduse
 * intr-un obiect de tip json.
 * @param prompts
 * Prompt-urile care trebuie transmise utilizatorului.
 * @param prompt_count
 * Numarul de prompt-uri.
 * @param data
 * Obiectul json in care datele vor fi salvate.
 */
int json_from_prompt(const char prompts[][15], int prompt_count, jason::ordered_json& data) {
	char buffer[1024];
	int flag = 0;
	for (int i = 0;i < prompt_count;i++) {
		printf("%s=", prompts[i]);
		fgets(buffer, 100, stdin);
		if (strlen(buffer) == 1) {
			flag = -1;
		}
		buffer[strlen(buffer) - 1] = 0;
		data[prompts[i]] = buffer;
	}
	return flag;
}

void send_auth_message(int fd, char* path, jason::ordered_json& payload) {
	std::string dmp = payload.dump();
	const char* ptr = dmp.c_str();
	char* message = compute_post_request(SERVER_IP ":" SERVER_PORT,
		path, "application/json",
		(char**)&ptr, 1, NULL, 0);
	send_to_server(fd, message);
	free(message);
}

void handle_register() {
	if (strlen(cookie) != 0 || strlen(jwt_token) != 0) {
		printf("Trebuie sa fii delogat pentru a inregistra un nou utilizator\n");
		return;
	}
	// primesc input-ul de la utilizator si il stochez intr-un json
	jason::ordered_json payload;
	json_from_prompt(auth_prompts, 2, payload);

	/*
	 * alcatuiesc campurile din header ca perechi cheie-valoare
	 * folosindu-ma de biblioteca pentru json-uri
	 */
	jason::ordered_json header;
	header["Host"] = SERVER_IP ":" SERVER_PORT;
	header["Content-Type"] = "application/json";
	std::string dmp = payload.dump();
	char* ptr = (char*)dmp.c_str();
	header["Content-Length"] = std::to_string(strlen(ptr));
	char* message = make_http_header("POST", "/api/v1/tema/auth/register", header, ptr);

	/*
	 * dupa ce tot mesajul a fost creat, creez o noua conexiune si trimit
	 * mesajul la server
	 */
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_to_server(fd, message);
	char* response = receive_from_server(fd);
	parse_response(response, REGISTER);
	close_connection(fd);
	free(message);
	free(response);
}

void handle_login() {
	if (strlen(cookie) != 0 || strlen(jwt_token) != 0) {
		printf("Trebuie sa fii delogat pentru a te loga in alt cont\n");
		return;
	}

	// primesc input-ul de la utilizator si il stochez intr-un json
	jason::ordered_json payload;
	json_from_prompt(auth_prompts, 2, payload);

	/*
	 * creez o noua conexiune si trimit mesajul cu datele utilizatorului
	 * catre server
	 */
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_auth_message(fd, "/api/v1/tema/auth/login", payload);
	char* response = receive_from_server(fd);
	int rc = parse_response(response, LOGIN);
	if (rc) {
		free(response);
		return;
	}

	// extrag cookie-ul din raspunsul primit de la server
	char* cookie_begin = strstr(response, "Set-Cookie: ");
	char* cookie_end = strchr(cookie_begin, ';');
	cookie_begin += strlen("Set-Cookie: ");
	memcpy(cookie, cookie_begin, cookie_end - cookie_begin);
	close_connection(fd);
	free(response);
}

void handle_enter_library() {
	if (strlen(cookie) == 0) {
		printf("Eroare: Pentru a accesa biblioteca trebuie sa fii logat\n");
		return;
	}

	// daca trimiteam &cookie ca parametru dadea aiurea
	char* ck = cookie;

	// creez mesajul care trebuie trimis serverului
	char* message = compute_get_request(SERVER_IP ":" SERVER_PORT,
		"/api/v1/tema/library/access", NULL, (char**)&ck, 1);
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_to_server(fd, message);
	char* response = receive_from_server(fd);
	int rc = parse_response(response, ENTER_LIBRARY);

	// daca s-a petrecut vreo eroare, nu parsez raspunsul primit
	if (rc) {
		free(response);
		return;
	}

	/*
	 * parsez payload-ul din raspunsul http si caut
	 * campul token pentru a putea afla token-ul JWT
	 */
	char* payload_begin = basic_extract_json_response(response);
	jason::ordered_json oj = jason::ordered_json::parse(payload_begin);
	const std::string& token = oj.at("token");
	memcpy(jwt_token, token.c_str(), token.length());
	close_connection(fd);
	free(message);
	free(response);
}

void handle_get_books() {
	if (strlen(jwt_token) == 0) {
		printf("Eroare: Pentru a accesa biblioteca trebuie sa fii logat\n");
		return;
	}

	/*
	 * alcatuiesc campurile din header ca perechi cheie-valoare
	 * folosindu-ma de biblioteca pentru json-uri
	 */
	jason::ordered_json header;
	header["Host"] = SERVER_IP ":" SERVER_PORT;
	header["Cookie"] = cookie;
	header["Authorization"] = "Bearer " + std::string(jwt_token);
	char* message = make_http_header("GET", "/api/v1/tema/library/books",
		header, NULL);

	// trimit mesajul la server
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_to_server(fd, message);
	char* response = receive_from_server(fd);

	// parsez raspunsul pentru a afla codul
	int rc = parse_response(response, GET_BOOKS);
	if (rc) {
		free(message);
		free(response);
		return;
	}

	/*
	 * stiu ca indiferent de numarul de carti returnate,
	 * rezultatul va fi mereu un vector de obiecte json deci
	 * caut secventa de inceput a vectorului pentru a putea parsa.
	 */
	char* p = strstr(response, "[{");
	if (p != NULL) {
		auto res = jason::json::parse(p);
		std::cout << res.dump(4) << "\n";
	}
	else {
		printf("Nu exista nicio carte de afisat\n");
	}
	close_connection(fd);
	free(message);
	free(response);
}

/**
 * @brief
 * Functie comuna pentru get_book si delete_book
 * @param method
 * "GET" sau "DELETE"
 */
void handle_individual_book(char* method) {
	if (strlen(jwt_token) == 0) {
		printf("Eroare: Pentru a accesa biblioteca trebuie sa fii logat\n");
		return;
	}
	jason::ordered_json header;
	char buffer[100];

	// astept de la utilizator id-ul cartii pe care vrea sa o manipuleze
	printf("id=");
	fgets(buffer, 100, stdin);
	buffer[strlen(buffer) - 1] = 0;

	// verific ca id-ul sa fie un numar pozitiv
	for (int i = 0; i < strlen(buffer); i++) {
		if (buffer[i] < '0' || buffer[i] > '9') {
			printf("Eroare: id-ul trebuie sa fie numar\n");
			return;
		}
	}
	char route[100] = "/api/v1/tema/library/books/";
	strcat(route, buffer);

	/*
	 * alcatuiesc campurile din header ca perechi cheie-valoare
	 * folosindu-ma de biblioteca pentru json-uri
	 */
	header["Host"] = SERVER_IP ":" SERVER_PORT;
	header["Cookie"] = cookie;
	header["Authorization"] = "Bearer " + std::string(jwt_token);
	char* message = make_http_header(method, route,
		header, NULL);

	// trimit mesajul la server
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_to_server(fd, message);
	free(message);
	char* response = receive_from_server(fd);
	operations op = strcmp(method, "GET") == 0 ? GET_BOOK : DELETE_BOOK;
	int rc = parse_response(response, op);
	if (rc || op == DELETE_BOOK) {
		free(response);
		return;
	}

	// daca operatia nu este delete, afisez datele despre cartea primita ca raspuns
	char* p = basic_extract_json_response(response);
	if (p == NULL) {
		free(response);
		fprintf(stderr, "Mesaj invalid primit de la server\n");
		return;
	}
	auto resp = jason::ordered_json::parse(p);
	std::cout << resp.dump(4) << "\n";
	free(response);
	close_connection(fd);
}

void handle_get_book() {
	handle_individual_book("GET");
	return;
}

void handle_add_book() {
	if (strlen(jwt_token) == 0) {
		printf("Eroare: Pentru a accesa biblioteca trebuie sa fii logat\n");
		return;
	}

	// primesc input-ul de la utilizator si il stochez intr-un json
	jason::ordered_json book;
	int rc = json_from_prompt(add_prompts, 5, book);
	if (rc) {
		printf("Eroare: campurile introduse trebuie sa contina cel putin un caracter\n");
		return;
	}
	// verific daca page_count e un numar pozitiv
	auto val = book.at("page_count");
	if (!val.is_string()) {
		printf("Eroare: page_count trebuie sa fie numar\n");
		return;
	}
	std::string str = val;
	for (int i = 0; i < strlen(str.c_str()); i++) {
		if (str[i] < '0' || str[i] > '9') {
			printf("Eroare: page_count trebuie sa fie numar\n");
			return;
		}
	}

	/*
	 * alcatuiesc campurile din header ca perechi cheie-valoare
	 * folosindu-ma de biblioteca pentru json-uri
	 */
	jason::ordered_json header;
	header["Host"] = SERVER_IP ":" SERVER_PORT;
	header["Content-Type"] = "application/json";
	std::string dmp = book.dump();
	char* ptr = (char*)dmp.c_str();
	header["Content-Length"] = std::to_string(strlen(ptr));
	header["Cookie"] = cookie;
	header["Authorization"] = "Bearer " + std::string(jwt_token);
	char* message = make_http_header("POST", "/api/v1/tema/library/books",
		header, ptr);

	// trimit mesajul la server
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);
	send_to_server(fd, message);
	char* response = receive_from_server(fd);
	parse_response(response, ADD_BOOK);
	close_connection(fd);
	free(message);
	free(response);
}

void handle_delete_book() {
	handle_individual_book("DELETE");
	return;
}

void handle_logout() {

	/*
	 * alcatuiesc campurile din header ca perechi cheie-valoare
	 * folosindu-ma de biblioteca pentru json-uri
	 */
	if (strlen(cookie) == 0) {
		printf("Eroare: Pentru a accesa biblioteca trebuie sa fii logat\n");
		return;
	}
	jason::ordered_json header;
	header["Host"] = SERVER_IP ":" SERVER_PORT;
	header["Cookie"] = cookie;
	char* message = make_http_header("GET", "/api/v1/tema/auth/logout",
		header, NULL);
	int fd = open_connection(SERVER_IP, atoi(SERVER_PORT), AF_INET, SOCK_STREAM, 0);

	// trimit mesajul la server
	send_to_server(fd, message);
	char* response = receive_from_server(fd);
	parse_response(response, LOGOUT);
	close_connection(fd);
	memset(jwt_token, 0, sizeof(jwt_token));
	memset(cookie, 0, sizeof(cookie));
	free(message);
	free(response);
}

// opreste serverul
void handle_exit() {
	if (strlen(jwt_token) != 0 || strlen(cookie) != 0) {
		handle_logout();
	}
	server_running = 0;
}

// afiseaza un mesaj pentru comanda invalida
void handle_invalid_command() {
	printf("Comanda primita nu este una valida\n");
}

int main(int argc, char* argv[])
{
	char input[512];
	/*
	 * Event loop-ul principal al programului
	 */
	while (server_running) {
		/*
		 * Se preia de la tastatura comanda pe
		 * care o doreste utilizatorul
		 */
		fgets(input, 40, stdin);
		input[strlen(input) - 1] = 0;
		bool is_valid = false;
		for (int i = 0; i < nr_commands; i++) {
			/*
			 * Se cauta o potrivire in numele de comenzi
			 * cunoscute de program
			 */
			if (strcmp(input, commands[i]) == 0) {
				/*
				 * Daca s-a gasit o astfel de potrivire,
				 * se executa functia corespunzatoare comenzii
				 */
				handlers[i]();
				is_valid = true;
			}
		}
		/*
		 * Daca nu s-a gasit nicio potrivire,
		 * inseamna ca input-ul introdus este invalid
		 */
		if (!is_valid) {
			handle_invalid_command();
		}
	}
	return 0;
}
