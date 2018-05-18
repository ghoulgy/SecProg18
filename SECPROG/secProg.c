#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#define SIZE_20 20
#define SIZE_40 40

// DB Function
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

void insertData(char name[SIZE_20], char pass[SIZE_20], sqlite3* db, char* sql, int rc, char* error_message) {
	sqlite3_stmt *stmt;

	sql = "INSERT INTO USERS (name, pass) "\
          "VALUES (?1, ?2);";

  	sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
  	sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);

  	rc = sqlite3_step(stmt);
  	if (rc != SQLITE_DONE) {
	    printf("ERROR inserting data: %s\n", sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
}

char *getData(char name[SIZE_20], sqlite3* db, char* sql, int rc, char* error_message) {
	sqlite3_stmt *stmt;
	char *hashedPass = (char *)malloc(sizeof(char) * SIZE_40);
	int sizeHash;

	sql = "SELECT pass FROM USERS WHERE name = ?;";

  	sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

  	rc = sqlite3_step(stmt);

	if(rc == SQLITE_ROW) {
		sizeHash = sizeof(hashedPass);
		strncpy(hashedPass, sqlite3_column_text(stmt, 0), SIZE_40);				// str-n-function
	}

	sqlite3_finalize(stmt);

	return hashedPass;
}
//DB Function

void login(sqlite3* db, char* sql, int rc, char* error_message) {
	char lname[SIZE_20];
	unsigned char lpass[SIZE_20];
	int sizeOri;

	printf("========== LOGIN ==========\n");
	printf("Enter user name: ");
	fgets(lname, sizeof(lname), stdin);
	for(int x=0;x<strlen(lname);x++) {
        if(lname[x] == '\n') {
            lname[x] = '\0';
            break;
        }
    }

	printf("Enter password: ");
	scanf("%s", lpass);
	// Input Hash
	size_t inputLength = strlen(lpass);
	unsigned char inputHash[SHA_DIGEST_LENGTH];
	SHA1(lpass, inputLength, inputHash);
	char input_sha1_hex[SIZE_40];
	for(int i = 0; i<SIZE_20; i++) {
		snprintf(&input_sha1_hex[i*2], 3,"%02x", (unsigned int)inputHash[i]);		// Move inputHash into input_sha1_hex
	}
	// Ori Hash
	char ori_sha1_hex[SIZE_40];
	sizeOri = sizeof(ori_sha1_hex);
	strncpy(ori_sha1_hex, getData(lname, db, sql, rc, error_message), sizeOri);	// str-n-function

	if(strncmp(input_sha1_hex, ori_sha1_hex, SIZE_40) == 0) {					// str-n-function
		printf("========== Success =========\n");
		printf("Welcome! HeHe!\n");
	} else {
		printf("========== Failed =========\n");
		printf("Bye! Wrong User and Password\n");
	}
}

void registerUser(sqlite3* db, char* sql, int rc, char* error_message) {
	char rname[SIZE_20];
	unsigned char rpass[SIZE_20];

	printf("========== REGISTER ==========\n");
	printf("Enter user name: ");
	fgets(rname, sizeof(rname), stdin);
	for(int x=0;x<strlen(rname);x++) {
        if(rname[x] == '\n') {
            rname[x] = '\0';
            break;
        }
    }

	printf("Enter password: ");
	scanf("%s", rpass);

	// Input Hash
	size_t inputLength = strlen(rpass);
	unsigned char inputHash[SHA_DIGEST_LENGTH];
	SHA1(rpass, inputLength, inputHash);
	char input_sha1_hex[SIZE_40];

	for(int i = 0; i<SIZE_20; i++) {
		sprintf(&input_sha1_hex[i*2], "%02x", (unsigned int)inputHash[i]);
	}

	insertData(rname, input_sha1_hex, db, sql, rc, error_message);

	printf("Insert successfully...\n"); 
}

int main() {
	// DB
	sqlite3 *db;
	char *sql;
	int rc;
	char *zErrMsg = 0;

	rc = sqlite3_open("secProg.db", &db);

	if(rc) {
	  fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
	  system("exit");
	} else {	
	// DB
		int choice;

		do {
			printf("\n========== Welcome to XYZ system ==========\n");
			printf("1) Login\n");
			printf("2) Register\n");
			printf("3) Quit\n");

			printf("Your Option: ");
			scanf("%d", &choice);
			getchar();

			switch(choice) {
				case 1:
					login(db, sql, rc, zErrMsg);
					break;
				case 2:
					registerUser(db, sql, rc, zErrMsg);
					break;
				case 3:
					printf("System Terminated...\n");
					return 0;
					break;
			}
		} while(choice);
	}
	return 0;
}
