BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "users" (
	"id"	INTEGER NOT NULL UNIQUE,
	"login"	VARCHAR(128) NOT NULL UNIQUE,
	"name"	VARCHAR(128) NOT NULL UNIQUE,
	"age"	INTEGER NOT NULL,
	"password"	VARCHAR(72) NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "contacts" (
	"id"	INTEGER NOT NULL UNIQUE,
	"phone"	VARCHAR(12) NOT NULL UNIQUE,
	"description"	INTEGER NOT NULL,
	"is_fax"	NUMERIC NOT NULL,
	"user_id"	INTEGER NOT NULL,
	FOREIGN KEY("user_id") REFERENCES "users"("id"),
	PRIMARY KEY("id" AUTOINCREMENT)
);
COMMIT;