# Go Project "web_server"
Project provides registering new users and adding/reading/editing/deleting contacts (phones)

## Set Up
1. The first thing to do is to clone the repository and move to the directory "web_server" in your terminal:
```sh
$ git clone https://github.com/mirzomumin/web_server
$ cd web_server
```

2. Download dependencies from go.mod:
```sh
$ go mod download
```

3. Create Sqlite3 Database and create tables using DB.sql file.

4. Create and set .env file like in .env-example file.

## Project Launch
3. Run the following command to launch the project:
```sh
$ go run cmd/main.go
```
