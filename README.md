**GoLang Rest Api Server**

This project is based on the work of [@brainbreaker](https://github.com/brainbreaker/rest-and-go) to explore the GoLang.

Its a simple rest api application with OAuth based authentication. The app uses MongoDB as the data store.

I will be adding more functionality related to the scenarios of rest api.

**Setup**

- Clone the repo and place it under `src/` folder of the go installation location.
- Install 3rd party/open source packages required by this app:

        go get  github.com/dgrijalva/jwt-go
        go get  github.com/gorilla/context
        go get  github.com/gorilla/mux
        go get  github.com/gorilla/handlers
        go get  github.com/globalsign/mgo
        go get  github.com/globalsign/mgo/bson
        go get github.com/joho/godotenv/cmd/godotenv
- Rename `.env.example` to `.env`.  Set values in  .env to run the program:
    - PORT
    - MONGO_URL
    - JWT_SECRET
- Build the program `go build main.go`
- Run the program `./main`. .env file should be in the same folder.
- You can also run it using the IDE like [GoLand](https://www.jetbrains.com/go/) by setting a package run config for Golang

