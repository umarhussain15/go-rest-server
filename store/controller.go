package store

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

//Controller ...
type Controller struct {
	Repository Repository
}

var secret = os.Getenv("JWT_SECRET")

const bCryptSaltRounds = 12

/* Middleware handler to handle all requests for authentication */
func AuthenticationMiddleware(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// read authorization header value
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			// extract the token value from header value
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {

				token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("there was an error parsing token")
					}
					// set key to use for decoding token
					return []byte(secret), nil
				})
				if err != nil {
					log.Fatal(err)
					json.NewEncoder(w).Encode(Response{Message: err.Error()})
					return
				}
				// for valid token, set context and call the next function in chain
				if token.Valid {
					log.Println("TOKEN WAS VALID")
					context.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(Response{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(Response{Message: "An authorization header is required"})
		}
	})
}

func (c *Controller) registerUser(w http.ResponseWriter, req *http.Request) {
	var user User
	json.NewDecoder(req.Body).Decode(&user)

	bytes, err := bcrypt.GenerateFromPassword([]byte(user.Password), bCryptSaltRounds)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user.Password = string(bytes)
	user, err = c.Repository.addUser(user)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(Response{Message: "Cannot create user"})
	} else {
		json.NewEncoder(w).Encode(Response{Message: "User created successfully"})
	}
}

// Get Authentication token GET /
func (c *Controller) loginUser(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	userDb, err := c.Repository.getUserByUsername(user.Username)
	if err != nil {
		log.Print("Error", err)

		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("User with email %s not found", user.Username)})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	userId := userDb.ID
	if len(userId) != 0 {
		err = bcrypt.CompareHashAndPassword([]byte(userDb.Password), []byte(user.Password))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(Response{Message: "User email password is incorrect"})
			return
		} else {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": user.Username,
				"userId":   userId,
			})
			log.Println("Username: " + user.Username)
			//log.Println("Password: " + user.Password);

			signedToken, err := token.SignedString([]byte(secret))
			if err != nil {
				fmt.Println(err)
			}
			json.NewEncoder(w).Encode(JwtToken{Token: signedToken})
			return
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("User with email '%s' not found", user.Username)})
		return
	}

}

// Index GET /
func (c *Controller) Index(w http.ResponseWriter, r *http.Request) {
	products := c.Repository.GetProducts() // list of all products
	// log.Println(products)
	data, _ := json.Marshal(products)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// AddProduct POST /
func (c *Controller) AddProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576)) // read the body of the request

	log.Println(body)

	if err != nil {
		log.Fatalln("Error AddProduct", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error AddProduct", err)
	}

	if err := json.Unmarshal(body, &product); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		log.Println(err)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error AddProduct unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	log.Println(product)
	success := c.Repository.AddProduct(product) // adds the product to the DB
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	return
}

// SearchProduct GET /
func (c *Controller) SearchProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)

	query := vars["query"] // param query
	log.Println("Search Query - " + query)
	products := c.Repository.GetProductsByString(query)
	data, _ := json.Marshal(products)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// UpdateProduct PUT /
func (c *Controller) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576)) // read the body of the request
	if err != nil {
		log.Fatalln("Error UpdateProduct", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error UpdateProduct", err)
	}

	if err := json.Unmarshal(body, &product); err != nil { // unmarshall body contents as a type Candidate
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error UpdateProduct unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	log.Println(product.ID)
	success := c.Repository.UpdateProduct(product) // updates the product in the DB

	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	return
}

// GetProduct GET - Gets a single product by ID /
func (c *Controller) GetProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)

	id := vars["id"] // param id
	log.Println(id)
	productid, err := strconv.Atoi(id)
	if err != nil {
		log.Fatalln("Error GetProduct", err)
	}

	product := c.Repository.GetProductById(productid)
	data, _ := json.Marshal(product)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// DeleteProduct DELETE /
func (c *Controller) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Println(vars)
	id := vars["id"] // param id
	log.Println(id)
	productid, err := strconv.Atoi(id)
	if err != nil {
		log.Fatalln("Error GetProduct", err)
	}

	if err := c.Repository.DeleteProduct(productid); err != "" { // delete a product by id
		log.Println(err)
		if strings.Contains(err, "404") {
			w.WriteHeader(http.StatusNotFound)
		} else if strings.Contains(err, "500") {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	return
}
