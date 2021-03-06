package store

import (
	"errors"
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"log"
	"os"
	"strings"
)

//Repository ...
type Repository struct{}

// server the DB server
var server = os.Getenv("MONGO_URL")

//const server = "mongodb://<db-username>:<db-user-password>@<host>:<port>/go-rest-server"

// dbName the name of the DB instance
const dbName = "go-rest-server"

// collection is the name of the collection in DB
const collection = "store"

const userCollection = "users"

var productId = 10

/**
Add user with hash password to db, after checking for username presence.
*/
func (r Repository) addUser(user User) (User, error) {
	session, err := mgo.Dial(server)

	if err != nil {
		log.Println("Failed to establish connection to Mongo server:", err)
		return user, err
	}
	defer session.Close()

	c := session.DB(dbName).C(userCollection)
	count, err := c.Find(bson.M{"username": user.Username}).Count()
	if err != nil {
		return user, err
	}

	if count == 0 {
		err = c.Insert(user)
		return user, err
	} else {
		return user, errors.New("user email already exists")
	}

}

func (r Repository) getUserByUsername(username string) (User, error) {
	session, err := mgo.Dial(server)
	var user User
	if err != nil {
		log.Println("Failed to establish connection to Mongo server:", err)
		return user, err
	}
	defer session.Close()

	c := session.DB(dbName).C("users")
	err = c.Find(bson.M{"username": username}).One(&user)

	return user, err
}

// GetProducts returns the list of Products
func (r Repository) GetProducts() Products {
	session, err := mgo.Dial(server)

	if err != nil {
		fmt.Println("Failed to establish connection to Mongo server:", err)
	}

	defer session.Close()

	c := session.DB(dbName).C(collection)
	results := Products{}

	if err := c.Find(nil).All(&results); err != nil {
		fmt.Println("Failed to write results:", err)
	}

	return results
}

// GetProductById returns a unique Product
func (r Repository) GetProductById(id int) Product {
	session, err := mgo.Dial(server)

	if err != nil {
		fmt.Println("Failed to establish connection to Mongo server:", err)
	}

	defer session.Close()

	c := session.DB(dbName).C(collection)
	var result Product

	fmt.Println("ID in GetProductById", id)
	if err := c.FindId(id).One(&result); err != nil {
		fmt.Println("Failed to write result:", err)
	}

	return result
}

// GetProductsByString takes a search string as input and returns products
func (r Repository) GetProductsByString(query string) Products {
	session, err := mgo.Dial(server)

	if err != nil {
		fmt.Println("Failed to establish connection to Mongo server:", err)
	}

	defer session.Close()

	c := session.DB(dbName).C(collection)
	result := Products{}

	// Logic to create filter
	qs := strings.Split(query, " ")
	and := make([]bson.M, len(qs))
	for i, q := range qs {
		and[i] = bson.M{"title": bson.M{
			"$regex": bson.RegEx{Pattern: ".*" + q + ".*", Options: "i"},
		}}
	}
	filter := bson.M{"$and": and}

	if err := c.Find(&filter).Limit(5).All(&result); err != nil {
		fmt.Println("Failed to write result:", err)
	}

	return result
}

// AddProduct adds a Product in the DB
func (r Repository) AddProduct(product Product) bool {
	session, err := mgo.Dial(server)
	defer session.Close()

	productId += 1
	product.ID = productId
	session.DB(dbName).C(collection).Insert(product)
	if err != nil {
		log.Fatal(err)
		return false
	}

	fmt.Println("Added New Product ID- ", product.ID)

	return true
}

// UpdateProduct updates a Product in the DB
func (r Repository) UpdateProduct(product Product) bool {
	session, err := mgo.Dial(server)
	defer session.Close()

	err = session.DB(dbName).C(collection).UpdateId(product.ID, product)

	if err != nil {
		log.Fatal(err)
		return false
	}

	fmt.Println("Updated Product ID - ", product.ID)

	return true
}

// DeleteProduct deletes an Product
func (r Repository) DeleteProduct(id int) string {
	session, err := mgo.Dial(server)
	defer session.Close()

	// Remove product
	if err = session.DB(dbName).C(collection).RemoveId(id); err != nil {
		log.Fatal(err)
		return "INTERNAL ERR"
	}

	fmt.Println("Deleted Product ID - ", id)
	// Write status
	return "OK"
}
