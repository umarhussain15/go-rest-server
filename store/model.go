package store

type User struct {
	ID       string `bson:"_id,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type Response struct {
	Message string `json:"message"`
}

// Product represents an e-comm item
type Product struct {
	ID     int    `bson:"_id,omitempty"`
	Title  string `json:"title"`
	Image  string `json:"image"`
	Price  uint64 `json:"price"`
	Rating uint8  `json:"rating"`
}

// Products is an array of Product objects
type Products []Product
