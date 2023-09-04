package domains

type User struct {
	Id       int    `json:"id"`
	Login    string `json:"login,omitempty"`
	Name     string `json:"name,omitempty"`
	Age      int    `json:"age,omitempty"`
	Password string `json:"password,omitempty"`
}
