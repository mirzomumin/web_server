package domains

type Contact struct {
	Id          int    `json:"id"`
	Phone       string `json:"phone"`
	Description string `json:"description"`
	IsFax       bool   `json:"is_fax"`
	UserId      int    `json:"user_id"`
}
