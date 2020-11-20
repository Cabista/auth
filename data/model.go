package data

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Login string `gorm:"unique"`
	Email string `gorm:"unique"`
	//EmailVerified bool
	PasswordHash string `gorm:"unique"`
	//Name          string
}

type Permission struct {
	Resource string
	Action   string
}
