package data

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Database *gorm.DB

func Initialize() error {
	var err error

	Database, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	err = Database.AutoMigrate(&User{})
	if err != nil {
		return err
	}

	return nil
}
