package data

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Database *gorm.DB

func Initialize(dsn string) error {
	var err error

	Database, err = gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
	}), &gorm.Config{})
	if err != nil {
		return err
	}

	err = Database.AutoMigrate(&User{})
	if err != nil {
		return err
	}

	return nil
}
