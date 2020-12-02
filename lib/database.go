package lib

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	errorWrapper "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Database struct {
	db *sql.DB
}

var (
	NoRowFound    = errors.New("no row found")
	StatusMatched = errors.New("status matched")
)

//connect with database server and return a database struct
func NewDatabase() (*Database, error) {
	if viper.GetString("POSTGRES_HOST") == "" {
		logrus.Fatal("the value of POSTGRES_HOST cannot be empty in config.yml file")
	}
	if viper.GetString("POSTGRES_PORT") == "" {
		logrus.Fatal("the value of POSTGRES_PORT cannot be empty in config.yml file")
	}
	if viper.GetString("POSTGRES_USER_NAME") == "" {
		logrus.Fatal("the value of POSTGRES_USER_NAME cannot be empty in config.yml file")
	}
	if viper.GetString("POSTGRES_DATABASE_NAME") == "" {
		logrus.Fatal("the value of POSTGRES_DATABASE_NAME cannot be empty in config.yml file")
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s",
		viper.GetString("POSTGRES_HOST"), viper.GetInt("POSTGRES_PORT"),
		viper.GetString("POSTGRES_USER_NAME"), viper.GetString("POSTGRES_DATABASE_NAME"))
	if viper.GetString("POSTGRES_DATABASE_PASSWORD") != "" {
		psqlInfo = fmt.Sprintf("%s password=%s", psqlInfo, viper.GetString("POSTGRES_DATABASE_PASSWORD"))
	}
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, errorWrapper.Wrap(err, "failed in connecting with database")
	}
	return &Database{db: db}, nil
}

//ping to database server,
func (d *Database) Ping() (bool, error) {
	err := d.db.Ping()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) InsertUser(name, email, password string) (int, error) {
	id := -1
	sqlStatement := `
INSERT INTO users (email, encrypted_password, name, date_format, time_format)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`
	bytePass := []byte(password)
	hash, err := bcrypt.GenerateFromPassword(bytePass, bcrypt.MinCost)
	if err != nil {
		return id, errorWrapper.Wrap(err, "failed in encrypting password ")
	}
	pwd := string(hash)
	err = d.db.QueryRow(sqlStatement, email, pwd, name, "", "").Scan(&id)
	if err != nil {
		return id, errorWrapper.Wrap(err, "failed in inserting user in database")
	}
	return id, nil
}

func (d *Database) InsertUserToGroup(userId int) error {
	id := -1
	sqlStatement := `
INSERT INTO groups_users (user_id, group_id)
VALUES ($1, $2)
RETURNING id`

	err := d.db.QueryRow(sqlStatement, userId, 1).Scan(&id)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in inserting user into group_users table")
	}
	return nil
}

//activate or inactivate a user, status = 1 will activate user, status = 2 will inactivate user
func (d *Database) ActivateUser(userId int, status int) (int, error) {
	id := -1
	sqlStatement := `
INSERT INTO states_users (state_id, user_id)
VALUES ($1, $2)
RETURNING id`
	userStatus, err := d.GetUserStatus(userId)
	if err == NoRowFound {

		//if user does not exists in table states_users
		err = d.db.QueryRow(sqlStatement, status, userId).Scan(&id)
		if err != nil {
			return id, errorWrapper.Wrap(err, "failed in inserting user status in user_status table")
		}
		return id, nil
	}
	if userStatus != status {
		sqlUpdate := `	
UPDATE states_users
	SET state_id = $2
	WHERE id = $1;`
		_, err := d.db.Exec(sqlUpdate, userId, status)
		if err != nil {
			return userId, errorWrapper.Wrap(err, "failed in activating user")
		}
		return userId, nil
	}
	return userId, nil

}

func (d *Database) DeleteUser(email string) error {
	userId, err := d.GetUserId(email)
	if err != nil && err != NoRowFound {
		return err
	}
	if err := d.DeleteUserStatus(userId); err != nil {
		return errorWrapper.Wrap(err, "failed in deleting user status")
	}
	if err := d.DeleteAllUserRole(userId); err != nil {
		return err
	}
	if err := d.DeleteUserFromGroupUser(userId); err != nil {
		return err
	}
	logrus.Infof("Delete roles from user's: %s", email)
	if err := d.DeleteUserSession(userId); err != nil {
		return err
	}

	sqlStatement := `
DELETE FROM users
WHERE id = $1;`
	_, err = d.db.Exec(sqlStatement, userId)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in deleting user: "+email)
	}

	return nil
}

func (d *Database) GetUserId(email string) (int, error) {
	id := -1
	sqlStatement := `SELECT id FROM users WHERE email=$1;`
	row := d.db.QueryRow(sqlStatement, email)
	switch err := row.Scan(&id); err {
	case sql.ErrNoRows:
		return id, NoRowFound
	case nil:
		return id, nil
	default:
		return id, err
	}
}

func (d *Database) GetUserStatus(userId int) (int, error) {
	status := -1
	sqlStatement := `SELECT state_id FROM states_users WHERE user_id=$1;`
	row := d.db.QueryRow(sqlStatement, userId)
	switch err := row.Scan(&status); err {
	case sql.ErrNoRows:
		return status, NoRowFound
	case nil:
		return status, nil
	default:
		return status, err
	}
}

func (d *Database) DeleteUserStatus(userId int) error {
	id, err := d.GetUserStatusId(userId)
	if err != nil {
		if strings.Contains(err.Error(), "no row found") {
			return nil
		}
		return err
	}

	sqlStatement := `
DELETE FROM states_users
WHERE id = $1;`
	_, err = d.db.Exec(sqlStatement, id)
	if err != nil {
		if !strings.Contains(err.Error(), "no row found") {
			return err
		}
	}
	return nil
}

func (d *Database) DeleteUserFromGroupUser(userId int) error {
	sqlStatement := `
DELETE FROM groups_users
WHERE user_id = $1;`
	_, err := d.db.Exec(sqlStatement, userId)
	if err != nil {
		if !strings.Contains(err.Error(), "no row found") {
			return err
		}
	}
	return nil
}

func (d *Database) DeleteUserSession(userId int) error {
	sqlStatement := `
DELETE FROM session
WHERE user_id = $1;`
	_, err := d.db.Exec(sqlStatement, userId)
	if err != nil {
		if !strings.Contains(err.Error(), "no row found") {
			return err
		}
	}
	return nil
}

func (d *Database) GetUserStatusId(userId int) (int, error) {
	statusId := -1
	sqlStatement := `SELECT id FROM states_users WHERE user_id=$1;`
	row := d.db.QueryRow(sqlStatement, userId)
	switch err := row.Scan(&statusId); err {
	case sql.ErrNoRows:
		return statusId, NoRowFound
	case nil:
		return statusId, nil
	default:
		return statusId, err
	}
}

func (d *Database) GetAllUsers() (map[string]int, error) {
	var users = make(map[string]int)
	sqlStatement := `SELECT id, email FROM users;`
	rows, err := d.db.Query(sqlStatement)
	if err != nil {
		return nil, errorWrapper.Wrap(err, "failed in getting all users from database")
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var email string
		err = rows.Scan(&id, &email)
		if err != nil {
			return nil, errorWrapper.Wrap(err, "failed in reading row")
		}
		users[email] = id
	}
	err = rows.Err()
	if err != nil {
		return nil, errorWrapper.Wrap(err, "failed in end of reading rows")
	}
	return users, nil
}

func (d *Database) GetRoles() (map[string]string, map[string]int, error) {
	roles := make(map[string]string)
	rolesId := make(map[string]int)
	sqlStatement := `SELECT id, name, description FROM roles;`
	rows, err := d.db.Query(sqlStatement)
	if err != nil {
		return nil, nil, errorWrapper.Wrap(err, "failed in querying roles from database")
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		var desc string
		err = rows.Scan(&id, &name, &desc)
		if err != nil {
			return nil, nil, errorWrapper.Wrap(err, "failed in reading row from roles query")
		}
		name = "FP-FBA Role: " + name
		desc = strings.ReplaceAll(desc, "'", "")
		roles[name] = desc
		rolesId[name] = id
	}
	roles["FP-FBA Status: Active"] = "Active users have all granted privileges to them. All actions are visible within Forcepoint UEBA."
	roles["FP-FBA Status: Inactive"] = "Inactive users cannot login, their history is visible within Forcepoint UEBA and indicated with inactive label."
	rolesId["FP-FBA Status: Active"] = -1
	rolesId["FP-FBA Status: Inactive"] = -1
	err = rows.Err()
	if err != nil {
		return nil, nil, errorWrapper.Wrap(err, "failed in end of reading rows")
	}
	return roles, rolesId, nil
}

func (d *Database) GetUsersRoles(users map[string]int) (map[string][]int, error) {
	var usersRoles = make(map[string][]int)
	for u, id := range users {
		sqlStatement := `SELECT role_id FROM roles_users where user_id=$1;`
		rows, err := d.db.Query(sqlStatement, id)
		if err != nil {
			return nil, errorWrapper.Wrap(err, "failed in querying user roles from database")
		}
		for rows.Next() {
			var id int
			err = rows.Scan(&id)
			if err != nil {
				return nil, errorWrapper.Wrap(err, "failed in reading row from user's roles query")
			}
			usersRoles[u] = append(usersRoles[u], id)
		}
	}
	return usersRoles, nil
}

func (d *Database) AddUserRoles(userId int, rolesId []int) error {
	sqlStatement := `
INSERT INTO roles_users (role_id, user_id)
VALUES ($1, $2)`
	for _, roleId := range rolesId {
		_, err := d.db.Exec(sqlStatement, roleId, userId)
		if err != nil {
			return errorWrapper.Wrap(err, "failed in adding a role from user")
		}
	}
	return nil
}

func (d *Database) DeleteUserRole(userId int, rolesId []int) error {
	sqlStatement := `
DELETE FROM roles_users
WHERE role_id = $1 AND user_id = $2;`
	for _, roleId := range rolesId {
		_, err := d.db.Exec(sqlStatement, roleId, userId)
		if err != nil {
			return errorWrapper.Wrap(err, "failed in deleting user role")
		}
	}
	return nil
}

func (d *Database) UpdateUserStatus(userId int, status int) error {
	sqlUpdate := `	
UPDATE states_users
	SET state_id = $2
	WHERE user_id = $1;`
	cStatus, err := d.GetUserStatus(userId)
	if err != nil {
		return err
	}
	if cStatus != status {
		_, err := d.db.Exec(sqlUpdate, userId, status)
		if err != nil {
			return errorWrapper.Wrap(err, "failed in updating user status")
		}
	} else {
		return StatusMatched
	}
	return nil
}

func (d *Database) DeleteAllUserRole(userId int) error {
	sqlStatement := `
DELETE FROM roles_users
WHERE user_id = $1;`
	_, err := d.db.Exec(sqlStatement, userId)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in deleting user role")
	}

	return nil
}
