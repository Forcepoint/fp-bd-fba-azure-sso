package cmd

import (
	"errors"
	"github.cicd.cloud.fpdev.io/BD/fp-fba-azure-sso/lib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strings"
)

const ACTIVATE = 1

func SyncUsers(azureUsers, fbaUsers, appUsers []string) error {
	if len(appUsers) == 0 {
		return errors.New("there is no user assigned to app: " + viper.GetString("AZURE_APPLICATION_NAME"))
	}
	var addUsers []string
	var deleteUsers []string
	for _, user := range appUsers {
		if user != "" && user != " " {
			if !strings.Contains(user, "#EXT#") {
				if !IsElementInList(fbaUsers, user) {
					addUsers = append(addUsers, user)
				}
			}
		}
	}

	for _, user := range fbaUsers {
		if user != "" && user != " " {
			if !IsElementInList(appUsers, user) && IsElementInList(azureUsers, user) {
				deleteUsers = append(deleteUsers, user)
			}
		}
	}
	if len(addUsers) != 0 {
		if err := AddUsersToDatabase(addUsers); err != nil {
			return err
		}
	}
	if len(deleteUsers) != 0 {
		if err := DeleteUsersFromDatabase(deleteUsers); err != nil {
			return err
		}
	}
	return nil
}

func IsElementInList(lis []string, element string) bool {
	for _, e := range lis {
		if e == element {
			return true
		}
	}
	return false
}

func AddUsersToDatabase(users []string) error {
	for _, user := range users {
		if user != "" && user != " " {
			userName, err := AzureInstance.GetUsrName(user)
			if err != nil {
				return err
			}
			userId, err := DBInstance.InsertUser(userName, user, viper.GetString("DEFAULT_FBA_PASSWORD"))
			if err != nil {
				return err
			}
			if err := DBInstance.InsertUserToGroup(userId); err != nil {
				return err
			}
			_, err = DBInstance.ActivateUser(userId, ACTIVATE)
			if err != nil && err != lib.NoRowFound {
				return err
			}
		}
		logrus.Infof("user %s is been added to database", user)
	}
	return nil
}

func DeleteUsersFromDatabase(users []string) error {
	for _, user := range users {
		if user != "" && user != " " {
			err := DBInstance.DeleteUser(user)
			if err != nil {
				return err
			}
		}
		logrus.Infof("user %s is been removed from database", user)
	}
	return nil
}

func SyncRoles(azureGroupMembers map[string][]string, fbaUserRoles map[string][]int, fbaUsers map[string]int, rolesId map[string]int) error {
	var mapAzureUserToRoles = make(map[string][]int)
	var addUserRoles = make(map[string][]int)
	var removeUserRoles = make(map[string][]int)
	var activeUsers []string
	var inactiveUsers []string
	for role, users := range azureGroupMembers {
		if role == "FP-FBA Status: Active" {
			activeUsers = users
			continue
		}
		if role == "FP-FBA Status: Inactive" {
			inactiveUsers = users
			continue
		}
		id := rolesId[role]
		for _, user := range users {
			if user != "" {
				mapAzureUserToRoles[user] = append(mapAzureUserToRoles[user], id)
			}
		}

	}
	for user, roles := range mapAzureUserToRoles {
		onFba := fbaUserRoles[user]
		for _, role := range roles {
			if !integerInList(onFba, role) {
				if role != -1 {
					addUserRoles[user] = append(addUserRoles[user], role)
				}
			}
		}
		for _, role := range onFba {
			if !integerInList(roles, role) {
				if role != -1 {
					removeUserRoles[user] = append(removeUserRoles[user], role)
				}
			}
		}
	}
	restrictedRoleId := rolesId["FP-FBA Role: restricted user"]
	shieldedRoleId := rolesId["FP-FBA Role: shielded user"]
	for user, roles := range addUserRoles {
		if integerInList(roles, restrictedRoleId) && len(roles) != 1 {
			return errors.New("the role 'restricted user' cannot be used in conjunction with other roles for user: " + user)
		}
		if integerInList(roles, shieldedRoleId) && len(roles) != 1 {
			return errors.New("the role 'shielded user' cannot be used in conjunction with other roles for user: " + user)
		}
	}
	for user, roles := range removeUserRoles {
		user = strings.TrimSpace(user)
		if user != "" && user != " " {
			userId := fbaUsers[user]
			if userId != 0 {
				if err := DBInstance.DeleteUserRole(userId, roles); err != nil && err != lib.NoRowFound {
					return err
				}
				logrus.Infof("Delete roles for user: %s", user)
			}
		}

	}
	for user, roles := range addUserRoles {
		user = strings.TrimSpace(user)
		if user != "" && user != " " {
			userId := fbaUsers[user]
			if userId != 0 {
				if err := DBInstance.AddUserRoles(userId, roles); err != nil && err != lib.NoRowFound {
					return err
				}
				logrus.Infof("Added roles for user: %s", user)
			}
		}
	}
	for _, user := range activeUsers {
		user = strings.TrimSpace(user)
		if user != "" && user != " " {
			userId := fbaUsers[user]
			if userId != 0 {
				if err := DBInstance.UpdateUserStatus(userId, 1); err != nil {
					if err == lib.StatusMatched || err == lib.NoRowFound {
						continue
					}
					if err != lib.StatusMatched && err != lib.NoRowFound {
						return err
					}
				}
				logrus.Infof("Active user: %s", user)
			}
		}
	}
	for _, user := range inactiveUsers {
		user = strings.TrimSpace(user)
		if user != "" && user != " " {
			userId := fbaUsers[user]
			if userId != 0 {
				if err := DBInstance.UpdateUserStatus(userId, 2); err != nil {
					if err != lib.StatusMatched {
						return err
					} else {
						continue
					}
				}
			}
			logrus.Infof("Inactive user: %s", user)
		}
	}
	return nil
}

func integerInList(list []int, number int) bool {
	for _, i := range list {
		if i == number {
			return true
		}
	}
	return false
}
