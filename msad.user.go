package msad

import (
	"fmt"
	"github.com/go-ldap/ldap"
	"strings"
)

const (
	UserAccountEnable  = "66048"
	UserAccountDisable = "66050"
)

const (
	SCRIPT                                 = 0x00000001 // The logon script is executed.
	ACCOUNTDISABLE                         = 0x00000002 // The user account is disabled.
	HOMEDIR_REQUIRED                       = 0x00000008 // The home directory is required.
	LOCKOUT                                = 0x00000010 // The account is currently locked out.
	PASSWD_NOTREQD                         = 0x00000020 // No password is required.
	PASSWD_CANT_CHANGE                     = 0x00000040 // The user cannot change the password.
	ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000080 // The user can send an encrypted password.
	TEMP_DUPLICATE_ACCOUNT                 = 0x00000100 // This is an account for users whose primary account is in another domain.
	NORMAL_ACCOUNT                         = 0x00000200 // This is a default account type that represents a typical user.
	INTERDOMAIN_TRUST_ACCOUNT              = 0x00000800 // This is a permit to trust account for a system domain that trusts other domains.
	WORKSTATION_TRUST_ACCOUNT              = 0x00001000 // This is a computer account for a computer that is a member of this domain.
	SERVER_TRUST_ACCOUNT                   = 0x00002000 // This is a computer account for a system backup domain controller that is a member of this domain.
	Unused1                                = 0x00004000 // Not used.
	Unused2                                = 0x00008000 // Not used.
	DONT_EXPIRE_PASSWD                     = 0x00010000 // The password for this account will never expire.
	MNS_LOGON_ACCOUNT                      = 0x00020000 // This is an MNS logon account.
	SMARTCARD_REQUIRED                     = 0x00040000 // The user must log on using a smart card.
	TRUSTED_FOR_DELEGATION                 = 0x00080000 // The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
	NOT_DELEGATED                          = 0x00100000 // The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
	USE_DES_KEY_ONLY                       = 0x00200000 // Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
	DONT_REQUIRE_PREAUTH                   = 0x00400000 // This account does not require Kerberos pre-authentication for logon.
	PASSWORD_EXPIRED                       = 0x00800000 // The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
	TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000 // The account is enabled for delegation.
	USE_AES_KEYS                           = 0x08000000
)

func (s *MSAd) GetUserGroups(user *EntryFilter) ([]*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"memberOf", "primaryGroupID", "objectSid"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	results := make(EntryCollection, 0)
	for _, item := range searchResult.Entries {
		primaryGroupID := item.GetAttributeValue("primaryGroupID")
		if len(primaryGroupID) > 0 {
			objectSid := s.decodeSID(item.GetRawAttributeValue("objectSid"))
			if len(objectSid) > 0 {
				sidPrefixIndex := strings.LastIndex(objectSid, "-")
				sidPrefix := objectSid[0:sidPrefixIndex]
				groupSid := fmt.Sprintf("%s-%s", sidPrefix, primaryGroupID)
				result, err := s.getObjectBySid(conn, groupSid)
				if err == nil {
					result.Class = ClassGroup
					results = append(results, result)
				}
			}
		}

		attributes := item.GetAttributeValues("memberOf")
		for _, attribute := range attributes {
			name := entryPath.Name(attribute)
			if len(name) < 1 {
				continue
			}

			result := &Entry{
				Name: entryPath.Name(attribute),
				Path: entryPath.Path(attribute),
			}
			result.Class = ClassGroup
			results = append(results, result)
		}
	}
	results.Sort()

	return results, nil
}

func (s *MSAd) GetUserManager(user *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"manager"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	managerPath := ""
	for _, item := range searchResult.Entries {
		managerPath = item.GetAttributeValue("manager")
		break
	}
	if len(managerPath) < 1 {
		return nil, fmt.Errorf("manager not exist")
	}

	entryPath := newEntryPath(s.Cfg.Base)
	managerFilter := &EntryFilter{
		Path: entryPath.Path(managerPath),
	}

	return s.GetEntry(managerFilter)
}

func (s *MSAd) SetUserManager(user, manager *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return s.setUserManager(conn, user, manager)
}

func (s *MSAd) GetUserDirectReports(user *EntryFilter) ([]*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	managerEntry, err := s.getEntry(conn, user)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	managerDn := entryPath.DistinguishedName(managerEntry.Path)

	searchFilter := fmt.Sprintf("(&(objectClass=user)(manager=%s))", managerDn)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "directReports"},
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	results := make(EntryCollection, 0)
	for _, item := range searchResult.Entries {
		result := &Entry{
			Name: entryPath.Name(item.DN),
			Path: entryPath.Path(item.DN),
		}
		result.Class = ClassUser
		results = append(results, result)
	}
	results.Sort()

	return results, nil
}

func (s *MSAd) SetUserPassword(user *EntryFilter, password string) (*Entry, error) {
	pwd, err := s.encodePassword(password)
	if err != nil {
		return nil, err
	}

	conn, err := s.openTls(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userEntry, err := s.getEntry(conn, user)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	userDn := entryPath.DistinguishedName(userEntry.Path)

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	modifyRequest.Replace("unicodePwd", []string{pwd})
	err = conn.Modify(modifyRequest)
	if err != nil {
		return nil, err
	}

	return userEntry, nil
}

func (s *MSAd) ChangeUserPassword(user *EntryFilter, oldPassword, newPassword string) error {
	newPwd, err := s.encodePassword(newPassword)
	if err != nil {
		return err
	}

	userEntry, err := s.Authenticate(user.Account, oldPassword)
	if err != nil {
		return err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	userDn := entryPath.DistinguishedName(userEntry.Path)

	conn, err := s.openTls(true)
	if err != nil {
		return err
	}
	defer conn.Close()

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	modifyRequest.Replace("unicodePwd", []string{newPwd})
	err = conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (s *MSAd) CreateUser(user *EntryUserCreate) (*Entry, error) {
	conn, err := s.openTls(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if user.Account == "" {
		return nil, fmt.Errorf("账号为空")
	}
	filter := &EntryFilter{
		Account: user.Account,
	}
	_, err = s.getEntry(conn, filter)
	if err == nil {
		return nil, fmt.Errorf("账号(%s)已存在", user.Account)
	}
	if user.Name == "" {
		user.Name = user.Account
	}
	entryPath := newEntryPath(s.Cfg.Base)
	userDn := entryPath.DistinguishedName(fmt.Sprintf("CN=%s,CN=Users", user.Name))
	if user.Parent != nil {
		filter = &EntryFilter{
			Path: user.Parent.Path,
		}
		parentEntry, err := s.getEntry(conn, filter)
		if err != nil {
			return nil, fmt.Errorf("父级容器(%s)不存在", user.Parent.Path)
		}
		userDn = entryPath.DistinguishedName(fmt.Sprintf("CN=%s,%s", user.Name, parentEntry.Path))
	}
	filter = &EntryFilter{
		Path: entryPath.Path(userDn),
	}
	_, err = s.getEntry(conn, filter)
	if err == nil {
		return nil, fmt.Errorf("姓名(%s)已存在", filter.Path)
	}

	pwd, err := s.encodePassword(user.Password)
	if err != nil {
		return nil, fmt.Errorf("秘密无效: %v", err)
	}
	email, _ := filter.getAccount(s.Cfg.Base, user.Account)

	addRequest := ldap.NewAddRequest(userDn, nil)
	addRequest.Attribute("objectClass", []string{ClassUser})
	addRequest.Attribute("sAMAccountName", []string{user.Account})
	addRequest.Attribute("userPrincipalName", []string{email})
	addRequest.Attribute("mail", []string{email})

	err = conn.Add(addRequest)
	if err != nil {
		return nil, err
	}

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	modifyRequest.Replace("unicodePwd", []string{pwd})
	err = conn.Modify(modifyRequest)
	if err != nil {
		s.deleteUser(conn, &EntryFilter{Path: entryPath.Path(userDn)})
		return nil, err
	}

	modifyRequest = ldap.NewModifyRequest(userDn, nil)
	modifyRequest.Replace("userAccountControl", []string{UserAccountEnable})
	err = conn.Modify(modifyRequest)
	if err != nil {
		s.deleteUser(conn, &EntryFilter{Path: entryPath.Path(userDn)})
		return nil, err
	}

	userEntry := &Entry{
		Path:  entryPath.Path(userDn),
		Name:  entryPath.Name(userDn),
		Class: ClassUser,
	}

	if user.Manager != nil {
		s.setUserManager(conn, &EntryFilter{Path: userEntry.Path}, &EntryFilter{Path: user.Manager.Path})
	}

	return userEntry, nil
}

func (s *MSAd) DeleteUser(user *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return s.deleteUser(conn, user)
}

func (s *MSAd) GetUserControl(user *EntryFilter) (*EntryUserControl, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"userAccountControl"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("not found: %s", searchFilter)
	}

	userAccountControl := ""
	for _, item := range searchResult.Entries {
		userAccountControl = item.GetAttributeValue("userAccountControl")
		break
	}

	controlEntry := &EntryUserControl{}
	err = controlEntry.FromValue(userAccountControl)
	if err != nil {
		return nil, err
	}

	return controlEntry, nil
}

func (s *MSAd) SetUserControl(user *EntryFilter, control *EntryUserControl) (*EntryUserControl, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "userAccountControl"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("not found: %s", searchFilter)
	}

	userDn := ""
	userAccountControl := ""
	for _, item := range searchResult.Entries {
		userDn = item.DN
		userAccountControl = item.GetAttributeValue("userAccountControl")
		break
	}
	controlValue, err := control.ToValue(userAccountControl)
	if err != nil {
		return nil, err
	}

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	modifyRequest.Replace("userAccountControl", []string{controlValue})
	err = conn.Modify(modifyRequest)
	if err != nil {
		return nil, err
	}

	return control, nil
}

func (s *MSAd) GetUserVpnEnable(user *EntryFilter) (bool, error) {
	conn, err := s.open(true)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"msNPAllowDialin"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}
	if len(searchResult.Entries) < 1 {
		return false, fmt.Errorf("not found: %s", searchFilter)
	}

	msNPAllowDialin := ""
	for _, item := range searchResult.Entries {
		msNPAllowDialin = item.GetAttributeValue("msNPAllowDialin")
		break
	}

	if strings.ToUpper(msNPAllowDialin) == "TRUE" {
		return true, nil
	} else {
		return false, nil
	}
}

func (s *MSAd) SetUserVpnEnable(user *EntryFilter, enable bool) error {
	conn, err := s.open(true)
	if err != nil {
		return err
	}
	defer conn.Close()

	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "msNPAllowDialin"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return err
	}
	if len(searchResult.Entries) < 1 {
		return fmt.Errorf("not found: %s", searchFilter)
	}

	userDn := ""
	msNPAllowDialin := ""
	for _, item := range searchResult.Entries {
		userDn = item.DN
		msNPAllowDialin = item.GetAttributeValue("msNPAllowDialin")
		break
	}

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	if enable {
		if len(msNPAllowDialin) > 0 {
			modifyRequest.Replace("msNPAllowDialin", []string{"TRUE"})
		} else {
			modifyRequest.Add("msNPAllowDialin", []string{"TRUE"})
		}
	} else {
		modifyRequest.Delete("msNPAllowDialin", []string{"TRUE"})
	}
	err = conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (s *MSAd) deleteUser(conn *ldap.Conn, user *EntryFilter) (*Entry, error) {
	userEntry, err := s.getEntry(conn, user)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	userDn := entryPath.DistinguishedName(userEntry.Path)

	delRequest := ldap.NewDelRequest(userDn, nil)
	err = conn.Del(delRequest)
	if err != nil {
		return nil, err
	}

	return userEntry, nil
}

func (s *MSAd) setUserManager(conn *ldap.Conn, user, manager *EntryFilter) (*Entry, error) {
	searchFilter := user.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "manager"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	userDn := ""
	managerOldDn := ""
	for _, item := range searchResult.Entries {
		userDn = item.DN
		managerOldDn = item.GetAttributeValue("manager")
		break
	}

	managerEntry, err := s.getEntry(conn, manager)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	managerNewDN := entryPath.DistinguishedName(managerEntry.Path)
	if managerNewDN == managerOldDn {
		return managerEntry, nil
	}

	modifyRequest := ldap.NewModifyRequest(userDn, nil)
	if len(managerOldDn) > 0 {
		modifyRequest.Replace("manager", []string{managerNewDN})
	} else {
		modifyRequest.Add("manager", []string{managerNewDN})
	}
	err = conn.Modify(modifyRequest)
	if err != nil {
		return nil, err
	}

	return managerEntry, nil
}
