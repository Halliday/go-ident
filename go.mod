module github.com/halliday/go-ident

go 1.18

replace github.com/halliday/go-errors => ../go-errors

replace github.com/halliday/go-module => ../go-module

replace github.com/halliday/go-tools => ../go-tools

replace github.com/halliday/go-router => ../go-router

replace github.com/halliday/go-rpc => ../go-rpc

replace github.com/halliday/go-values => ../go-values

replace github.com/halliday/go-openid => ../go-openid

require (
	github.com/golang-jwt/jwt/v4 v4.4.1
	github.com/google/uuid v1.3.0
	github.com/halliday/go-module v1.0.0
	github.com/halliday/go-openid v1.0.0
	github.com/halliday/go-router v1.0.0
	github.com/halliday/go-rpc v1.0.0
	github.com/halliday/go-tools v1.0.0
	github.com/jackc/pgtype v1.11.0
	github.com/jackc/pgx/v4 v4.16.1
	golang.org/x/crypto v0.0.0-20220518034528-6f7dac969898
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5
	github.com/halliday/go-errors v1.0.0
)

require (
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/halliday/go-values v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.12.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/puddle v1.2.2-0.20220404125616-4e959849469a // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
