module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.6.0

require (
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
	github.com/stretchr/testify v1.8.0
)

replace github.com/stretchr/testify => github.com/stretchr/testify v1.8.1