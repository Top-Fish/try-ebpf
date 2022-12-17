package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func hello(c *gin.Context) {
	fmt.Printf("请求路径:%v\n", c.Request.URL.Path)
	fmt.Printf("操作方法:%v\n", c.Request.Method)
	fmt.Printf("请求内容:%v\n", c.Request.Body)
	c.String(http.StatusOK, "欢迎来到三体世界")
}

func main() {
	r := gin.Default()

	ebpfGroup := r.Group("/ebpf")
	ebpfGroup.GET("/", hello)
	ebpfGroup.POST("/", hello)

	r.Run(":8080")
}
