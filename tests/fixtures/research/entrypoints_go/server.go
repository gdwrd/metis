package main

import "net/http"

func run(w http.ResponseWriter, r *http.Request) {
  cmd := r.URL.Query().Get("cmd")
  _ = cmd
}

func ginHandler(c *gin.Context) {
  _ = c.Query("id")
}

func cobraRun(cmd *cobra.Command, args []string) {
  _ = args[0]
}

func init() {
  http.HandleFunc("/run", run)
  r.GET("/gin", ginHandler)
}
