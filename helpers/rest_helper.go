package helpers

import (
	"encoding/json"
	"net/http"
)

type MessageResponse struct {
	Message string `json:"message"`
}

func WriteJSONResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

func DecodeRequestBody[T any](r *http.Request, w http.ResponseWriter) (*T, bool) {
	var request T
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		WriteJSONResponse(w, http.StatusBadRequest, MessageResponse{
			Message: "Invalid request body",
		})
		return nil, false
	}
	return &request, true
}
