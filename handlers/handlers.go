package handlers

import (
	"fmt"
	"net/smtp"
	"os"
	"math/rand"
	"time"
	"database/sql"
	"encoding/json"
	"grameenkart/db"
	"grameenkart/module"
	"net/http"
)

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req module.SignupRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" || req.UserType == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	if req.UserType == "admin" {
		http.Error(w, "Admin signup not allowed", http.StatusForbidden)
		return
	}

	var existing int
	err = db.DB.QueryRow("SELECT id FROM users WHERE email=$1", req.Email).Scan(&existing)

	if err != sql.ErrNoRows {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := module.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Error processing password", 500)
		return
	}

	query := `
		INSERT INTO users (name, email, password, user_type)
		VALUES ($1, $2, $3, $4)
	`

	_, err = db.DB.Exec(query, req.Name, req.Email, hashedPassword, req.UserType)
	if err != nil {
		http.Error(w, "Error creating user", 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Signup successful",
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req module.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password required", 400)
		return
	}

	var userID int
	var email, hashedPassword, userType string

	query := `
		SELECT id, email, password, user_type
		FROM users
		WHERE email=$1
	`

	err = db.DB.QueryRow(query, req.Email).
		Scan(&userID, &email, &hashedPassword, &userType)

	if err == sql.ErrNoRows {
		http.Error(w, "User not found. Please signup.", 404)
		return
	}

	err = module.CheckPassword(hashedPassword, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	token, err := module.GenerateToken(userID, email)
	if err != nil {
		http.Error(w, "Error generating token", 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"token":   token,
		"user": map[string]interface{}{
			"id":       userID,
			"email":    email,
			"userType": userType,
		},
	})
}

func SendOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req module.OTPRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Email == "" {
		http.Error(w, "Email required", 400)
		return
	}
	rand.Seed(time.Now().UnixNano())
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	expiry := time.Now().Add(5 * time.Minute)

	query := `
		INSERT INTO email_otp (email, otp, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (email)
		DO UPDATE SET
		otp = EXCLUDED.otp,
		expires_at = EXCLUDED.expires_at`
	
	_, err := db.DB.Exec(query, req.Email, otp, expiry)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}

	err = SendEmail(req.Email, otp)
	if err != nil {
		fmt.Println("Email error:", err)
		http.Error(w, "Failed to send email", 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP sent to email",
	})
}

func VerifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req module.OTPRequest
	json.NewDecoder(r.Body).Decode(&req)

	var dbOtp string
	var expiry time.Time

	query := `SELECT otp, expires_at FROM email_otp WHERE email=$1 ORDER BY expires_at DESC LIMIT 1`
	err := db.DB.QueryRow(query, req.Email).Scan(&dbOtp, &expiry)
	if err != nil {
		http.Error(w, "OTP not found", 404)
		return
	}

	if time.Now().After(expiry) {
		http.Error(w, "OTP expired", 400)
		return
	}

	if dbOtp != req.Otp {
		http.Error(w, "Invalid OTP", 400)
		return
	}

	_, err = db.DB.Exec(`DELETE FROM email_otp WHERE email=$1`, req.Email)
	if err != nil {
		http.Error(w, "Failed to cleanup OTP", 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP verified successfully",
	})
}

func SendEmail(to string, otp string) error {
	from := os.Getenv("EMAIL_SENDER")
	password := os.Getenv("EMAIL_PASSWORD")

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	msg := []byte(fmt.Sprintf(
		"Subject: GrameenKart OTP Verification\r\n"+
			"MIME-version: 1.0;\r\nContent-Type: text/plain; charset=\"UTF-8\";\r\n\r\n"+
			"Your OTP is: %s\nValid for 5 minutes.",
		otp,
	))

	auth := smtp.PlainAuth("", from, password, smtpHost)

	return smtp.SendMail(
		smtpHost+":"+smtpPort,
		auth,
		from,
		[]string{to},
		msg,
	)
}

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req module.ResetPasswordRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	if req.Email == "" || req.NewPassword == "" {
		http.Error(w, "Email and new password required", 400)
		return
	}

	// Hash new password
	hashedPassword, err := module.HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Error hashing password", 500)
		return
	}

	// Update password
	result, err := db.DB.Exec(
		"UPDATE users SET password=$1 WHERE email=$2",
		hashedPassword,
		req.Email,
	)

	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		http.Error(w, "User not found", 404)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password updated successfully",
	})
}