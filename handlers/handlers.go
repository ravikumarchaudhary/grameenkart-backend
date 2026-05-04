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
	"github.com/lib/pq"
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
	if req.Type == "" {
		req.Type = "resetpassword"
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
	err = SendEmail(req.Email, otp, req.Type)
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

func SendEmail(to string, otp string, usertype string) error {
	from := os.Getenv("EMAIL_SENDER")
	password := os.Getenv("EMAIL_PASSWORD")
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	var subject string
	var body string
	if usertype == "resetpassword" {
		subject = "GrameenKart Password Reset OTP"
		body = fmt.Sprintf(`
		<html>
		<body style="font-family: Arial, sans-serif; background-color:#f4f4f4; padding:20px;">
			<div style="max-width:500px; margin:auto; background:white; padding:20px; border-radius:10px;">
				<h2 style="color:#2e7d32; text-align:center;">GrameenKart</h2>
				<p>Hello,</p>
				<p>You requested to reset your password.</p>
				<p>Your OTP for password reset is:</p>
				<div style="text-align:center; margin:20px 0;"><span style="font-size:28px; font-weight:bold; letter-spacing:5px;">%s</span>
				</div>
				<p>This OTP is valid for <b>5 minutes</b>.</p>
				<p style="color:red;"><b>⚠️ Do NOT share this OTP with anyone.</b></p>
				<p>If you did NOT request a password reset, please ignore this email.</p>
				<hr/>
				<p style="font-size:12px; color:#888; text-align:center;">© 2026 GrameenKart. All rights reserved.</p>
			</div>
		</body>
		</html>
		`, otp)

	} else {
		subject = "GrameenKart OTP Verification"
		body = fmt.Sprintf(`
		<html>
		<body style="font-family: Arial, sans-serif; background-color:#f4f4f4; padding:20px;">
			<div style="max-width:500px; margin:auto; background:white; padding:20px; border-radius:10px;">
				<h2 style="color:#2e7d32; text-align:center;">GrameenKart</h2>
				<p>Hello,</p>
				<p>Your One-Time Password (OTP) for account verification is:</p>
				<div style="text-align:center; margin:20px 0;"><span style="font-size:28px; font-weight:bold; letter-spacing:5px;">%s</span></div>
				<p>This OTP is valid for <b>5 minutes</b>.</p>
				<p style="color:red;"><b>⚠️ Do NOT share this OTP with anyone.</b></p>
				<p>If you did not request this, please ignore this email.</p>
				<hr/>
				<p style="font-size:12px; color:#888; text-align:center;">© 2026 GrameenKart. All rights reserved.</p>
			</div>
		</body>
		</html>
		`, otp)
	}
	msg := []byte(fmt.Sprintf(
		"Subject: %s\r\n"+
			"MIME-version: 1.0;\r\n"+
			"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n"+
			"%s",
		subject,
		body,
	))
	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort,auth,from,[]string{to},msg,)
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

func GetItemsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`
		SELECT id, name, price, description, image, created_by, discountpercentage, images, created_at
		FROM items ORDER BY created_at DESC
	`)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var items []map[string]interface{}

	for rows.Next() {
		var id int
		var name, desc, image, createdBy string
		var price float64
		var discount float64
		var images []string
		var createdAt time.Time

		err := rows.Scan(
			&id,
			&name,
			&price,
			&desc,
			&image,
			&createdBy,
			&discount,
			pq.Array(&images),
			&createdAt,
		)

		if err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			return
		}

		items = append(items, map[string]interface{}{
			"id": id,
			"name": name,
			"price": price,
			"description": desc,
			"image": image,
			"images": images,
			"created_by": createdBy,
			"discountpercentage": discount,
			"created_at": createdAt,
		})
	}

	json.NewEncoder(w).Encode(items)
}

func InsertItemHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req module.ItemRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Price <= 0 || req.CreatedBy == "" {
		http.Error(w, "Name, Price and CreatedBy are required", http.StatusBadRequest)
		return
	}

	query := `
	INSERT INTO items (name, description, price, image, images, created_by, discountpercentage)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	RETURNING id, created_at
	`

	var id int
	var createdAt time.Time

	err = db.DB.QueryRow(
		query,
		req.Name,
		req.Description,
		req.Price,
		req.Image,
		req.Images,
		req.CreatedBy,
		req.DiscountPercentage,
	).Scan(&id, &createdAt)

	if err != nil {
		fmt.Println("DB Error:", err)
		http.Error(w, "Failed to insert item", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Item created successfully",
		"id":      id,
		"time":    createdAt,
	})
}