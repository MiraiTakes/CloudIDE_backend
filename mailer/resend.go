package mailer

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

type resendPayload struct {
    From    string   `json:"from"`
    To      []string `json:"to"`
    Subject string   `json:"subject"`
    Text    string   `json:"text"`
}

func SendVerificationCodeResend(toEmail, code string) error {
    apiKey := os.Getenv("RESEND_API_KEY")

    payload := resendPayload{
        From:    "CloudIDE <noreply@cloudide.xyz>",
        To:      []string{toEmail},
        Subject: "Код подтверждения CloudIDE",
        Text:    fmt.Sprintf("Ваш код подтверждения: %s", code),
    }

    body, _ := json.Marshal(payload)

    req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(body))
    if err != nil {
        return fmt.Errorf("resend request create: %w", err)
    }

    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("resend send error: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        var buf bytes.Buffer
        buf.ReadFrom(resp.Body)
        return fmt.Errorf("resend error (%d): %s", resp.StatusCode, buf.String())
    }

    return nil
}