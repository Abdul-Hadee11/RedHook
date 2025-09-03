import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime

# === CONFIG ===
EMAIL_USER = "redhookcs@gmail.com"
EMAIL_PASS = "socmrcelluzzcztn"  # App password from Gmail
MAILBOX = "inbox"

def clean(text):
    """Sanitize text for safe filenames/logs"""
    return "".join(c if c.isalnum() else "_" for c in text)

def fetch_recent_emails(max_results=5):  # ✅ Accepts optional argument
    print("[FETCHER] Starting fetch_recent_emails")
    """Fetches the most recent emails from Gmail inbox via IMAP"""
    try:
        # Connect to Gmail IMAP
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(EMAIL_USER, EMAIL_PASS)
    except Exception as e:
        print(f"❌ Login failed: {e}")
        return []

    try:
        # Select mailbox
        imap.select(MAILBOX)
        status, messages = imap.search(None, "ALL")
        if status != "OK":
            print("❌ Failed to retrieve emails.")
            return []

        email_ids = messages[0].split()[-max_results:]  # ✅ use max_results instead of fixed N_EMAILS
        emails = []

        for eid in email_ids:
            print(f"[FETCHER] Fetching email ID: {eid}")

            _, msg_data = imap.fetch(eid, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    try:
                        msg = email.message_from_bytes(response_part[1])

                        # Decode subject
                        raw_subject = msg.get("Subject", "")
                        subject, encoding = decode_header(raw_subject)[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding or "utf-8", errors="ignore")

                        # Decode sender
                        raw_from = msg.get("From", "")
                        sender, enc = decode_header(raw_from)[0]
                        if isinstance(sender, bytes):
                            sender = sender.decode(enc or "utf-8", errors="ignore")

                        # Extract timestamp
                        raw_date = msg.get("Date", "")
                        try:
                            timestamp = parsedate_to_datetime(raw_date)
                            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception as e:
                            print(f"[!] Failed to parse date: {raw_date} – {e}")
                            timestamp_str = "N/A"

                        # Extract plain text body
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk(): 
                                content_type = part.get_content_type()
                                content_dispo = str(part.get("Content-Disposition"))
                                if content_type == "text/plain" and "attachment" not in content_dispo:
                                    try:
                                        body_bytes = part.get_payload(decode=True)
                                        if body_bytes:
                                            body = body_bytes.decode(errors="ignore")
                                            break
                                    except Exception as decode_err:
                                        print(f"[!] Body decode failed: {decode_err}")
                        if not body and content_type == "text/html":
                            try:
                                body_bytes = part.get_payload(decode=True)
                                if body_bytes:
                                    body = body_bytes.decode(errors="ignore")
                            except:
                                pass

                        emails.append({
                            "subject": subject.strip() or "No Subject",
                            "from": sender.strip() or "unknown@example.com",
                            "body": body.strip() or "[NO BODY FOUND]",
                            "timestamp": timestamp_str
                        })

                    except Exception as parse_error:
                        print(f"[!] Failed to parse email: {parse_error}")
        print("[FETCHER] Final emails:", emails)
        return emails

    finally:
        imap.logout()


# Optional test
if __name__ == "__main__":
    emails = fetch_recent_emails(max_results=5)
    for idx, mail in enumerate(emails):
        print(f"\n📧 Email #{idx+1}")
        print("Subject:", mail["subject"])
        print("From:", mail["from"])
        print("Date:", mail["timestamp"])
        print("Body Preview:", mail["body"][:300], "...\n")
