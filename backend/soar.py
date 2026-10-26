def block_sender(sender: str):
    print(f"[SOAR] Blocking sender: {sender}")

def disable_user(user_email: str):
    print(f"[SOAR] Disabling user account: {user_email}")

def notify_soc(incident: dict):
    print(f"[SOAR] SOC notified: {incident['id']} ({incident['classification']})")

def simulate_actions(incident: dict):
    classification = incident["classification"]
    sender = incident["from"]

    if classification == "PHISHING_HIGH":
        block_sender(sender)
        disable_user(sender)  # or victim user in a real system
        notify_soc(incident)
    elif classification == "PHISHING_MEDIUM":
        block_sender(sender)
        notify_soc(incident)
    elif classification == "PHISHING_LOW":
        notify_soc(incident)
    else:
        # BENIGN
        pass
    