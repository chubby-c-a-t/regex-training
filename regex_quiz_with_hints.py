import random
import re
import readline
import sys
from datetime import datetime, timedelta

_ = readline

class SyntheticLogGenerator:
    """Generates random SOC logs and dynamically selects a target field for extraction."""
    
    @staticmethod
    def gen_ip():
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    @staticmethod
    def gen_user():
        names = ['jsmith', 'admin', 'svc_account', 'root', 'guest', 't.stark', 'b.wayne', 'system']
        return f"{random.choice(names)}_{random.randint(100, 999)}"

    @staticmethod
    def gen_pid():
        return str(random.randint(1000, 65535))

    @staticmethod
    def gen_port():
        return str(random.randint(1024, 65535))

    @staticmethod
    def gen_status():
        return str(random.choice([200,301,303,401,403,404,500]))
        
    @staticmethod
    def gen_timestamp():
        now = datetime.now()
        random_days = random.randint(0, 30)
        random_minutes = random.randint(0, 1440)
        past_date = now - timedelta(days=random_days, minutes=random_minutes)
        return past_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_challenge(self):
        """Builds a random log and selects a random field to be extracted."""
        data = {
            "Source IP": self.gen_ip(),
            "Destination IP": self.gen_ip(),
            "Username": self.gen_user(),
            "PID": self.gen_pid(),
            "Source Port": self.gen_port(),
            "Destination Port": self.gen_port(),
            "HTTP Status": self.gen_status(),
            "Timestamp": self.gen_timestamp()
        }

        templates = [
            {
                "log": f"{data['Timestamp']} sshd[{data['PID']}]: Failed password for invalid user {data['Username']} from {data['Source IP']} port {data['Source Port']} ssh2",
                "available_targets": ["Timestamp", "PID", "Username", "Source IP", "Source Port"]
            },
            {
                "log": f"{data['Source IP']} - {data['Username']} [{data['Timestamp']}] \"POST /api/v1/login HTTP/1.1\" {data['HTTP Status']} 4392",
                "available_targets": ["Source IP", "Username", "HTTP Status"]
            },
            {
                "log": f"CEF:0|Security|Firewall|v1.0|100|BLOCK|7|src={data['Source IP']} dst={data['Destination IP']} spt={data['Source Port']} dpt={data['Destination Port']}",
                "available_targets": ["Source IP", "Destination IP", "Source Port", "Destination Port"]
            },
            {
                "log": f"EventID: 4625, User: {data['Username']}, Client_IP: {data['Source IP']}, Process_ID: {data['PID']}, Status: 0xC000006D",
                "available_targets": ["Username", "Source IP", "PID"]
            }
        ]

        chosen_template = random.choice(templates)
        target_field_name = random.choice(chosen_template["available_targets"])
        target_value = data[target_field_name]

        return chosen_template["log"], target_field_name, target_value

def run_trainer():
    print("=" * 75)
    print("      SOC Analyst RegEx Trainer      ")
    print("=" * 75)
    print("Instructions: Write a RegEx pattern containing ONE capture group ()")
    print("to extract the exact requested field from the randomly generated log.\n")
    print("Type 'quit' to exit or 'skip' for a new log.\n")

    hints = {
"Source IP": r"""Look for 4 groups of numbers, or anchor to a prefix.
Try: `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})` or `src=(\S+)`
• `\d`    = Any digit (0-9).
• `{1,3}` = Matches between 1 and 3 of the preceding character.
• `\.`    = Escapes the period so it acts as a literal dot, not a wildcard.
• `\S`    = Any non-whitespace character (capital S).
• `+`     = Matches 1 or more of the preceding character.""",

        "Destination IP": r"""Look for an IP format, usually following 'dst='.
Try capturing non-whitespace characters: `dst=(\S+)` or `dst=([\d\.]+)`
• `dst=`   = Literal string anchor.
• `[\d\.]` = A custom character class matching either a digit OR a literal dot.
• `+`      = 1 or more times.
• `()`     = Your capture group to extract just the IP.""",

        "Username": r"""Context dictates the pattern depending on the log type.
Web logs: `-\s(\S+)\s\[` (Grabs characters between the hyphen and the timestamp bracket).
Win logs: `User:\s([^,]+)` (Grabs everything until a comma).
SSH logs: `user\s(\w+)` (Grabs word characters after 'user ').
• `\s`    = Any whitespace character (space, tab).
• `\[`    = Escaped left bracket (targets the `[` in web logs).
• `[^,]`  = A negated set. Matches anything that is NOT a comma.
• `\w`    = Any word character (alphanumeric and underscores).""",

        "PID": r"""Process IDs are numbers often found inside brackets or after 'Process_ID:'.
Try: `\[(\d+)\]` or `Process_ID:\s(\d+)`
• `\[` / `\]` = Escaped literal brackets.
• `\d`        = Any digit.
• `+`         = 1 or more digits (handles variable length PIDs).""",

        "Source Port": r"""Look for numbers near 'port ' or 'spt='.
Try: `port\s(\d+)` or `spt=(\d+)`
• `\s` = Accounts for the space after the word 'port'.
• `\d+` = Captures the numeric port value.
• `\b` = Try adding a word boundary `\bport\s(\d+)` to ensure you match 'port' and not a word like 'support'.""",

        "Destination Port": r"""Look for numbers near 'dpt='.
Try: `dpt=(\d+)`
• `dpt=` = Literal anchor.
• `\d+`  = Extracts 1 or more digits.""",

        "HTTP Status": r"""A 3-digit number near the end. Anchor it with quotes or spaces.
Try: `"\s(\d{3})\s`
• `"`    = Matches the literal quote closing the HTTP request string.
• `\s`   = Matches the space before and after the status code.
• `\d{3}`= Matches EXACTLY 3 digits (ensures you don't grab a port or bytes field).""",

        "Timestamp": r"""Timestamps are either at the start of the line or inside brackets.
Try: `^(\S+)` (Start of line) or `\[(.*?)\]` (Inside brackets)
• `^`    = Asserts the start of a line.
• `\S+`  = Grabs everything until the first space.
• `.*?`  = Lazy match. Grabs characters until the VERY FIRST closing bracket `\]` it sees."""
    }
    
    generator = SyntheticLogGenerator()
    score = 0
    rounds = 0

    while True:
        rounds += 1
        raw_log, target_name, expected_value = generator.get_challenge()
        
        print(f"\n--- [ Round {rounds} | Score: {score} ] ---")
        print(f"Raw Log: \n--> {raw_log}")
        print(f"Target Field to Extract: **{target_name}**")
        
        attempts = 0
        while attempts < 3:
            user_pattern = input("\nEnter your RegEx pattern: ").strip()
            
            if user_pattern.lower() == 'quit':
                print(f"\nExiting. Final Score: {score} out of {rounds-1} completed rounds.")
                sys.exit(0)
            elif user_pattern.lower() == 'skip':
                print(f"Skipped. The correct value we were looking for was: {expected_value}")
                break

            success = False
                
            try:
                compiled_re = re.compile(user_pattern)
                match = compiled_re.search(raw_log)
                
                if match:
                    if match.groups():
                        extracted_val = match.group(1)
                        if extracted_val == expected_value:
                            print(f"SUCCESS! Captured '{extracted_val}'. Excellent data parsing.")
                            score += 1
                            success = True
                            break
                        else:
                            print(f"CLOSE: Captured '{extracted_val}', but needed '{expected_value}'.")
                    else:
                        print("WARNING: You found a match, but forgot the capture group () to extract the data!")
                else:
                    print("NO MATCH: Your RegEx didn't trigger on this log.")
                    
            except re.error as e:
                print(f"INVALID REGEX: {e}. Check your syntax.")

            if not success and attempts == 0:
                print(f"\nHINT: {hints.get(target_name, 'No hint available.')}")
                
            attempts += 1
            if attempts < 3:
                print(f"Remaining attempts: {3 - attempts}")
            else:
                print(f"Out of attempts! The target value was: '{expected_value}'")

if __name__ == "__main__":
    try:
        run_trainer()
    except KeyboardInterrupt:
        print("\nSession terminated.")
        sys.exit(0)