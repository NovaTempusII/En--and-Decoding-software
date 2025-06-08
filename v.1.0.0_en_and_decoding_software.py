import string
import hashlib
import os
import logging
from pathlib import Path
from datetime import datetime

DEBUG = False

def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}\n")
    logger.debug(msg)

SPECIALS = set("""@#€_&-+()/?!;:'"*№$£¢¥₱₹—–·±[<{>}]★†‡”„“»«’‚‘›‹¡¿‽~`|♣♪♠♥♦•√ΩΠμπ÷×¶§∆£←↑↓→^′″°∞≠≈=\\‰℅%©®™✓., """ + string.punctuation)

def setup_logging():
    """Set up logging to file in user's Documents folder and console."""
    # Determine user's Documents folder
    home = Path.home()
    documents = home / "Documents"
    if not documents.exists():
        documents = home  # fallback to home if Documents doesn't exist

    log_dir = documents / "en-decoding_software"
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"debug_log_{timestamp}.txt"

    # Configure logger
    global logger
    logger = logging.getLogger("encoder_decoder")
    logger.setLevel(logging.DEBUG)

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_level = logging.DEBUG if DEBUG else logging.INFO
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logger.info(f"Logging started. Log file at: {log_file}")

def generate_key_seq(key: str) -> list:
    debug(f"Generating key sequence from key: {key}")
    if not (key.isdigit() and len(key) == 10):
        raise ValueError("Key must be a 10-digit number string.")

    hash_input = key
    hash_stream = ""

    total_chunks = (26 * 3) + (26 * 2) + (10 * 1) + (len(SPECIALS) * 4)
    total_letters_needed = total_chunks
    debug(f"Need to generate {total_letters_needed} letters for mapping.")

    while len(hash_stream) < total_letters_needed * 2:
        hashed = hashlib.sha256(hash_input.encode()).hexdigest()
        debug(f"SHA256({hash_input}) = {hashed}")
        hash_stream += hashed
        hash_input = hashed

    letter_sequence = []
    for c in hash_stream:
        if c.isdigit():
            idx = int(c)
        else:
            idx = ord(c.lower()) - ord('a') + 10
        letter = string.ascii_lowercase[idx % 26]
        letter_sequence.append(letter)

    debug(f"Generated {len(letter_sequence)} lowercase letters for mapping.")
    return letter_sequence[:total_letters_needed]

def build_mapping(key):
    debug(f"Building encoding/decoding maps for key: {key}")
    seq = generate_key_seq(key)
    mappings = {'upper': {}, 'lower': {}, 'digit': {}, 'special': {}}
    reverse = {}
    i = 0

    for c in string.ascii_uppercase:
        chunk = ''.join(seq[i:i+3])
        mappings['upper'][c] = chunk
        reverse[chunk] = c
        debug(f"Mapped upper '{c}' -> '{chunk}'")
        i += 3

    for c in string.ascii_lowercase:
        chunk = ''.join(seq[i:i+2])
        mappings['lower'][c] = chunk
        reverse[chunk] = c
        debug(f"Mapped lower '{c}' -> '{chunk}'")
        i += 2

    for c in string.digits:
        chunk = ''.join(seq[i:i+1])
        mappings['digit'][c] = chunk
        reverse[chunk] = c
        debug(f"Mapped digit '{c}' -> '{chunk}'")
        i += 1

    for c in SPECIALS:
        chunk = ''.join(seq[i:i+4])
        mappings['special'][c] = chunk
        reverse[chunk] = c
        debug(f"Mapped special '{c}' -> '{chunk}'")
        i += 4

    debug("Finished building mappings.")
    return mappings, reverse

def encode(message, key):
    debug(f"Starting encoding for message: {message}")
    mappings, _ = build_mapping(key)
    result = ''
    for c in message:
        if c.isupper():
            enc = mappings['upper'][c]
            kind = 'upper'
        elif c.islower():
            enc = mappings['lower'][c]
            kind = 'lower'
        elif c.isdigit():
            enc = mappings['digit'][c]
            kind = 'digit'
        elif c in SPECIALS:
            enc = mappings['special'][c]
            kind = 'special'
        else:
            raise ValueError(f"Unsupported character: {repr(c)}")
        debug(f"Char '{c}' ({kind}) -> '{enc}'")
        result += enc
    debug(f"Final encoded result: {result}")
    return result

def decode(encoded, key):
    debug(f"Starting decoding for string: {encoded}")
    _, reverse = build_mapping(key)
    encoded = encoded.replace(" ", "")
    result = ''
    i = 0
    while i < len(encoded):
        for length in (4, 3, 2, 1):
            chunk = encoded[i:i+length]
            if chunk in reverse:
                original = reverse[chunk]
                debug(f"Chunk '{chunk}' -> '{original}'")
                result += original
                i += length
                break
        else:
            raise ValueError(f"Unknown sequence at position {i}: {encoded[i:i+4]}")
    debug(f"Final decoded result: {result}")
    return result

if __name__ == "__main__":
    # Setup logging before anything else
    setup_logging()

    run = True

    while run:
        try:
            input_ = input("En-/Decoding >>>    ")
            logger.info(f"User input: {input_}")  # log overall
            debug(f"Parsing input: {input_}")
            parts = input_.split()
            if not parts:
                continue

            operation = parts[0].lower()
            debug(f"Operation detected: {operation}")

            if operation == "debugging":
                if len(parts) > 1:
                    if parts[1].lower() == "true":
                        DEBUG = True
                        logger.info("Debugging enabled.\n")
                    elif parts[1].lower() == "false":
                        DEBUG = False
                        logger.info("Debugging disabled.\n")
                    else:
                        print("Use 'debugging True' or 'debugging False'\n")
                        logger.warning("Invalid debugging command.")
                else:
                    print("Usage: debugging True/False\n")
                    logger.warning("Missing argument for debugging.")

            elif operation in {"encode", "decode"}:
                if len(parts) < 3:
                    print("Usage: encode|decode [10-digit-key] [message]\n")
                    logger.warning("Not enough arguments for encode/decode.")
                    continue

                key = parts[1]
                input_msg = ' '.join(parts[2:])
                debug(f"Key received: {key}")
                debug(f"Message received: {input_msg}")

                if len(key) != 10 or not key.isdigit():
                    print("Key must be a 10-digit number.\n")
                    logger.error("Invalid key length or non-digit key.")
                    continue

                print(f"Key:      {key}\n")
                logger.info(f"Key: {key}")
                print(f"Original: {input_msg}\n")
                logger.info(f"Original: {input_msg}")

                if operation == "encode":
                    encoded = encode(input_msg, key)
                    print(f"Encoded:  {encoded}\n")
                    logger.info(f"Encoded: {encoded}")
                else:
                    decoded = decode(input_msg, key)
                    print(f"Decoded:  {decoded}\n")
                    logger.info(f"Decoded: {decoded}")

            elif operation == "help":
                help_msg = """
Usage: [operation] [10-digit-key] [message]

Operations:
  encode       Encode a message using the given key
  decode       Decode a message using the given key
  debugging    Turn debug output on/off (debugging True/False)
  help         Show this help message
  exit         Exit the program

Examples:
  encode 1234567890 Hello, world!
  decode 1234567890 jkasdlasdkfjkqw
  debugging True
"""
                print(help_msg)
                logger.info("Displayed help message.")

            elif operation == "exit":
                debug("User requested exit.")
                logger.info("Exiting program.")
                run = False

            else:
                print(f"Unknown operation '{operation}'. Use 'help' for commands.\n")
                logger.warning(f"Unknown operation: {operation}")

        except Exception as e:
            print("An error occurred:", e, "\n")
            logger.exception(f"Exception occurred: {e}")
