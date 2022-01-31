#!/usr/bin/env python3
import random, sys

STATE_OPEN = "<"
STATE_CLOSE = ">"
STATE_CLOSETAG = "/>"
STATE_EQUALS = " = "
STATE_PAYLOADTAG = "x"
STATE_PAYLOADBODY = "y"
STATE_TAGSPACE = "STATE_TAGSPACE"
STATE_BODYSPACE = "STATE_BODYSPACE"
STATE_CRLF = "\n"

transitions = {
	STATE_OPEN : { STATE_PAYLOADTAG: 1 },
	STATE_CLOSE : { STATE_PAYLOADBODY: 1 },
	STATE_CLOSETAG : { STATE_OPEN: 1 },
	STATE_EQUALS : { STATE_PAYLOADTAG: 1 },
	STATE_PAYLOADTAG : {STATE_PAYLOADTAG: 0.5, STATE_CLOSETAG: 0.15, STATE_CLOSE: 0.15, STATE_TAGSPACE: 0.1, STATE_EQUALS: 0.1},
	STATE_PAYLOADBODY : {STATE_PAYLOADBODY: 0.775, STATE_BODYSPACE: 0.1, STATE_CRLF: 0.025, STATE_OPEN: 0.1},
	STATE_TAGSPACE : { STATE_PAYLOADTAG: 1 },
	STATE_BODYSPACE : { STATE_PAYLOADBODY: 1 },
	STATE_CRLF : { STATE_PAYLOADBODY: 1 }
}

import base64
if len(sys.argv) != 2:
	print("usage: encoder.py <binary file>")
with open(sys.argv[1], "rb") as f:
	to_encode = base64.urlsafe_b64encode(f.read())

out = ""

current_state = STATE_OPEN
encoded_chars = 0
out += "<html>\n"
while encoded_chars < len(to_encode):
	if current_state in [STATE_BODYSPACE, STATE_TAGSPACE]:
		out += " "
	elif current_state in [STATE_PAYLOADTAG, STATE_PAYLOADBODY]:
		out += chr(to_encode[encoded_chars])
		encoded_chars += 1
	else:
		out += current_state
	current_state = random.choices(list(transitions[current_state].keys()), list(transitions[current_state].values()))[0]
out += "\n</html>"

with open(sys.argv[1]+".html", "w") as f:
	f.write(out)