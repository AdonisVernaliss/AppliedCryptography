import asyncio
from pywebio import start_server
from pywebio.input import *
from pywebio.output import *
from pywebio.session import run_async, run_js

# Global variables
chat_msgs = []
online_users = set()
MAX_MESSAGES_COUNT = 150

# RSA parameters


p = 281
q = 311

# RSA Modulus
n = p * q

# Eulers Toitent -> f(n) = f(p) * f(q) -> if n is prime -> (p-1)(q-1)
r = (p - 1) * (q - 1)
e = 65537


# d * e mod f(n) = 1 -> d? :
def find_closed_exponent(e, r):
    d, d1 = 0, 1
    r1 = r
    while e != 0:
        q = r // e
        r, e = e, r % e
        d, d1 = d1, d - q * d1
    if r != 1:
        raise ValueError("e and r are not coprime")
    if d < 0:
        d = d + r1
    return d


d = find_closed_exponent(e, r)


# Encryption and Decryption functions
def encrypt(pub_key, text):
    e, n = pub_key
    return [(ord(char) ** e) % n for char in text]


def decrypt(priv_key, cipher_text):
    d, n = priv_key
    decrypted_chars = [chr((char ** d) % n) for char in cipher_text]
    return ''.join(decrypted_chars)


# Main chat function
async def main():
    global chat_msgs
    global online_users

    # Output box for messages
    msg_box = output()
    put_scrollable(msg_box, height=300, keep_bottom=True)

    # User joins
    nickname = await input(required=True, placeholder="Your name:",
                           validate=lambda
                               n: "Nickname's already in use." if n in online_users or n == '[INFO]' else None)
    online_users.add(nickname)
    chat_msgs.append(('[INFO]', f'`{nickname}` joined.'))
    msg_box.append(put_markdown(f'[INFO] `{nickname}` join the chat'))

    # Asynchronous task to refresh messages
    refresh_task = run_async(refresh_msg(nickname, msg_box))

    # Chat loop
    while True:
        data = await input_group("| Internet Relay Chat |", [
            input(placeholder="...", name="msg"),
            file_upload("Select file", name="file"),
            actions(name="cmd", buttons=["Send", {'label': "Log out", 'type': 'cancel'}])
        ], validate=lambda m: ('msg', "Enter the message") if m["cmd"] == "Send" and not m['msg'] and not m[
            'file'] else None)

        # If user logs out or closes the dialog
        if data is None or data['cmd'] == "Log out":
            break

        # Encrypt and send message
        message = data['msg']
        if 'file' in data and data['file']:
            file_content = data['file']['content'].decode('latin-1')
            encrypted_file_content = encrypt((e, n), file_content)
            msg_box.append(put_markdown(f"`{nickname}` (Encrypted file): {encrypted_file_content} \n{file_content}\n "
                                        f"[file: {data['file']['filename']} ({len(data['file']['content'])} bytes)]"))
            chat_msgs.append((nickname, encrypted_file_content))

        if message:
            encrypted_msg = encrypt((e, n), message)
            msg_box.append(put_markdown(f"`{nickname}` (Encrypted): {encrypted_msg} ({message})"))
            chat_msgs.append((nickname, encrypted_msg))

    refresh_task.close()
    online_users.remove(nickname)
    toast("You have logged out of the chat.")
    msg_box.append(put_markdown(f'[INFO] User `{nickname}` left the chat.'))
    chat_msgs.append(('[INFO]', f'User `{nickname}` left the chat.'))

    put_buttons(['Re-visit'], onclick=lambda btn: run_js('window.location.reload()'))


async def refresh_msg(nickname, msg_box):
    global chat_msgs
    last_idx = len(chat_msgs)

    while True:
        await asyncio.sleep(1)

        for m in chat_msgs[last_idx:]:
            if m[0] != nickname:
                try:
                    decrypted_msg = decrypt((d, n), m[1])
                    msg_box.append(put_markdown(f"`{m[0]}` (Decrypted): {decrypted_msg}"))
                except TypeError:
                    if not m[1].startswith("[INFO]"):
                        msg_box.append(put_markdown(f"`{m[0]}`: {m[1]}"))

        if len(chat_msgs) > MAX_MESSAGES_COUNT:
            chat_msgs = chat_msgs[len(chat_msgs) // 2:]

        last_idx = len(chat_msgs)


if __name__ == "__main__":
    start_server(main, debug=True, port=8080, cdn=False)
