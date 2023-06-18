import os
import threading
import time
import random
import ctypes
import cfscrape
import asyncio
import websocket
import base64
import colorama
import hashlib
import sys
from datetime import datetime
from rgbprint import gradient_print, Color
from ctypes import wintypes
import os

import json as jsond  # json
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import platform  # check platform
import subprocess  # needed for mac device


try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("py -m pip install -r requirements.txt")
    else:
        os.system("py -m pip install pywin32")
        os.system("py -m pip install pycryptodome")
        os.system("py -m pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)

try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(5)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("init".encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print(
                    "Invalid Version, Contact owner to add download link to latest app version")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("register".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("upgrade".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully upgraded user")
            print("please restart program and login")
            time.sleep(2)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("login".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged in")
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("license".encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            return True
        else:
            return False
            time.sleep(5)
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("var".encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("getvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(
                f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables")
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("setvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("ban".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("file".encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body="", conttype=""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("webhook".encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            time.sleep(5)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("check".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("checkblacklist".encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("log".encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("fetchOnline".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
                return None
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatget".encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatsend".encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(2)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("changeUsername".encode()),
            "newUsername": username,
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully Changed Username")
        else:
            print(json["message"])
            os._exit(1)

    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            # You can also use WMIC (better than SID, some users had problems with WMIC)
            sid = win32security.LookupAccountName(None, winuser)[0]
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen(
                "ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            time.sleep(5)
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            time.sleep(5)
            os._exit(1)


def pause():
    os.system("pause >nul")


def clear():
    os.system("cls")


def getChecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


class Console:

    def blockInput(block: bool) -> bool:
        INPUT_MOUSE = 0
        INPUT_KEYBOARD = 1
        INPUT_HARDWARE = 2
        KEYEVENTF_EXTENDEDKEY = 0x0001
        KEYEVENTF_KEYUP = 0x0002
        KEYEVENTF_SCANCODE = 0x0008

        # Define necessary structures
        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", ctypes.c_long),
                        ("dy", ctypes.c_long),
                        ("mouseData", ctypes.c_ulong),
                        ("dwFlags", ctypes.c_ulong),
                        ("time", ctypes.c_ulong),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", ctypes.c_ushort),
                        ("wScan", ctypes.c_ushort),
                        ("dwFlags", ctypes.c_ulong),
                        ("time", ctypes.c_ulong),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class HARDWAREINPUT(ctypes.Structure):
            _fields_ = [("uMsg", ctypes.c_ulong),
                        ("wParamL", ctypes.c_short),
                        ("wParamH", ctypes.c_ushort)]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("mi", MOUSEINPUT),
                            ("ki", KEYBDINPUT),
                            ("hi", HARDWAREINPUT)]
            _anonymous_ = ["_input"]
            _fields_ = [("type", ctypes.c_ulong),
                        ("_input", _INPUT)]

        # Define necessary functions
        SendInput = ctypes.windll.user32.SendInput
        BlockInput = ctypes.windll.user32.BlockInput

        # Define necessary variables
        MOUSEEVENTF_MOVE = 0x0001
        MOUSEEVENTF_LEFTDOWN = 0x0002
        MOUSEEVENTF_LEFTUP = 0x0004
        MOUSEEVENTF_RIGHTDOWN = 0x0008
        MOUSEEVENTF_RIGHTUP = 0x0010
        MOUSEEVENTF_MIDDLEDOWN = 0x0020
        MOUSEEVENTF_MIDDLEUP = 0x0040
        MOUSEEVENTF_ABSOLUTE = 0x8000
        KEYEVENTF_UNICODE = 0x0004
        BlockInput(block)

    def beep(frequency, duration):
        Beep = ctypes.windll.kernel32.Beep
        Beep(int(frequency), int(duration))

    def setupNiceConsole():
        clear()
        os.system("mode 140,40")
        GWL_STYLE = -16
        WS_MAXIMIZEBOX = 0x10000
        WS_MINIMIZEBOX = 0x20000
        console_window_handle = ctypes.windll.kernel32.GetConsoleWindow()
        style = ctypes.windll.user32.GetWindowLongPtrW(
            console_window_handle, GWL_STYLE)
        style &= ~(WS_MAXIMIZEBOX | WS_MINIMIZEBOX)
        ctypes.windll.user32.SetWindowLongPtrW(
            console_window_handle, GWL_STYLE, style)
        console_handle = ctypes.windll.kernel32.GetConsoleWindow()
        scrollbar_handle = ctypes.windll.user32.GetDlgItem(console_handle, 0)
        ctypes.windll.user32.EnableScrollBar(console_handle, 0, 3)
        ENABLE_QUICK_EDIT = 0x0040
        STD_INPUT_HANDLE = -10
        GetStdHandle = ctypes.windll.kernel32.GetStdHandle
        GetConsoleMode = ctypes.windll.kernel32.GetConsoleMode
        SetConsoleMode = ctypes.windll.kernel32.SetConsoleMode
        console_handle = GetStdHandle(STD_INPUT_HANDLE)
        console_mode = ctypes.c_uint()
        if not GetConsoleMode(console_handle, ctypes.byref(console_mode)):
            pass
        console_mode.value &= ~ENABLE_QUICK_EDIT
        if not SetConsoleMode(console_handle, console_mode):
            pass
        os.system("title RAMBLETRICK AutoJoiner, by Tesco.")

    def removeResize():
        GWL_STYLE = -16
        WS_THICKFRAME = 0x00040000
        WS_MAXIMIZEBOX = 0x00010000
        WS_MINIMIZEBOX = 0x00020000
        console_handle = ctypes.windll.kernel32.GetConsoleWindow()
        style = ctypes.windll.user32.GetWindowLongW(console_handle, GWL_STYLE)
        style = style & ~WS_THICKFRAME
        style = style & ~WS_MAXIMIZEBOX
        style = style & ~WS_MINIMIZEBOX
        ctypes.windll.user32.SetWindowLongW(console_handle, GWL_STYLE, style)

    def visibleConsole(setting):
        if setting == True:
            GWL_STYLE = -16
            WS_CAPTION = 0xC00000
            WS_SYSMENU = 0x80000
            console_handle = ctypes.windll.kernel32.GetConsoleWindow()
            style = ctypes.windll.user32.GetWindowLongW(
                console_handle, GWL_STYLE)
            style = style | WS_CAPTION | WS_SYSMENU
            ctypes.windll.user32.SetWindowLongW(
                console_handle, GWL_STYLE, style)
        else:
            SWP_NOMOVE = 0x0002
            console_handle = ctypes.windll.kernel32.GetConsoleWindow()
            ctypes.windll.user32.SetWindowPos(
                console_handle, 0, 0, 0, 0, 0, SWP_NOMOVE)


class RBLXWild:
    def checkAuthToken(authToken):
        checkRequest = cfscrape.create_scraper().post("https://rblxwild.com/api/trading/cc/info",
                                                      headers={"content-type": "application/json", "authorization": authToken}, json={})
        if checkRequest.status_code != 200:
            return False
        else:
            try:
                if checkRequest.json()["message"] == "You have been banned!":
                    return False
                elif checkRequest.json()["message"] == "You need to log in to do this!":
                    return False
            except:
                return True
            return True


class WILDSocket:

    battles = []

    teamId4way = None
    teamId3way = None
    teamId2way = None
    teamId2v2 = None
    seatIndex = "0"
    seatIndex2v2 = "0"

    def generateNewSlots():
        WILDSocket.teamId4way = random.choice(["2","3","4"])
        WILDSocket.teamId3way = random.choice(["2","3"])
        WILDSocket.teamId2way = "2"
        WILDSocket.teamId2v2 = random.choice(["1","2"])
        if WILDSocket.teamId2v2 == "1":
            WILDSocket.seatIndex2v2="2"
        else:
            WILDSocket.seatIndex2v2 = random.choice(["1", "2"])
        WILDSocket.seatIndex="0"

    def startNewRetardHeartbeat(wildSocket):
        while True:
            try:
                wildSocket.send(f'42["time:requestSync",{{"clientTime":{time.time()}}}]')
                time.sleep(1)
            except:
                try:
                    wildSocket.close()
                except:
                    pass
                break

    def sendPayload(wildSocket, payload):
        wildSocket.send(payload)

    async def start(authToken, safeSettingsEnabled, safeSettings, minimumPercent):
        randomBytes = os.urandom(16)
        wsKey = base64.b64encode(randomBytes).decode('utf-8')
        wildHeaders = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "Upgrade",
            "Host": "rblxwild.com",
            "Origin": "https://rblxwild.com",
            "Pragma": "no-cache",
            "Sec-GPC": "1",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "Sec-WebSocket-Key": wsKey,
            "Sec-WebSocket-Version": "13",
            "Upgrade": "websocket",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
        }
        wildSocket = websocket.WebSocket()
        wildSocket.connect('wss://rblxwild.com/socket.io/?EIO=4&transport=websocket', header=wildHeaders)
        wildSocket.recv()
        wildSocket.send("40")
        wildSocket.recv()
        wildSocket.send(f'42["authentication",{{"authToken":"{authToken}","clientTime":{time.time()}}}]')
        string_data = (wildSocket.recv()).replace('42["authenticationResponse",', '')[:-1]
        try:
            userData = jsond.loads(string_data)["userData"]
        except:
            print()
            gradient_print('    [!] An irregularity has been detected:',
                           start_color=Color.red, end_color=Color.dark_red)
            gradient_print('    [!] You seem to be ratelimited, or there is a problem with RBLXWILD',
                           start_color=Color.red, end_color=Color.dark_red)
            gradient_print('    [!] Try using a VPN or come back in ~5 minutes.',
                           start_color=Color.red, end_color=Color.dark_red)
            return
        threading._start_new_thread(WILDSocket.startNewRetardHeartbeat, (wildSocket,))
        userBalance = str(userData["balance"])
        wildSocket.send('42["casebattles:subscribe"]')
        # wildSocket.send('42["chat:subscribe",{"channel":"EN"}]')
        print()
        gradient_print("    [+] Display Name: " + userData["displayName"],
                       start_color=Color.light_green, end_color=Color.dark_green)
        gradient_print("    [+] Balance: " + str(userBalance),
                       start_color=Color.light_green, end_color=Color.dark_green)
        gradient_print("    [+] Status: " + "Ready to join battles!",
                       start_color=Color.light_green, end_color=Color.dark_green)
        print()
        gradient_print("    [+] Tip: " + "Close all other instances of RBLXWild (tabs, other AJs)!",
                       start_color=Color.light_green, end_color=Color.dark_green)
        gradient_print("    [+] Tip: " + "Use Ethernet over WI-FI!",
                       start_color=Color.light_green, end_color=Color.dark_green)
        WILDSocket.generateNewSlots()
        while True:
            try:
                socketEvent = wildSocket.recv()
                if "casebattles:pushGame" in str(socketEvent):
                    battleData = None
                    try:
                        battleData = jsond.loads(socketEvent.split(
                            '42["casebattles:pushGame",')[1][:-1])
                    except Exception as e:
                        gradient_print('    [!] An irregularity has been detected:',
                                       start_color=Color.red, end_color=Color.dark_red)
                        gradient_print(
                            f'    [!] {str(e)}', start_color=Color.red, end_color=Color.dark_red)
                    if battleData["funding"] >= minimumPercent:
                        versusType = battleData["versusType"]
                        teamIde=None
                        seatIndexe=None
                        if versusType == "1v1v1v1":
                            teamIde = WILDSocket.teamId4way
                            seatIndexe = WILDSocket.seatIndex
                        elif versusType == "1v1v1":
                            teamIde = WILDSocket.teamId3way
                            seatIndexe = WILDSocket.seatIndex
                        elif versusType == "1v1":
                            teamIde = WILDSocket.teamId2way
                            seatIndexe = WILDSocket.seatIndex
                        elif versusType == "2v2":
                            teamIde = WILDSocket.teamId2v2
                            seatIndexe = WILDSocket.seatIndex2v2
                        wildSocket.send('42["casebattles:join",{"gameId":' + str(
                            battleData["id"]) + ',"teamId":' + teamIde + ',"seatIndex":' + seatIndexe + '}]')
                        cases = []
                        caseNames = []
                        for i in battleData["caseEntries"]:
                            cases.append(
                                {"name": i["name"], "amount": i["quantity"], "price": i["price"]})
                            caseNames.append(
                                i["name"] + ":" + str(i["quantity"]))
                        with open("battles.json", "r") as f:
                            battlese = jsond.load(f)
                            f.close()
                        battlese.append({"cases": cases, "price": battleData["betAmount"], "id": battleData[
                                        "id"], "urlId": battleData["urlId"], "battleOwner": battleData["owner"]["displayName"]})
                        with open('battles.json', 'w') as f:
                            jsond.dump(battlese, f, indent=4)
                            f.close()
                        print()
                        gradient_print(f"    [+] Found {battleData['funding']}% off battle! Value: " + str(
                            battleData["betAmount"]), start_color=Color.green, end_color=Color.dark_green)
                        gradient_print(f"    [+] Cases: " + ", ".join(caseNames),
                                       start_color=Color.green, end_color=Color.dark_green)
                        WILDSocket.generateNewSlots()
                elif str(socketEvent) == "2":
                    wildSocket.send("3")
                elif "casebattles:setSlot" in str(socketEvent):
                    if userData["displayName"] in str(socketEvent):
                        print()
                        gradient_print(f"    [+] Joined battle! (probably the one above)",
                                       start_color=Color.lime_green, end_color=Color.dark_green)
                elif "user:updateBalance" in str(socketEvent):
                    balanceData = jsond.loads(socketEvent.split(
                        '42["user:updateBalance",')[1][:-1])
                    if str(userBalance) == str(balanceData["value"]):
                        pass
                    else:
                        userBalance = str(balanceData["value"])
                        print()
                        gradient_print(f"    [+] Balance Update! Current Balance: " + str(
                            balanceData["value"]), start_color=Color.light_cyan, end_color=Color.dark_cyan)
            except Exception as e:
                if "closed" in str(e).lower():
                    print()
                    gradient_print('    [!] An irregularity has been detected:',
                               start_color=Color.red, end_color=Color.dark_red)
                    try:
                        wildSocket.close()
                    except:
                        pass
                    await WILDSocket.start(authToken, safeSettingsEnabled, safeSettings, minimumPercent)
                    return
                else:
                    print()
                    gradient_print('    [!] An irregularity has been detected:',
                                   start_color=Color.red, end_color=Color.dark_red)
                    gradient_print(
                        f'    [!] {str(e)}', start_color=Color.red, end_color=Color.dark_red)
                    pass
                pass


async def mainStart():
    Console.visibleConsole(False)
    Console.removeResize()
    Console.beep(640, 700)
    Console.setupNiceConsole()
    appVersion = ""
    keyauthapp = api(
        name="",
        ownerid="",
        secret="",
        version=appVersion,
        hash_to_check=getChecksum()
    )
    Console.visibleConsole(True)
    Console.blockInput(False)
    Console.beep(440, 700)
    
    with open("configuration.json", "r") as f:
        joinerConfig = jsond.loads(f.read())
    print()
    if joinerConfig["license"] != "":
        gradient_print("    [+] Trying license saved in configuration...",
                       start_color=Color.light_cyan, end_color=Color.dark_green)
        auth = keyauthapp.license(joinerConfig["license"])
        if auth == False:
            gradient_print("    [+] License key is not valid, banned, or expired!",
                           start_color=Color.light_cyan, end_color=Color.dark_cyan)
            joinerConfig["license"] = ""
            with open('configuration.json', 'w') as f:
                jsond.dump(joinerConfig, f, indent=4)
                f.close()
            key = input(colorama.Fore.CYAN + "    [+] License key: ")
            auth = keyauthapp.license(key)
            if auth == False:
                gradient_print("    [+] License key is not valid, banned, or expired!",
                               start_color=Color.light_cyan, end_color=Color.dark_cyan)
                pause()
                return
            elif auth == True:
                gradient_print(
                    "    [+] Authenticated!", start_color=Color.light_cyan, end_color=Color.dark_green)
                joinerConfig["license"] = key
                with open('configuration.json', 'w') as f:
                    jsond.dump(joinerConfig, f, indent=4)
                    f.close()
                clear()
        elif auth == True:
            gradient_print(
                "    [+] Authenticated!", start_color=Color.light_cyan, end_color=Color.dark_green)
            clear()
    else:
        key = input(colorama.Fore.CYAN + "    [+] License key: ")
        auth = keyauthapp.license(key)
        if auth == False:
            gradient_print("    [+] License key is not valid, banned, or expired!",
                           start_color=Color.light_cyan, end_color=Color.dark_cyan)
            pause()
            return
        elif auth == True:
            gradient_print(
                "    [+] Authenticated!", start_color=Color.light_cyan, end_color=Color.dark_green)
            joinerConfig["license"] = key
            with open('configuration.json', 'w') as f:
                jsond.dump(joinerConfig, f, indent=4)
                f.close()
            clear()
    # Config
    authToken = joinerConfig["authToken"]
    safeSettingsEnabled = joinerConfig["safeSettingsEnabled"]
    minimumPercent = joinerConfig["minimumPercent"]
    safeSettings = {
        "minimumPrice": joinerConfig["safeSettings"]["minimumPrice"],
        "maximumPrice": joinerConfig["safeSettings"]["maximumPrice"],
        "missBattles": joinerConfig["safeSettings"]["missBattles"],
        "missEvery": {
            "miss": joinerConfig["safeSettings"]["missEvery"]["miss"],
            "every": joinerConfig["safeSettings"]["missEvery"]["every"]
        }
    }
    piracyCheck = joinerConfig["whosTheBest?"]
    with open('battles.json') as f:
        battles = jsond.load(f)
        f.close()
    print()
    gradient_print("""                         ██████╗  █████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗██████╗ ██╗ ██████╗██╗  ██╗""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                         ██╔══██╗██╔══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██║ ██╔╝""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                         ██████╔╝███████║██╔████╔██║██████╔╝██║     █████╗     ██║   ██████╔╝██║██║     █████╔╝  (V"""+str(appVersion)+""")""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                         ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██╗██║     ██╔══╝     ██║   ██╔══██╗██║██║     ██╔═██╗ """,
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                         ██║  ██║██║  ██║██║ ╚═╝ ██║██████╔╝███████╗███████╗   ██║   ██║  ██║██║╚██████╗██║  ██╗""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                         ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                                                     - by Tesco / rambletrick""",
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                                                   - Battles Joined (local): """ +
                   str(len(battles)) + """""", start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("""                                                   - Users using AJ (global): """ +
                   str(len(keyauthapp.fetchOnline())) + """""", start_color=Color.orange, end_color=Color.dark_red)
    print()
    subs = keyauthapp.user_data.subscriptions
    for i in range(len(subs)):
        sub = subs[i]["subscription"]
        if sub == "aj":
            sub = "RBLXWild Battle AutoJoiner"
        expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
            '%Y-%m-%d %H:%M:%S')

    gradient_print("    [+] Subscription: " + sub,
                   start_color=Color.orange, end_color=Color.dark_red)
    gradient_print("    [+] Expiry: " + str(expiry),
                   start_color=Color.orange, end_color=Color.dark_red)
    print()
    if piracyCheck != "Tesco":
        gradient_print('    [!] An irregularity has been detected:',
                       start_color=Color.red, end_color=Color.dark_red)
        gradient_print('    [!] "' + piracyCheck + """" ain't the best, Tesco is! Fix it in configuration.json""",
                       start_color=Color.red, end_color=Color.dark_red)
        pause()
        return
    if RBLXWild.checkAuthToken(authToken):
        gradient_print("    [+] Authorization: " + authToken[:-100]+"... = SUCCESS",
                       start_color=Color.light_green, end_color=Color.dark_green)
        if safeSettingsEnabled:
            gradient_print(
                f"    [+] Safe Settings are enabled (DISFUNCTIONAL ATM): {str(safeSettingsEnabled)}", start_color=Color.orange, end_color=Color.dark_red)
            gradient_print(
                f"    [+] Minimum battle price (DISFUNCTIONAL ATM): {str(safeSettings['missEvery']['miss'])}", start_color=Color.orange, end_color=Color.dark_red)
            gradient_print(
                f"    [+] Maximum battle price (DISFUNCTIONAL ATM): {str(safeSettings['missEvery']['miss'])}", start_color=Color.orange, end_color=Color.dark_red)
            gradient_print(
                f"    [+] Should it miss battles? (DISFUNCTIONAL ATM): {str(safeSettings['missEvery']['miss'])}", start_color=Color.orange, end_color=Color.dark_red)
            gradient_print(f"    [+] It should miss {str(safeSettings['missEvery']['miss'])} battle(s) every {str(safeSettings['missEvery']['every'])} battle(s) (DISFUNCTIONAL ATM)",
                           start_color=Color.orange, end_color=Color.dark_red)
        else:
            gradient_print(
                f"    [+] Minimum discount: {str(minimumPercent)}", start_color=Color.orange, end_color=Color.dark_red)
            gradient_print(
                f"    [+] Safe Settings are enabled (DISFUNCTIONAL ATM): {str(safeSettingsEnabled)}", start_color=Color.orange, end_color=Color.dark_red)
        threading._start_new_thread(asyncio.run, (
            WILDSocket.start(authToken, safeSettingsEnabled, safeSettings, minimumPercent),))
        while True:
            pass
        pass
    else:
        gradient_print("    [+] Authorization: " + authToken[:-100]+"... = FAILURE",
                       start_color=Color.red, end_color=Color.dark_red)
        print()
        gradient_print('    [!] An irregularity has been detected:',
                       start_color=Color.red, end_color=Color.dark_red)
        gradient_print('    [!] The authToken you provided is invalid or banned, replace it in configuration.json',
                       start_color=Color.red, end_color=Color.dark_red)
    pause()

Console.blockInput(True)
Console.visibleConsole(False)

if __name__ == "__main__":
    asyncio.run(mainStart())
