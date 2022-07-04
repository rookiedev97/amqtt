# Copyright (c) 2015 Nicolas JOUANIN
#
# See the file license.txt for copying permission.
import logging
import os
from passlib.apps import custom_app_context as pwd_context
import requests
import json
from cryptography.fernet import Fernet


class BaseAuthPlugin:
    def __init__(self, context):
        self.context = context
        try:
            self.auth_config = self.context.config["auth"]
        except KeyError:
            self.context.logger.warning(
                "'auth' section not found in context configuration"
            )

    def authenticate(self, *args, **kwargs):
        if not self.auth_config:
            # auth config section not found
            self.context.logger.warning(
                "'auth' section not found in context configuration"
            )
            return False
        return True


class AnonymousAuthPlugin(BaseAuthPlugin):
    def __init__(self, context):
        super().__init__(context)

    async def authenticate(self, *args, **kwargs):
        authenticated = super().authenticate(*args, **kwargs)
        if authenticated:
            allow_anonymous = self.auth_config.get(
                "allow-anonymous", True
            )  # allow anonymous by default
            if allow_anonymous:
                authenticated = True
                self.context.logger.debug(
                    "Authentication success: config allows anonymous"
                )
            else:
                try:
                    session = kwargs.get("session", None)
                    authenticated = True if session.username else False
                    if self.context.logger.isEnabledFor(logging.DEBUG):
                        if authenticated:
                            self.context.logger.debug(
                                "Authentication success: session has a non empty username"
                            )
                        else:
                            self.context.logger.debug(
                                "Authentication failure: session has an empty username"
                            )
                except KeyError:
                    self.context.logger.warning("Session information not available")
                    authenticated = False
        return authenticated


class FileAuthPlugin(BaseAuthPlugin):
    def __init__(self, context):
        super().__init__(context)
        self._users = dict()
        self._read_password_file()

    def _read_password_file(self):
        password_file = self.auth_config.get("password-file", None)
        if password_file:
            try:
                with open(password_file) as f:
                    self.context.logger.debug(
                        "Reading user database from %s" % password_file
                    )
                    for line in f:
                        line = line.strip()
                        if not line.startswith("#"):  # Allow comments in files
                            (username, pwd_hash) = line.split(sep=":", maxsplit=3)
                            if username:
                                self._users[username] = pwd_hash
                                self.context.logger.debug(
                                    "user %s , hash=%s" % (username, pwd_hash)
                                )
                self.context.logger.debug(
                    "%d user(s) read from file %s" % (len(self._users), password_file)
                )
            except FileNotFoundError:
                self.context.logger.warning(
                    "Password file %s not found" % password_file
                )
        else:
            self.context.logger.debug(
                "Configuration parameter 'password_file' not found"
            )

    async def authenticate(self, *args, **kwargs):
        authenticated = super().authenticate(*args, **kwargs)
        if authenticated:
            session = kwargs.get("session", None)
            if session.username:
                hash = self._users.get(session.username, None)
                if not hash:
                    authenticated = False
                    self.context.logger.debug(
                        "No hash found for user '%s'" % session.username
                    )
                else:
                    authenticated = pwd_context.verify(session.password, hash)
            else:
                return None
        return authenticated


class DBAuthPlugin(BaseAuthPlugin):
    def __init__(self, context):
        super().__init__(context)

        # test_password is must be hashed
        # format for dictionary
        # {"fake name":"password hash"}
        test_name = os.environ.get("Test_USER")
        test_password = os.environ.get("Test_PW")
        temp_dict = {}
        temp_dict[test_name] = test_password
        self._users = temp_dict
        
    async def authenticate(self, *args, **kwargs):
        authenticated = super().authenticate(*args, **kwargs)
        if authenticated:
            session = kwargs.get("session", None)
            if session.username:
                print(session.username)
                print(self._users)
                hash = self._users.get(session.username, None)
                if not hash:
                    authenticated = False
                    self.context.logger.debug(
                        "No hash found for user '%s'" % session.username
                    )
                else:
                    authenticated = pwd_context.verify(session.password, hash)
            else:
                return None
        return authenticated



class BackendAuthPlugin(BaseAuthPlugin):
    def __init__(self, context):
        super().__init__(context)
        
    async def authenticate(self, *args, **kwargs):
        authenticated = super().authenticate(*args, **kwargs)
        if authenticated:
            session = kwargs.get("session", None)
            if session.username:
                random_string = str(os.environ.get('BROKER_ENCRYPT_KEY'))
                key = random_string.encode('UTF-8')
                fernet = Fernet(key)
                if session.username == None: 
                    session.username = "No user"
                if session.password == None:
                    session.password = "No password"

                encrypted_name = fernet.encrypt(session.username.encode())
                encrypted_pwd = fernet.encrypt(session.password.encode())
                temp_dict = {}
                temp_dict["username"] = encrypted_name
                temp_dict["password"] = encrypted_pwd
                response = requests.post(os.environ.get("Backend_Api_Endpoint"), data = temp_dict)
                if response.json()==True:
                    authenticated = True
                else:
                    authenticated = False
            else:
                return None
        return authenticated