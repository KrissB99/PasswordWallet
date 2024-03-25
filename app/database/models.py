import hashlib
import os
import bcrypt
from flask import session
from app import db
from sqlalchemy.orm import relationship
from sqlalchemy import BLOB, Column, Integer, String, ForeignKey, Boolean

from app.const_vars import PEPPER

class DBManager:
    """Class for CRUD"""
    
    session = db.session
    
    @classmethod
    def get_all(cls) -> list[db.Model]:
        return cls.query.all()
    
    @classmethod
    def get_by_id(cls, id: int) -> db.Model:
        return cls.query.filter(cls.id == id).first()
    
    @classmethod
    def add_all(cls, db_objects: list[db.Model]) -> None:
        db.session.add_all(db_objects)
        db.session.commit()
    
    def update_db(self, attr: dict) -> None:
        for name, value in attr.items():
            setattr(self, name, value)
        db.session.commit()
        
    def add(self) -> db.Model:
        db.session.add(self)
        db.session.commit()
        return self
        
    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()
        

class User(db.Model, DBManager):
    
    __tablename__ = 'users'
    __allow_unmapped__ = True
    id = Column(Integer, primary_key=True)
    login = Column(String(30))
    password_hash= Column(String(512), nullable=False)
    salt = Column(String(20), nullable=False)
    is_password_kept_as_hash = Column(Boolean)
    
    passwords: object = relationship('Password', back_populates='user')
    
    @classmethod
    def create_user(cls, data: dict) -> None:
        """Add new user to db

        Args:
            email (str): Given email address
            password (str): Given password
        """
        if data['is_password_kept_as_hash']: hashed_password, salt = cls._hash_password_BRYPT(data['password_hash'])
        else: hashed_password, salt = cls._hash_password_HMAC(data['password_hash'])
        user = User(login = data['login'], password_hash = hashed_password, salt = salt, 
                   is_password_kept_as_hash = data['is_password_kept_as_hash'])
        new_user = user.add()
        return new_user.to_dict()
        
    @classmethod           
    def _hash_password_BRYPT(cls, password: str) -> list:
        """Secures the password

        Args:
            password (str): Given password from the user

        Returns:
            str: Hashed password
            str: salt
        """
        salt = bcrypt.gensalt()
        password += PEPPER
        return bcrypt.hashpw(password.encode('utf-8'), salt), salt
    
    @classmethod
    def check_password(cls, login: int, password: str) -> bool:
        """Check if given password is valid with hashed from db

        Args:
            login (int): Users login
            password (str): Password given by user

        Returns:
            bool: True if passwords mach, False if not
        """
        user = User.query.filter(User.login == login).first()
        if user.is_password_kept_as_hash: 
            password += PEPPER
            new_hashed_password = bcrypt.hashpw(password.encode('utf-8'), user.salt)
            return new_hashed_password == user.password_hash, user
        else: 
            hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user.salt, 100000, dklen=128)
            return hashed_password == user.password_hash, user
        
    @classmethod           
    def _hash_password_HMAC(cls, password: str) -> list:
        """Secures the password

        Args:
            password (str): Password given by user to check if matches

        Returns:
            list(): Hashed password and salt
        """
        salt = os.urandom(32)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=128)
        return hashed_password, salt
    
    @classmethod
    def check_login(cls, login: str) -> bool:
        """Checking if the login exists

        Args:
            login (str): _description_

        Returns:
            bool: _description_
        """
        if login in [user.login for user in cls.get_all()]:
            return True
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'login': self.login,
            'password_hash': self.password_hash.decode('utf-8'), 
            'salt': self.salt.decode('utf-8'),
            'is_password_kept_as_hash': self.is_password_kept_as_hash
        }
    
    def __repr__(self):
        return f"User(id: {self.id}, login: {self.login}, password_hash: {self.password_hash}, \
                      salt: {self.salt}, is_password_kept_as_hash: {self.is_password_kept_as_hash})"
    
    
class Password(db.Model, DBManager):
    
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True)
    password  = Column(BLOB)
    web_address = Column(String(256))
    description = Column(String(256))
    login = Column(String(30))
    
    id_user: int = Column(Integer, ForeignKey("users.id"))
    
    user = relationship('User', back_populates='passwords')
    
    @classmethod
    def create_password(cls, data: dict) -> object:
        """Adding new password into the db

        Args:
            data (dict): parameters from form

        Returns:
            object: new db object
        """
        data['password'] = cls.encode(data['password'])
        password = cls(**data, id_user=session['id']).add()
        return password.to_dict()
    
    @classmethod
    def encode(cls, password:str) -> str:
        """Encode password before putting it to the db

        Args:
            password (str): given password

        Returns:
            str: encoded password
        """
        return password.encode('utf_16','strict')
    
    @classmethod
    def decode(cls, password_encoded:str) -> str:
        """Decode password from db

        Args:
            password_encoded (str): Encoded password from db

        Returns:
            str: Decoded password
        """
        return password_encoded.decode('utf_16', 'strict')
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'web_address': self.web_address,
            'login': self.login,
            'description': self.description,
            'id_user': self.id_user,
            'password': Password.decode(self.password)
        }
    
    def __repr__(self):
        return f"Password(id: {self.id}, password: {self.password}, login: {self.login},\
                    web_address: {self.web_address}, description: {self.description})"
