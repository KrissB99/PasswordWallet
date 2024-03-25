from functools import wraps
from flask import session, redirect, url_for

def check_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        
        if 'login' not in session:
           return redirect(url_for("login"))
       
        return func(*args, **kwargs)
    
    return wrapper