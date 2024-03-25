import os

from app.const_vars import DB_TEST_PATH

def test_create_db(db):
    db_exists = os.path.exists(DB_TEST_PATH)
    if db_exists: 
        os.remove(DB_TEST_PATH)
    db.create()
    assert os.path.exists(DB_TEST_PATH)
    
def test_models():
    ...
    