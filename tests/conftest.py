import pytest
from app import app, db as DB

@pytest.fixture()
def client():
    return app.test_client()

@pytest.fixture()
def db():
    return DB