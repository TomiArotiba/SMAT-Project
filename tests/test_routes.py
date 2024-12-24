def test_register(client):
    """Test user registration."""
    response = client.post('/register', data={
        'email': 'newuser@example.com',
        'password': 'securepassword'
    })
    assert response.status_code == 302  # Redirects to login

def test_login(client):
    """Test user login."""
    client.post('/register', data={
        'email': 'test@example.com',
        'password': 'testpassword'
    })
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'testpassword'
    })
    assert response.status_code == 302  # Redirects to profile

def test_profile_route_unauthorized(client):
    """Test profile route requires login."""
    response = client.get('/profile', follow_redirects=True)
    assert b"Login" in response.data
