class MiniTwitTestCase(unittest.TestCase):
    def test_login_logout(self):
        rv = self.login('user1', 'default')
        assert b'You were logged in' in rv.data
        rv = self.login('user1', 'wrongpassword')
        assert b'Invalid password' in rv.data
