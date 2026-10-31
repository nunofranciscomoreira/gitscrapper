it('does not use a polluted prototype for proxy auth', async () => {
  const proxy = {
    host: '127.0.0.1',
    auth: {
      username: 'polluted-user',
      password: 'polluted-pass'
    }
  };
  await axios.get('http://localhost:4444/', { proxy });
});
