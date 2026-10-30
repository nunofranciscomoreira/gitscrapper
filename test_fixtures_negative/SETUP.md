# Setup

Copy `.env.sample` to `.env` and fill in your own credentials:

```sh
export API_TOKEN=<your-api-token>
export DB_PASSWORD=<database password>
export CLIENT_SECRET="{{CLIENT_SECRET}}"
```

```yaml
auth:
  api_key: "<API_KEY>"
  password: "********"
  token: "${API_TOKEN}"
```

Send `Authorization: Bearer <access_token>` with every request.
