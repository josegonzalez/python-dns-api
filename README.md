# dns-api

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/josegonzalez/python-dns-api)

A simple service for managing a dnsimple account.

## Requirements

- Python 2.7

## Usage


### Authentication

Other than the base `/` endpoint, all endpoints are managed via JWT Token Authentication.

To create JWT tokens for configured users, run the following:

```shell
python token-generator
```

For users who have deployed to Heroku, run the following instead:

```shell
# replace 'APP_NAME' with your heroku application's name
heroku --app APP_NAME run python token-generator
```

You can then use the resulting json-web-token to make requests to the api:

```shell
# replace JWT_TOKEN with your generated token
curl -X POST -H "Authorization: Bearer JWT_TOKEN" http://localhost:8000/whoami
```

Tokens do not expire, and are stable across installations so long as the `SECRET_KEY` environment variable is the same. To expire all tokens, simply change the `SECRET_KEY` to a new value.

### Endpoints

Other than the `Authorization` header, `dns-api` endpoints only depend on the `HTTP Method` and the path to make changes. This is to simplify cli usage.

> You may also _optionally_ use the endpoints that require posting json data for creating or updating records.

All examples use the following base url: `http://localhost:8000`

#### `GET /`

Returns an endpoint that can be used for making HTTP-based healthchecks.

```shell
curl \
  -X GET \
  http://localhost:8000/
```

#### `GET /whoami`

- headers:
  - `Authorization`: Required

Returns the currently authenticated user.

```shell
curl \
  -X GET \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/whoami
```

#### `GET /domains`

- headers:
  - `Authorization`: Required

Returns a list of domains that can be managed, as well as blacklisted subdomains.

```shell
curl \
  -X GET \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/domains
```

#### `GET /records/<record_id>`

- headers:
  - `Authorization`: Required
- path:
  - `record_id`: A `dns-api` record id

Returns a single dns record.

```shell
curl \
  -X GET \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/records/1
```

#### `POST /records`

Create a new record.

- headers:
  - `Authorization`: Required
  - `Content-Type`: Required. Value: `application/json`
- json data:
  - `domain_type`: Options: [`A`, `CNAME`]. Case-insensitive
  - `domain`: A domain managed by `dns-api`
  - `subdomain`: A valid subdomain. Currently only alphanumeric values are allowed.
  - `to`: A endpoint to point the `A` record or `CNAME`.

Creates an `A` or `CNAME` record for the specified path.

```shell
curl \
  -X POST \
  -H "Authorization: Bearer JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain_type": "cname", "domain": "example.com", "subdomain": "api", "to": "api.example.org"}' \
  http://localhost:8000/records
```

#### `PATCH /records/<record_id>`

Replace the `to` value for a specified record.

- headers:
  - `Authorization`: Required
  - `Content-Type`: Required. Value: `application/json`
- json data:
  - `to`: A endpoint to point the `A` record or `CNAME`.
- path:
  - `record_id`: A `dns-api` record id

Creates an `A` or `CNAME` record for the specified path.

```shell
curl \
  -X POST \
  -H "Authorization: Bearer JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "api.example.org"}' \
  http://localhost:8000/records/1
```

#### `DELETE /records/<record_id>`

Delete the specified record.

- headers:
  - `Authorization`: Required
- path:
  - `record_id`: A `dns-api` record id

Deletes the specified dns record.

```shell
curl \
  -X DELETE \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/records/1
```

#### `POST /records/<domain_type>/<domain>/<subdomain>/<to>`

Create or update a record specified by path.

- headers:
  - `Authorization`: Required
- path:
  - `domain_type`: Options: [`A`, `CNAME`]. Case-insensitive
  - `domain`: A domain managed by `dns-api`
  - `subdomain`: A valid subdomain. Currently only alphanumeric values are allowed.
  - `to`: A endpoint to point the `A` record or `CNAME`.

Creates an `A` or `CNAME` record for the specified path.

```shell
curl \
  -X POST \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/records/cname/example.com/api/api.example.org
```

#### `DELETE /records/<domain_type>/<domain>/<subdomain>`

Delete a record specified by path.

- headers:
  - `Authorization`: Required
- path:
  - `domain_type`: Options: [`A`, `CNAME`]. Case-insensitive
  - `domain`: A domain managed by `dns-api`
  - `subdomain`: A valid subdomain. Currently only alphanumeric values are allowed.

Deletes an `A` or `CNAME` record on the specified path.

```shell
curl \
  -X DELETE \
  -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:8000/records/cname/example.com/api
```
