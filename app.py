# -*- coding: utf-8 -*-
from __future__ import print_function

import datetime
import json
import logging
import os
import requests
import types
from flask import Flask
from flask import g
from flask import request
from flask import Response
from flask_httpauth import HTTPTokenAuth
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import JSONWebSignatureSerializer as JWT
from json import JSONEncoder
from sqlalchemy import func
from sqlalchemy.orm import validates

BLACKLISTED_SUBDOMAINS = os.getenv('BLACKLISTED_SUBDOMAINS', '').split(',')
BLACKLISTED_SUBDOMAINS = filter(None, BLACKLISTED_SUBDOMAINS)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:////tmp/test.db')
DNSIMPLE_ACCOUNT_ID = os.getenv('DNSIMPLE_ACCOUNT_ID')
DNSIMPLE_ACCOUNT_TOKEN = os.getenv('DNSIMPLE_ACCOUNT_TOKEN')
DNSIMPLE_DOMAIN_TTL = int(os.getenv('DNSIMPLE_DOMAIN_TTL', 60))
DNSIMPLE_DOMAINS = os.getenv('DNSIMPLE_DOMAINS').split(',')
DNSIMPLE_DOMAINS = filter(None, DNSIMPLE_DOMAINS)
SECRET_KEY = os.getenv('SECRET_KEY', 'secret key')
VALID_USERS = os.getenv('VALID_USERS', '').split(',')
VALID_USERS = filter(None, VALID_USERS)
BASE_URL = 'https://api.dnsimple.com/v2/{0}'.format(DNSIMPLE_ACCOUNT_ID)

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
jwt = JWT(app.config['SECRET_KEY'])
auth = HTTPTokenAuth('Bearer')


def _json_data(self, key, default):
    if not getattr(self, 'data_json', None):
        self.data_json = {}
        try:
            self.data_json = json.loads(self.data)
        except:
            pass

        if type(self.data_json) is not dict:
            self.data_json = {}

    return self.data_json.get(key, default)


def _default(self, obj):
    if isinstance(obj, datetime.datetime):
        return obj.strftime('%Y-%m-%dT%H:%M:%S')
    return getattr(obj.__class__, 'to_json', _default.default)(obj)


_default.default = JSONEncoder().default
JSONEncoder.default = _default


class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dnsimple_record_id = db.Column(db.BigInteger, unique=True, nullable=False)
    domain_key = db.Column(db.Unicode(116), unique=True, nullable=False)
    domain_type = db.Column(db.Unicode(16), unique=False, nullable=False)
    domain = db.Column(db.Unicode(32), unique=False, nullable=False)
    subdomain = db.Column(db.Unicode(32), unique=False, nullable=False)
    to = db.Column(db.Unicode(64), unique=False, nullable=False)
    created = db.Column(db.DateTime, default=func.now(), nullable=False)

    def __repr__(self):
        return '<Record %r>' % self.domain_key

    @classmethod
    def find_by_id(cls, record_id):
        return cls.query.filter_by(id=record_id).first()

    @classmethod
    def find_by_domain_key(cls, domain_key):
        return cls.query.filter_by(domain_key=domain_key).first()

    @classmethod
    def paginate(cls, page_number=1, page_size=30):
        return cls.query.order_by(cls.id.desc())\
                        .offset((page_number - 1) * page_size)\
                        .limit(page_size)\
                        .all()

    @classmethod
    def new(cls, domain_type, domain, subdomain, to):
        domain_key = cls.get_domain_key(domain_type, domain, subdomain)
        return Record(
            domain_key=domain_key,
            domain_type=domain_type.upper(),
            domain=domain,
            subdomain=subdomain,
            to=to)

    @classmethod
    def domain_or_new(cls, domain_type, domain, subdomain, to):
        domain_key = cls.get_domain_key(domain_type, domain, subdomain)
        record = cls.find_by_domain_key(domain_key)

        if not record:
            record = Record.new(domain_type, domain, subdomain, to)

        record.to = to
        return record

    @classmethod
    def get_domain_key(cls, domain_type, domain, subdomain):
        return u'{0}::{1}::{2}'.format(domain_type.upper(), domain, subdomain)

    @property
    def payload(self):
        return {
            'name': self.subdomain,
            'type': self.domain_type,
            'content': self.to,
            'ttl': DNSIMPLE_DOMAIN_TTL,
            'priority': 10,
        }

    @validates('domain_type')
    def validate_domain_type(self, key, value):
        value = value.upper()
        assert value is not None, 'domain_type cannot be None'
        assert value in ['A',
                         'CNAME'], 'domain_type must be one of A or CNAME.'
        return value

    @validates('domain')
    def validate_domain(self, key, value):
        assert value is not None, 'Domain cannot be None'
        assert value in DNSIMPLE_DOMAINS, 'Invalid domain specified.'
        return value

    @validates('subdomain')
    def validate_subdomain(self, key, value):
        assert value is not None, 'Subdomain cannot be None'
        assert len(value) > 0, 'Subdomain cannot be zero-length'
        assert value.isalnum(
        ), 'Subdomain can only be made of letters and numbers.'
        assert value not in BLACKLISTED_SUBDOMAINS, 'Specified subdomain is blacklisted.'
        return value

    @validates('to')
    def validate_to(self, key, value):
        assert value is not None, 'To cannot be None'
        assert len(value) > 0, 'To cannot be zero-length'
        return value

    def delete(self):
        is_new = self.id is None
        if is_new:
            return True

        try:
            if getattr(self, 'before_delete', None):
                if not self.before_delete():
                    return False

            db.session.delete(self)
            db.session.commit()

            if getattr(self, 'after_save', None):
                self.after_save()

            return True
        except Exception as e:
            app.logger.warning('delete failed: {0}'.format(str(e)))
            self.append_errors([{'title': e}])
            db.session.rollback()
            return False

        return True

    def save(self):
        is_new = self.id is None
        try:
            if getattr(self, 'before_save', None):
                if not self.before_save(is_new):
                    return False

            db.session.add(self)
            db.session.commit()

            if getattr(self, 'after_save', None):
                self.after_save(is_new)

            return True
        except Exception as e:
            app.logger.warning('Save failed: {0}'.format(str(e)))
            self.append_errors([{'title': e}])

            try:
                self.save_failed()
            except Exception as e:
                self.append_errors([{'title': e}])
            db.session.rollback()
            return False

    def append_errors(self, errors):
        if not getattr(self, '_errors', None):
            self._errors = []
        self._errors.extend(errors)

    def get_errors(self):
        if not getattr(self, '_errors', None):
            self._errors = []
        return self._errors

    def before_delete(self):
        return self.delete_dnsimple_record()

    def delete_dnsimple_record(self):
        if not self.dnsimple_record_id:
            return True

        success = False
        errors = []
        try:
            r = requests.delete(
                '{0}/zones/{1}/records/{2}'.format(BASE_URL, self.domain,
                                                   self.dnsimple_record_id),
                headers={
                    'Authorization':
                    'Bearer {0}'.format(DNSIMPLE_ACCOUNT_TOKEN)
                },
                timeout=3)
            success, errors = process_request(r, requests.codes.no_content)
        except requests.exceptions.ReadTimeout as e:
            errors.append({'title': e})
        except requests.exceptions.RequestException as e:
            errors.append({'title': e})

        if not success:
            self.append_errors(errors)

        return success

    def before_save(self, is_new):
        success = False
        errors = []
        if is_new:
            success, errors = self.before_save_new()
        else:
            success, errors = self.before_save_existing()

        if not success:
            self.append_errors(errors)

        return success

    def before_save_new(self):
        success = False
        errors = []

        try:
            r = requests.post(
                '{0}/zones/{1}/records'.format(BASE_URL, self.domain),
                data=self.payload,
                headers={
                    'Authorization':
                    'Bearer {0}'.format(DNSIMPLE_ACCOUNT_TOKEN)
                },
                timeout=3)

            if r.status_code == requests.codes.created:
                self.dnsimple_record_id = r.json()['data']['id']

            success, errors = process_request(r, requests.codes.created)
        except requests.exceptions.ReadTimeout as e:
            errors.append({'title': e})
        except requests.exceptions.RequestException as e:
            errors.append({'title': e})

        return success, errors

    def before_save_existing(self):
        success = False
        errors = []

        try:
            r = requests.patch(
                '{0}/zones/{1}/records/{2}'.format(BASE_URL, self.domain,
                                                   self.dnsimple_record_id),
                data=self.payload,
                headers={
                    'Authorization':
                    'Bearer {0}'.format(DNSIMPLE_ACCOUNT_TOKEN)
                },
                timeout=3)
            success, errors = process_request(r, requests.codes.ok)
        except requests.exceptions.ReadTimeout as e:
            errors.append({'title': e})
        except requests.exceptions.RequestException as e:
            errors.append({'title': e})

        return success, errors

    def save_failed(self):
        return self.delete_dnsimple_record()

    def to_json(self):
        return {
            'id': self.id,
            'type': 'record',
            'domain_key': self.domain_key,
            'domain_type': self.domain_type,
            'domain': self.domain,
            'subdomain': self.subdomain,
            'to': self.to,
            'created': self.created,
        }


try:
    db.create_all()
except Exception as e:
    app.logger.warning(e)


@auth.verify_token
def verify_token(token):
    g.username = None
    try:
        data = jwt.loads(token)
    except:
        return False

    if 'username' not in data:
        return False

    if data['username'] in VALID_USERS:
        g.username = data['username']
        return True

    return False


@app.before_first_request
def setup_logging():
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)


@app.before_request
def before_request():
    request.json_data = types.MethodType(_json_data, request)


@app.errorhandler(401)
def page_not_found(e):
    return json_response(status=404, errors=[{'title': 'Unauthorized'}])


@app.errorhandler(404)
def page_not_found(e):
    return json_response(status=404, errors=[{'title': 'Route not found'}])


@app.errorhandler(405)
def method_not_allowed(e):
    return json_response(status=405, errors=[{'title': 'Method not allowed'}])


@app.errorhandler(AssertionError)
def assertion_error(e):
    return json_response(status=400, errors=[{'title': e.message}])


@app.route('/')
def home():
    return json_response(status=200)


@app.route('/whoami')
@auth.login_required
def whoami():
    return json_response(status=200, data={'id': g.username, 'type': 'user'})


@app.route('/domains')
@auth.login_required
def domains():
    data = []
    for domain in DNSIMPLE_DOMAINS:
        data.append({'id': domain, 'type': 'domain'})
    for subdomain in BLACKLISTED_SUBDOMAINS:
        data.append({'id': subdomain, 'type': 'blacklisted_subdomain'})

    return json_response(status=200, data=data)


@app.route('/records', methods=['GET'])
def read_list():
    page_number = within_range(
        try_int(request.args.get('page[number]', 1), 1), 1, None, 1)
    page_size = within_range(
        try_int(request.args.get('page[size]', 30), 30), 10, 100, 30)
    records = Record.paginate(page_number=page_number, page_size=page_size)
    return json_response(
        status=200,
        data=records,
        meta={'pagination': {
            'number': page_number,
            'size': page_size,
        }})


@app.route('/records', methods=['POST'])
@auth.login_required
def create():
    domain_type = request.json_data('domain_type', None)
    domain = request.json_data('domain', None)
    subdomain = request.json_data('subdomain', None)
    to = request.json_data('to', None)

    domain_key = Record.get_domain_key(domain_type, domain, subdomain)
    record = Record.find_by_domain_key(domain_key)
    if record:
        return json_response(
            status=409, errors=[{
                'title': 'Record already exists'
            }])

    record = Record.new(domain_type, domain, subdomain, to)
    if record.save():
        return json_response(status=200, data=record)
    return json_response(status=400, errors=record.get_errors())


@app.route('/records/<record_id>', methods=['GET'])
@auth.login_required
def read(record_id):
    record = Record.find_by_id(record_id)
    if not record:
        return json_response(
            status=404, errors=[{
                'title': 'Record not found'
            }])

    return json_response(status=200, data=record)


@app.route('/records/<record_id>', methods=['PATCH'])
@auth.login_required
def update(record_id):
    to = request.json_data('to', None)

    record = Record.find_by_id(record_id)
    if not record:
        return json_response(
            status=404, errors=[{
                'title': 'Record not found'
            }])

    record.to = to
    if record.save():
        return json_response(status=200, data=record)
    return json_response(status=400, errors=record.get_errors())


@app.route('/records/<record_id>', methods=['DELETE'])
@auth.login_required
def destroy(record_id):
    record = Record.find_by_id(record_id)
    if not record:
        return json_response(
            status=404, errors=[{
                'title': 'Record not found'
            }])

    if record.delete():
        return json_response(status=200)

    return json_response(status=400, errors=record.get_errors())


@app.route(
    '/records/<domain_type>/<domain>/<subdomain>/<to>', methods=['POST'])
@auth.login_required
def create_path(domain_type, domain, subdomain, to):
    record = Record.domain_or_new(domain_type, domain, subdomain, to)
    if record.save():
        return json_response(status=200, data=record)
    return json_response(status=400, errors=record.get_errors())


@app.route('/records/<domain_type>/<domain>/<subdomain>', methods=['DELETE'])
@auth.login_required
def destroy_path(domain_type, domain, subdomain):
    domain_key = Record.get_domain_key(domain_type, domain, subdomain)
    record = Record.find_by_domain_key(domain_key)
    if not record:
        return json_response(
            status=404, errors=[{
                'title': 'Record not found'
            }])

    if record.delete():
        return json_response(status=200)

    return json_response(status=400, errors=record.get_errors())


def json_response(status=200,
                  data=None,
                  errors=None,
                  meta=None,
                  override_status=None):
    response = {}
    if meta is None:
        meta = {}
    if data is not None:
        response['data'] = data
    if errors is not None:
        response['errors'] = errors

    response['meta'] = meta
    response['meta']['status'] = status
    if override_status is not None:
        response['meta']['status'] = override_status
    return Response(
        sorted_json(response), mimetype='application/json', status=status)


def process_request(r, ok_status_code):
    success = r.status_code == ok_status_code
    errors = []
    if not success:
        if 'application/json' in r.headers['Content-Type'].split(';'):
            has_errors = False
            for field, errs in json.loads(r.text).get('errors', {}).items():
                has_errors = True
                for error in errs:
                    errors.append({'title': '{0}: {1}'.format(field, error)})
            if not has_errors:
                errors.append({'title': json.loads(r.text).get('message')})
        else:
            errors = [{'title': 'Bad response from dnsimple api'}]
    return success, errors


def sorted_json(data):
    return json.dumps(data, sort_keys=True, indent=2, separators=(',', ': ')),


def try_int(i, default):
    try:
        i = int(i)
    except Exception:
        i = default
    return i


def within_range(i, minimum, maximum, default):
    if minimum is not None and i < minimum:
        i = default
    if maximum is not None and i > maximum:
        i = default
    return i
