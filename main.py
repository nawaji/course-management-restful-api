from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io
from dotenv import load_dotenv
import os

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

load_dotenv()

PHOTO_BUCKET = os.getenv('PHOTO_BUCKET')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

client = datastore.Client()

USERS = "users"
COURSES = "courses"
course_required_fields = ['subject', 'number', 'title', 'term', 'instructor_id']

ERROR_400 = {"Error": "The request body is invalid"}, 400
ERROR_401 = {"Error": "Unauthorized"}, 401
ERROR_403 = {"Error": "You don't have permission on this resource"}, 403
ERROR_404 = {"Error": "Not found"}, 404
ERROR_409 = {"Error": "Enrollment data is invalid"}, 409

# Update the values of the following 3 variables
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTH_DOMAIN = os.getenv('AUTH_DOMAIN')
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

# change this to https when using actual gcloud domain
PROTOCOL = os.getenv('PROTOCOL')
HW_DOMAIN = os.getenv('DOMAIN')

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + AUTH_DOMAIN,
    access_token_url="https://" + AUTH_DOMAIN + "/oauth/token",
    authorize_url="https://" + AUTH_DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ AUTH_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ AUTH_DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload     

def has_duplicates(arr):
    deduped_list = list(set(arr))
    if len(deduped_list) != len(arr):
        return True 
    else:
        return False

# returns iterable blobs of each object in the bucket
def list_blobs_in_bucket(bucket_name):
    storage_client = storage.Client()
    blobs = storage_client.list_blobs(bucket_name)
    return blobs

# compares the auth0 string from a given JWT and user in datastore
def is_specified_user(sub, id):
    user_key = client.key(USERS, id)
    user = client.get(key = user_key)
    if sub == user['sub']:
        return True
    else:
        return False   

# API endpoint #1 user login
# generate a JWT from the Auth0 domain and return it
# request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()

    if "username" not in content:
        return ERROR_400

    if "password" not in content:
        return ERROR_400

    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + AUTH_DOMAIN + '/oauth/token'

    resp = requests.post(url, json=body, headers=headers)
    resp_data = resp.json()

    if 'id_token' not in resp_data:
        return ERROR_401

    token = {}
    token['token'] = resp_data['id_token']
    return token, 200

# API endpoint #2 get all users
# return a list of all users with specifically "id", "sub", and "role"
# request: JWT as bearer token in authorization header
# response: JSON with "id", "sub", and "role" for each listed user
@app.route('/' + USERS, methods=['GET'])
def get_businesses():
    if 'Authorization' in request.headers:
        try:
            payload = verify_jwt(request)
        except Exception as e:
            print(e)
            return ERROR_401

        admin_query = client.query(kind = USERS)
        admin_query.add_filter('sub', '=', payload['sub'])
        admin_query.add_filter('role', '=', "admin")
        results = list(admin_query.fetch())

        if results:
            user_query = client.query(kind = USERS)
            results = list(user_query.fetch())
            for r in results:
                r['id'] = r.key.id
            return results, 200

        else:
            return ERROR_403

# API endpoint #3 get a user
# return details of a specified user
# request: JWT as bearer token in authorization header
# response: JSON with additional details not shown by GETing all users
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_business(id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return ERROR_401

    user_key = client.key(USERS, id)
    user = client.get(key = user_key)
    user['id'] = user.key.id

    blobs = list_blobs_in_bucket(PHOTO_BUCKET)
    for blob in blobs:
        if blob.metadata['id'] == str(id):
            user['avatar_url'] = PROTOCOL + HW_DOMAIN + "/" + USERS + "/" + str(id) + "/avatar"
            break

    if user is None:
        return ERROR_404

    if user['role'] == 'student':
        user['courses'] = []

        course_query = client.query(kind = COURSES)
        course_query.add_filter('enrollment', '=', user.key.id)
        results = list(course_query.fetch())

        print("results", results)
        for course in results:
            user['courses'].append(course.key.id)

    if user['role'] == 'instructor':
        user['courses'] = []
        course_query = client.query(kind = COURSES)
        course_query.add_filter('instructor_id', '=', id)
        results = list(course_query.fetch())

        for course in results:
            course_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "/" + str(course.key.id)
            user['courses'].append(course_url)
 
    if payload['sub'] == user['sub']:
        return user, 200
    else:
        user_query = client.query(kind = USERS)
        user_query.add_filter('sub', '=', payload['sub'])
        user_query.add_filter('role', '=', "admin")
        results = list(user_query.fetch())

        if results:
            return user, 200
        else:
            return ERROR_403

@app.route('/')
def index():
    return "Hello!"

# API endpoint #4 create/update a user's avatar
# return avatar url
# request: JWT as bearer token in authorization header, must be
#   owned by the user_id in the path parameter
# response: JSON with avatar url string
@app.route('/' + USERS + '/<int:id>/avatar', methods=['POST'])
def create_update_avatar(id):
    if 'file' not in request.files:
        return ERROR_400

    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return ERROR_401

    if is_specified_user(payload['sub'], id) == False:
        return ERROR_403

    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)

    blobs = list_blobs_in_bucket(PHOTO_BUCKET)
    for blob in blobs:
        if blob.metadata['id'] == str(id):
            blob.delete()

    blob = bucket.blob(file_obj.filename)
    blob.metadata = {'id': str(id)}
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    resp = {}
    resp['avatar_url'] = PROTOCOL + HW_DOMAIN + '/' + USERS + "/" + str(id) + "/avatar"
    return resp, 200

# API endpoint #5 get user avatar
# return file in the response body
# request: JWT as bearer token in authorization header, must be
#   owned by the user_id in the path parameter
# response: avatar file
@app.route('/' + USERS + '/<int:id>/avatar', methods=['GET'])
def get_user_avatar(id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return ERROR_401

    if is_specified_user(payload['sub'], id) == False:
        return ERROR_403

    blobs = list_blobs_in_bucket(PHOTO_BUCKET)
    for blob in blobs:
        if blob.metadata['id'] == str(id):
            file_obj = io.BytesIO()
            blob.download_to_file(file_obj)
            file_obj.seek(0)
            return send_file(file_obj, mimetype='image/x-png', download_name=blob.name)

    return ERROR_404

# API endpoint #6 delete user avatar
# return 204 with empty body
# request: JWT as bearer token in authorization header, must be
#   owned by the user_id in the path parameter
# response: 204 with empty body
@app.route('/' + USERS + '/<int:id>/avatar', methods=['DELETE'])
def delete_user_avatar(id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        print(e)
        return ERROR_401

    if is_specified_user(payload['sub'], id) == False:
        return ERROR_403

    blobs = list_blobs_in_bucket(PHOTO_BUCKET)
    for blob in blobs:
        if blob.metadata['id'] == str(id):
            blob.delete()
            return '', 204

    return ERROR_404

# API endpoint #7 create a course
# return course details minus enrollment
# request: JWT as bearer token in authorization header, must be
#   admin
# response: JSON with course details minus enrollment
@app.route('/' + COURSES, methods=['POST'])
def create_course():
    content = request.get_json()
    new_course = datastore.entity.Entity(key=client.key(COURSES))

    try:
        payload = verify_jwt(request)
    except Exception as e:
        return ERROR_401

    for i in range(len(course_required_fields)):
        if course_required_fields[i] not in content:
            return ERROR_400

    admin_query = client.query(kind = USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return ERROR_403

    user_key = client.key(USERS, content['instructor_id'])
    user = client.get(key = user_key)

    if not user:
        return ERROR_400

    if user['role'] != 'instructor':
        return ERROR_400

    new_course.update({
        "subject": content["subject"], 
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": content["instructor_id"],
        "enrollment": []
    })

    client.put(new_course)
    del new_course['enrollment']
    new_course['id'] = new_course.key.id
    api_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "/" + str(new_course.key.id)
    new_course['self'] = api_url
    return (new_course, 201)

# API endpoint #8 get all courses
# return pages of courses minus enrollment details
# request: none
# path params: ?offset=[number]&limit=[number]
# response: course pagination based on path params
@app.route('/' + COURSES, methods=['GET'])
def lodgings_get():
    args = request.args

    limit = 3
    offset = 0
    entries = []
    if 'limit' in args:
        limit = int(args['limit'])
        offset = int(args['offset'])

    course_query = client.query(kind = COURSES)
    course_query.order = ['subject']
    page_iterator = course_query.fetch(limit=limit, offset=offset)
    page = page_iterator.pages
    results = list(next(page))

    for course in results:
        if "enrollment" in course:
            del course["enrollment"]
        course['id'] = str(course.key.id)
        api_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "/" + str(course.key.id)
        course['self'] = api_url

    next_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "?limit=3&offset=3"
    return ({'courses': results, 'next': next_url})

# API endpoint #9 get a course
# return course minus enrollment details
# request: course_id
# response: course details
@app.route('/' + COURSES + "/<int:id>", methods=['GET'])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key = course_key)

    if not course:
        return ERROR_404
    
    del course['enrollment']
    course['id'] = str(course.key.id)
    api_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "/" + str(course.key.id)
    course['self'] = api_url
    return course

# API endpoint #10 patch a course
# return updated course details 
# request: Any of the course properties, excluding enrollment.
#   Enrollment can be updated via API endpoint #12.
# response: updated course detils
@app.route('/' + COURSES + "/<int:id>", methods=['PATCH'])
def patch_course(id):
    content = request.get_json()

    try:
        payload = verify_jwt(request)
    except Exception as e:
        return ERROR_401

    course_key = client.key(COURSES, id)
    course = client.get(key = course_key)

    if not course:
        return ERROR_403

    admin_query = client.query(kind = USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return ERROR_403

    if "instructor_id" in content:
        user_key = client.key(USERS, content['instructor_id'])
        user = client.get(key = user_key)        

        if user['role'] != 'instructor':
            return ERROR_400

    for data in content:
        course[data] = content[data]

    client.put(course)
    del course['enrollment']
    course['id'] = str(course.key.id)
    api_url = PROTOCOL + HW_DOMAIN + "/" + COURSES + "/" + str(course.key.id)
    course['self'] = api_url
    return course

# API endpoint #11 delete a course
# return 204 with empty body
# request: course_id
#   Enrollment is a property tied to course, meaning nothing else
#   needs to be done to ensure students are un-enrolled.
# response: 204 with empty body
@app.route('/' + COURSES + "/<int:id>", methods=['DELETE'])
def delete_course(id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        return ERROR_401

    course_key = client.key(COURSES, id)
    course = client.get(key = course_key)

    if not course:
        return ERROR_403

    admin_query = client.query(kind = USERS)
    admin_query.add_filter('sub', '=', payload['sub'])
    admin_query.add_filter('role', '=', "admin")
    results = list(admin_query.fetch())

    if not results:
        return ERROR_403

    client.delete(course_key)
    return ("", 204)    

# API endpoint #12 update enrollment
# return 200 with empty body
# request: Two arrays, "add" and "remove". It is assumed at least
#   one is non-empty.
# response: 200 with empty body
@app.route('/' + COURSES + "/<int:id>/students", methods=['PATCH'])
def update_enrollment(id):
    content = request.get_json()

    try:
        payload = verify_jwt(request)
    except Exception as e:
        return ERROR_401

    course_key = client.key(COURSES, id)
    course = client.get(key = course_key)

    if not course:
        return ERROR_403

    user_query = client.query(kind = USERS)
    user_query.add_filter('sub', '=', payload['sub'])
    results = list(user_query.fetch())

    for user_result in results:
        if user_result['role'] == 'admin':
            break

        if user_result['role'] == 'instructor':
            if course['instructor_id'] != user_result.key.id:
                return ERROR_403
        else:
            return ERROR_403

    # student ids cannot be in both "add" and "remove"
    # check for ID validness and create a deduped list of IDs 
    students_to_add = []
    students_to_remove = []

    for student in content['add']:
        user_key = client.key(USERS, student)
        user = client.get(key = user_key)

        if not user:
            return ERROR_409
        if user['role'] != 'student':
            return ERROR_409
        if student in content['remove']:
            return ERROR_409
        if user.key.id not in students_to_add:
            students_to_add.append(user.key.id)

    for student in content['remove']:
        user_key = client.key(USERS, student)
        user = client.get(key = user_key)

        if not user:
            return ERROR_409
        if user['role'] != 'student':
            return ERROR_409
        if user not in students_to_remove:
            students_to_remove.append(user.key.id)

    # We can either attach the course ID as a property to each student
    # OR check courses every time there's a get request for a student /
    # instructor to check for enrollment.
    # I think it's easier to have the list of IDs attached to the course object

    for student in students_to_add:
        if student not in course['enrollment']:
            course['enrollment'].append(student)

    for student in students_to_remove:
        if student in course['enrollment']:
            course['enrollment'].remove(student)
    
    client.put(course)
    return ("", 200)     

# API endpoint #13 get enrollment
# return 200 with enrollment list
# request: course_id, JWT as a bearer token in auth header
# response: 200 with list of enrolled students for a specified course
@app.route('/' + COURSES + "/<int:id>/students", methods=['GET'])
def get_enrollment(id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        return ERROR_401

    course_key = client.key(COURSES, id)
    course = client.get(key = course_key)

    if not course:
        return ERROR_403
    
    user_query = client.query(kind = USERS)
    user_query.add_filter('sub', '=', payload['sub'])
    results = list(user_query.fetch())
    user = results[0]

    if not results:
        return ERROR_403

    if user['role'] == 'admin':
        return course['enrollment'], 200

    if user['role'] == 'instructor':
        if user.key.id != course['instructor_id']:
            return ERROR_403

        return course['enrollment'], 200     

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)