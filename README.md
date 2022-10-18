# Django Authentication system

Django project setup with complete authentication rest apis
with cors enabled and jwt token based authentication.

## How to run project

Clone project

Create virtual environment 

```bash
python3 -m venv venv
```
Activate virtual environment and install all dependancies

```bash
. venv/bin/activate
```

```bash
pip install -r requirements.txt
```

Apply all migrattions to migrate  

```bash
python3 manage.py migrate
```

Now you can test the app using development server

```bash
python3 manage.py runserver
```
