# Django Authentication system

Django Authentication system with custom user model.
You can login with email instead of username.

This is the complete tutorial for creating Django Authentication system with custom user model.
Also added email templates where email is sent using html templates instead of regular text emails.

## Features

1. Complete rest apis
2. Compatible with any frontend technolgies like React, Angular, Vue
3. Json Web Token (JWT) enabled
4. Cors enabled
5. Email HTML templates to send creative emails instead of regular text emails

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
