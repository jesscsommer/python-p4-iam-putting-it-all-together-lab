#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    if not session.get('user_id') and request.endpoint == 'recipes':
        return make_response({'error': 'Unauthorized'}, 401)


class Signup(Resource):
    def post(self):
        try: 
            data = request.get_json()

            username = data.get('username')
            password = data.get('password')
            image_url = data.get('image_url')
            bio = data.get('bio')

            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            new_user.password_hash = password 

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id 
            
            return make_response(new_user.to_dict(), 201)
        except Exception as e: 
            return make_response({'error': [str(e)]}, 422)

class CheckSession(Resource):
    def get(self): 
        if id := session.get('user_id'):
            user = db.session.get(User, id)
            return make_response(user.to_dict(), 200)
        return make_response({'error': 'Unauthorized'}, 401)

class Login(Resource):
    def post(self):
        try:
            data = request.get_json()
            
            username = data.get('username')
            password = data.get('password')
            if user := User.query.filter(User.username == username).first():
                if user.authenticate(password):
                    session['user_id'] = user.id
                    return make_response(
                        user.to_dict(only= 
                                        ('id', 'username', 'image_url', 'bio')), 
                        201
                    )
            return make_response({'error': 'Invalid credentials'}, 401)
        except: 
            return make_response({'error': 'Invalid credentials'}, 401) 

class Logout(Resource):
    def delete(self): 
        if session.get('user_id'):
            session['user_id'] = None
            return make_response({}, 204)
        return make_response({'error': 'Unauthorized'}, 401)

class RecipeIndex(Resource):
    def get(self):
        recipes = [r.to_dict() for r in Recipe.query.all()]
        return make_response(recipes, 200)
    def post(self):
        try: 
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session.get('user_id')
            )
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)
        except: 
            return make_response({'error': 'Unprocessable Entity'}, 422)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
