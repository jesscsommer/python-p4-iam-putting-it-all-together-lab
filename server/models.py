from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates 

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    recipes = db.relationship('Recipe', back_populates='user')

    def __repr__(self):
        return f'User #{self.id}: {self.username}'
    
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed')
    
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, 
                                            password.encode('utf-8'))
    
    @validates('username')
    def validate_username(self, _, value):
        existing_user = User.query.filter(User.username == value).first()
        if not value or existing_user: 
            return AttributeError('Unique username required')
        return value 
    
    @validates('_password_hash', 'image_url', 'bio')
    def validate_user(self, key, value):
        if not value: 
            raise AttributeError(f'{key} required')
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50'),
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)


    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='recipes')

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'

    @validates('title', 'instructions')
    def validate_recipe(self, key, value):
        if not key: 
            return AttributeError(f'{key} must be present')
        if key == 'instructions' and len(value) < 50: 
            return AttributeError(f'{key} must be at least 50 characters')
        return value
