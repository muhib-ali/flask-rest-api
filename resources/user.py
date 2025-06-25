from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity,create_refresh_token
# from redis import Redis
from blocklist import BLOCKLIST
from flask_jwt_extended import jwt_required,get_jwt

from db import db
from models import UserModel
from schema import UserSchema

blp=Blueprint("users","users",description="Operation on users")

# connecting redis
# redis_blocklist = Redis(host="redis-server", port=6379, decode_responses=True)


@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(UserModel.username==user_data["username"]).first():
            abort(409,message="User with same name already registed")
        user=UserModel(username=user_data["username"],password=pbkdf2_sha256.hash(user_data["password"]))
        db.session.add(user)
        db.session.commit()
        return {"message":"user registerd"},200 
    
@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200,UserSchema)
    def get(self,user_id):
        return UserModel.query.get_or_404(user_id)


    def delete(self,user_id):
        user = UserModel.query.get(user_id)
        db.session.delete(user)
        db.session.commit()

        return {"message":"User deleted"},200    
    
@blp.route("/login")
class Userlogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter_by(username=user_data["username"]).first()
        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=str(user.id),fresh=True)
            refresh_token = create_refresh_token(identity=user.id)

            return {"access_token": access_token,"refresh_token":refresh_token}
        
        abort(401, message="Invalid credentials")

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user=get_jwt_identity()
        new_token=create_access_token(identity=current_user,fresh=False)
        return {"access_token":new_token}

@blp.route("/logout")
class Userlogout(MethodView):
    @jwt_required()
    def post(self):
         jti=get_jwt()["jti"]
         BLOCKLIST.add(jti)
         return {"message":"Successfully logged out"}
         