from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required
  # Make sure stores is also imported
from db import db  
from schema import ItemSchema, ItemUpdateSchema
from models import ItemModel
from sqlalchemy.exc import SQLAlchemyError
blp = Blueprint("items", __name__, description="Operations on items")

@blp.route("/item")
class Items(MethodView):
    @jwt_required()
    @blp.response(200,ItemSchema(many=True))
    def get(self):
        return ItemModel.query.all()
    
    @jwt_required()
    @blp.arguments(ItemSchema)
    @blp.response(200,ItemSchema)
    def post(self, item_data):
        item=ItemModel(**item_data)
        try: 
          db.session.add(item)
          db.session.commit()
        except SQLAlchemyError:
            abort(500,message="An error occured while inserting the item")  

        return item

@blp.route("/item/<string:item_id>")
class ItemById(MethodView):
    @blp.response(200,ItemSchema)
    def get(self, item_id):
       item=ItemModel.query.get_or_404(item_id)
       return item
    
    @jwt_required()
    @blp.arguments(ItemUpdateSchema)
    @blp.response(200,ItemSchema)
    def put(self,item_data ,item_id):
        item=ItemModel.query.get(item_id)
        if item:
            item.name=item_data["name"]
            item.price=item_data["price"]
        else:
            item=ItemModel(**item_data)

        db.session.add(item)
        db.session.commit()

        return item                

    def delete(self, item_id):
        item=ItemModel.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return {"message":"Item deleted"}

