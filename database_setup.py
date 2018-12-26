import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


Base = declarative_base()


class Category(Base):
    __tablename__ = 'catg'
    id = Column(Integer, primary_key=True)
    title = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {
            'Id': self.id,
            'Name': self.title,
        }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    fullname = Column(String(250), nullable=False)
    photo = Column(String(250), nullable=False)


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    title = Column(String(250), nullable=False)
    catg_id = Column(Integer, ForeignKey('catg.id'))
    description = Column(String(450), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    Category = relationship(Category)
    User = relationship(User)

    @property
    def serialize(self):
            return {
                'category_id': self.catg_id,
                'description': self.description,
                'id': self.id,
                'title': self.title,
            }

engine = create_engine('sqlite:///itemcatalog.db?check_same_thread=False')
Base.metadata.create_all(engine)
