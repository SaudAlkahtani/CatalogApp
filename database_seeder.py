from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Item, User, Base

engine = create_engine('sqlite:///itemcatalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# delete all old rows:
session.query(Category).delete()
session.query(Item).delete()
session.query(User).delete()
session.commit()
User.__table__.columns.keys()
# creating temp user:
User1 = User(email="king77saud@gmail.com", fullname="Saud Alkahtani",
             photo="www.google.com")
session.add(User1)
session.commit()
# first Category :
Category1 = Category(title="Smartphones")
Item1 = Item(title="iPhone 6s plus", description="Phone by Apple",
             Category=Category1, User=User1)
Item2 = Item(title="Galaxy S3", description="Old Phone by Samsung",
             Category=Category1, User=User1)
Item3 = Item(title="HUAWEI Mate 20 Pro", description="Has 3 Cameras!",
             Category=Category1, User=User1)
session.add(Category1)
session.commit()
session.add(Item1)
session.add(Item2)
session.add(Item3)
session.commit()
# second category:
Category2 = Category(title="Games")
Item4 = Item(title="The Legend of zelda Wind waker",
             description="Best game ever!",
             Category=Category2, User=User1)
Item5 = Item(title="Super smash bros ultimate", description="Second best game",
             Category=Category2, User=User1)
session.add(Category2)
session.commit()
session.add(Item4)
session.add(Item5)
session.commit()
# third category:
Category3 = Category(title='Gaming Consoles')
Item6 = Item(title='Nintendo Switch',
             description="Handheld console made by nintendo - 2017",
             Category=Category3, User=User1)
Item7 = Item(title="PSPgo",
             description="Handheld Console made by Sony - 2009",
             Category=Category3, User=User1)
Item8 = Item(title="PS4", description="Home console made by Sony - 2013",
             Category=Category3, User=User1)
session.add(Category3)
session.commit()
session.add(Item6)
session.add(Item7)
session.add(Item8)
session.commit()


print "database populated!"

# Categorys = session.query(Category).all()
# for Category in Categorys:
#     print Category.title
#     print Category.id


# items = session.query(Item).all()
# for item in items:
#     print item.title
#     print item.description
#     print item.catg_id
