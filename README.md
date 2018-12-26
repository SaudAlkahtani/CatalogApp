## This project is presented for Udacity Full stack nano degree 
### main feature of this project to display an item catalog
### This project uses google sign in to allow users to sign in and add items to the categories
### The project uses a database which contain these tables
- Category Table
  - Includes these columns :
    - Title of the category.
    - id of the category.
-  Item Table
   - Includes these columns:
     - The id of the item.
     - The title of the item.
     - The category id of which this item belongs ( as foreign key )
     - The id of the owner of the item ( as foreign key ) 
-  User table
  - Includes these columns:
    - The id of the user. 
    - The email of the user.
    - The full name of the user.
    - The photo of the user
## Steps you need to run this code:
 - Install the required software:
   - a.Vagrant: https://www.vagrantup.com/downloads.html
   - b. Virtual Machine: https://www.virtualbox.org/wiki/Downloads
   - c. Download a FSND virtual machine: https://github.com/udacity/fullstack-nanodegree-vm
 - Once installed, download the project as zip file , then extract the files into the vagrant folder  "/vagrant"
   using your prefered command line , input the following commands:
   ```
    cd vagrant
    vagrant up 
    vagrant ssh
    cd /vagrant
   ```
- This means that vagrant is ready, now you have to input the following commands:
- "database_setup.py" will create the tables mentioned above
- "database_seeder.py" will populate the database with dummy data
- "catalogApp.py" is the app which you run to access the item catalog
- Once you're ready and have all these files, input these commands:
    ```
    python database_setup.py
    python database_seeder.py
    python catalogApp.py
    ```       
- The project should be excuted and now you can browse the item catalog by going to your prefered internet browser and enter the url: http://localhost:5000/ 
