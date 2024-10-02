import pymongo
from flask import app, request,redirect,url_for

client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
userdb = client['userdb']
users = userdb.customers

client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['userdb']  # Replace 'scanner_results' with your database name
collection = db['scans']



def insert_data():
	if request.method == 'POST':
		name = request.form['name']
		email = request.form['email']
		password = request.form['pass']

		reg_user = {}
		reg_user['name'] = name
		reg_user['email'] = email
		reg_user['password'] = password

		if users.find_one({"email":email}) == None:
			users.insert_one(reg_user)
			return True
		else:
			return False
           

def check_user():

	if request.method == 'POST':
		email = request.form['email']
		password = request.form['pass']

		user = {
			"email": email,
			"password": password
		}

		user_data = users.find_one(user)
		if user_data == None:
			return False, ""
		else:
			return True, user_data["name"]



client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['userdb']
collection = db['scans']

def save_to_database(results):
    try:
        if request.method == 'POST':
            # Assuming 'results' is a dictionary or JSON-like object
            inserted_id = collection.insert_one(results).inserted_id
            print(f"Data inserted with ID: {inserted_id}")
            return True  # Indicate successful insertion
    except pymongo.errors.PyMongoError as e:
        print(f"Error saving to MongoDB: {e}")
        return False  # Return false on error
    
    finally:
        client.close()  
        
        # Always close the MongoDB connection

# Example usage
if __name__ == '__main__':
    results = {"example": "data"}
    save_to_database(results)
    
    
    
    
