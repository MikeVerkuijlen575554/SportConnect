from app import app, db

def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        print("All tables dropped successfully.")
        
        # Create all tables
        db.create_all()
        print("All tables created successfully.")

if __name__ == '__main__':
    reset_database() 