import MySQLdb
from app import app, db, EventType, EventSubType

def init_db():
    # Connect directly to MySQL to handle table dropping
    conn = MySQLdb.connect(
        host='localhost',
        user='root',
        password='Sportgemeenschap1',
        db='sportconnect'
    )
    cursor = conn.cursor()
    
    try:
        # Disable foreign key checks
        cursor.execute('SET FOREIGN_KEY_CHECKS=0')
        
        # Drop tables in correct order
        tables = [
            'subscription',
            'event_registrations',
            'preference',
            'event',
            'event_sub_type',
            'event_type',
            'user'
        ]
        
        for table in tables:
            try:
                cursor.execute(f'DROP TABLE IF EXISTS {table}')
                print(f"Dropped table {table}")
            except Exception as e:
                print(f"Error dropping table {table}: {str(e)}")
        
        # Re-enable foreign key checks
        cursor.execute('SET FOREIGN_KEY_CHECKS=1')
        conn.commit()
        
        with app.app_context():
            # Create all tables
            db.create_all()
            print("All tables created successfully.")
            
            # Create event types with local icons
            event_types = [
                ('Football', '/static/images/icons/football.png'),
                ('Basketball', '/static/images/icons/basketball.png'),
                ('Tennis', '/static/images/icons/tennis.png'),
                ('Swimming', '/static/images/icons/swimming.png'),
                ('Running', '/static/images/icons/running.png'),
                ('Cycling', '/static/images/icons/cycling.png'),
                ('Volleyball', '/static/images/icons/volleyball.png'),
                ('Fitness', '/static/images/icons/fitness.png')
            ]
            
            for name, icon in event_types:
                event_type = EventType(name=name, icon=icon)
                db.session.add(event_type)
            
            # Create event subtypes
            subtypes = {
                'Football': ['5-a-side', '7-a-side', '11-a-side', 'Casual game'],
                'Basketball': ['3x3', '5x5', 'Streetball', 'Training'],
                'Tennis': ['Singles', 'Doubles', 'Training', 'Tournament'],
                'Swimming': ['Freestyle', 'Backstroke', 'Breaststroke', 'Training'],
                'Running': ['5K', '10K', 'Marathon', 'Trail running'],
                'Cycling': ['Road cycling', 'Mountain biking', 'BMX', 'Tour'],
                'Volleyball': ['Indoor', 'Beach', '4x4', 'Training'],
                'Fitness': ['Cardio', 'Strength', 'HIIT', 'Yoga']
            }
            
            # Add subtypes
            for event_type_name, subtype_list in subtypes.items():
                event_type = EventType.query.filter_by(name=event_type_name).first()
                if event_type:
                    for subtype_name in subtype_list:
                        subtype = EventSubType(name=subtype_name, eventTypeID=event_type.id)
                        db.session.add(subtype)
            
            db.session.commit()
            print("Database initialized successfully!")
    
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    init_db() 