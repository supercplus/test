# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# import os

# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://hello_flask:hello_flask@localhost/Project'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# def run_sql_file(file_path):
#     """Run SQL commands from a given file."""
#     with open(file_path, 'r', encoding='utf-8') as file:
#         sql_commands = file.read()
#         commands = sql_commands.split(';')
        
#         for command in commands:
#             if command.strip():
#                 db.session.execute(command)

# @app.route('/create_db', methods=['POST'])
# def create_db():
#     """Create database tables and seed initial data."""
#     db.drop_all()
#     run_sql_file(os.path.join('Project', 'session.sql')) 
#     db.session.commit() 
#     return "Database created and seeded successfully."

# if __name__ == "_main_":
#     cli()