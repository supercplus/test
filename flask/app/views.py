from functools import wraps
import json
from os import abort
from flask import (jsonify, render_template,
                   request, url_for, flash, redirect, session, abort)


from sqlalchemy.sql import text
from app import app
from app import db
# from app import User
import requests
import psycopg2
import hashlib
from werkzeug.utils import secure_filename
import os
from flask import send_from_directory
import base64
from app import socketio
from flask_socketio import emit
from flask import url_for




CLIENT_ID = '26GxenhhK15m5n2prKgjQYF33tT0uMjnwkC0Y2Z7'
CLIENT_SECRET = 'z3CTyqGN2sBj4wbeBPEYEu08TU0VVcAyXkWXwYFP'
CMU_OAUTH_URL = 'https://oauth.cmu.ac.th/v1/Authorize.aspx'
REDIRECT_URI = 'http://localhost:56733/auth/cmu/callback'
TOKEN_URL = 'https://oauth.cmu.ac.th/v1/GetToken.aspx'
SCOPE = 'cmuitaccount.basicinfo'
STATE = 'xyz'
LINE_API_URL = 'https://api.line.me/v2/bot/message/broadcast'
CHANNEL_SECRET = '1b163ac789d05c49ef40605fc09bf3eb'
CHANNEL_ACCESS_TOKEN = 'rGYC0cRzr/zaBJNS6jH5u82Jo6aEPg20Rba83njFvYIluGL9UgAB1Eu3UgjtXAr6hy1nqbFCtKYiNNvHUYp8Gjb59mywhzKdmDTzaPRr9wXhXwJ91FR+qE2/fPXuJwkymjwBjQVecwefYNTJICwI7gdB04t89/1O/w1cDnyilFU='  # นำ Access Token จาก Line Developer มาใส่ตรงนี้

def broadcast_line_notification(message):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {CHANNEL_ACCESS_TOKEN}'
    }
    data = {
        "messages": [
            {
                "type": "text",
                "text": message
            }
        ]
    }

    try:
        response = requests.post(LINE_API_URL, headers=headers, json=data)
        response.raise_for_status()
        print("Broadcast message sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending broadcast message: {e}")

@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)
    
@app.route('/login')
def login():
    authorization_url = f'{CMU_OAUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}'
    return redirect(authorization_url)

@app.route('/auth/cmu/callback')
def auth_callback():
    code = request.args.get('code')
    data = {
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code'
        }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        response = requests.post(TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        access_token = response.json().get('access_token')
        session['access_token'] = access_token
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        user_response = requests.get('https://misapi.cmu.ac.th/cmuitaccount/v1/api/cmuitaccount/basicinfo', headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()
        
        # เก็บชื่อและอีเมลใน session
        session['firstname'] = user_data.get('firstname_EN')
        session['email'] = user_data.get('cmuitaccount')  # เก็บ email ลงใน session
        
        email = user_data.get('cmuitaccount')
        
        # ย่อ Super_Admin เป็น S.Admin เพื่อให้สั้นเวลาแสดงตรง sidebar
        role = get_user_role(email)
        session['role'] = "S.Admin" if role == "Super_Admin" else role
        
        if is_admin(email):
            return redirect('/file') 

        return redirect("/api/basicinfo") 

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
      

@app.route('/api/basicinfo')
def get_basicinfo():
    access_token = session.get('access_token')
    print(f"Access Token: {access_token}")

    if not access_token:
        return redirect('/login')
    
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    try:
        response = requests.get('https://misapi.cmu.ac.th/cmuitaccount/v1/api/cmuitaccount/basicinfo', headers=headers)
        response.raise_for_status()
        user_data = response.json()
        print(f"User Data: {user_data}")

        if user_data.get('organization_name_EN') == 'Faculty of Science':
            if user_data.get('itaccounttype_EN') == 'Student Account':
                session['stu_id'] = user_data.get('student_id')
                session['firstname'] = user_data.get('firstname_EN').capitalize()
                session['lastname'] = user_data.get('lastname_EN').capitalize()
                session['email'] = user_data.get('cmuitaccount')

                return redirect('/homerequest')
            return redirect('/home')
        return jsonify(user_data)

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Helper function to check if email is in admin table
def is_admin(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin WHERE email = %s', (email,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()
        return admin is not None
    except Exception as e:
        print(f"Error checking admin email: {e}")
        return False

# Decorator to restrict access to certain routes for admins only
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = session.get('access_token')

        if not access_token:
            return redirect(url_for('login')) 

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get('https://misapi.cmu.ac.th/cmuitaccount/v1/api/cmuitaccount/basicinfo', headers=headers)
            response.raise_for_status()
            user_data = response.json()

            email = user_data.get('cmuitaccount')  

            if not is_admin(email):
                return abort(403)  

        except requests.exceptions.RequestException as e:
            return f"Error fetching user data: {e}"

        return f(*args, **kwargs)

    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = session.get('access_token')

        if not access_token:
            return redirect(url_for('login')) 

        return f(*args, **kwargs)

    return decorated_function

@app.route('/contact')
def contact():
    return render_template('temp/contact.html')

@app.route('/')
def homepage():
    return render_template('temp/homepage.html')

@app.route('/role')
@admin_required
def role():
    firstname = session.get('firstname')
    email = session.get('email')

    if not email:
        return "User not logged in", 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM admin WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            role = user[0]
        else:
            return "User not found", 404

        return render_template('temp/role.html', firstname=firstname, role=role)

    except Exception as e:
        print(f"Error fetching role: {e}")
        return "Internal Server Error", 500


@app.route('/stat')
@admin_required
def statistic():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Regular Students (ประเภทโปรเจกต์เป็น cs204499)
        cursor.execute('''
            SELECT COUNT(*) 
            FROM project p
            JOIN project_FileType pf ON p.projectID = pf.projectID
            JOIN file_Type ft ON pf.fileID = ft.fileID
            WHERE ft.file_type = '204499'
        ''')
        regular_students_count = cursor.fetchone()[0]
        print(f"Regular Students Count: {regular_students_count}")

        # Co-operative Education Students (ประเภทโปรเจกต์เป็น coOperative)
        cursor.execute('''
            SELECT COUNT(*) 
            FROM project p
            JOIN project_FileType pf ON p.projectID = pf.projectID
            JOIN file_Type ft ON pf.fileID = ft.fileID
            WHERE ft.file_type = 'Co-operative'
        ''')
        coop_students_count = cursor.fetchone()[0]
        print(f"Co-operative Education Students Count: {coop_students_count}")

        # ดึงจำนวนไฟล์ทั้งหมดที่อัปโหลดขึ้นระบบ
        cursor.execute('SELECT COUNT(*) FROM project')
        all_files_count = cursor.fetchone()[0]
        print(f"All Files Count: {all_files_count}")

        # อันดับสูงสุด 5 อันดับ
        cursor.execute("""
            SELECT c.categoryName, COUNT(*) as count 
            FROM Project_Category pc
            JOIN category c ON pc.categoryID = c.categoryID
            GROUP BY c.categoryName
            ORDER BY count DESC
            LIMIT 5
        """)
        top_categories = cursor.fetchall()
        print(f"Top Categories: {top_categories}")

        cursor.close()
        conn.close()

        # สร้างตัวแปรเพื่อเก็บข้อมูลสถิติ
        statistics = {
            "all_files_count": all_files_count,
            "regular_students_count": regular_students_count,
            "coop_students_count": coop_students_count,
            "top_categories": [{"name": category[0], "count": category[1]} for category in top_categories]
        }
        firstname = session.get('firstname')
        return render_template('temp/stat.html', statistics=statistics, firstname=firstname)

    except Exception as e:
        print(f"Error fetching statistics: {e}")
        abort(500, description="Internal Server Error while fetching statistics")


@app.route('/personal')
def personal():
    try:
        email = session.get('email')
        if not email:
            return redirect('/login')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT stu_id, firstname, lastname, email FROM student WHERE email = %s", (email,))
        student = cursor.fetchone()
        if student:
            stu_id = student[0]

            cursor.execute("SELECT projectID FROM project_student WHERE stu_id = %s", (stu_id,))
            project_id_row = cursor.fetchone()
            print(project_id_row)

            # ตรวจสอบว่าพบ project_id หรือไม่
            if project_id_row is None:
                project_id = None
            else:
                project_id = project_id_row[0]

            cursor.close()
            conn.close()

            return render_template(
                'temp/personal.html',
                stu_id=student[0],
                firstname=student[1],
                lastname=student[2],
                email=student[3],
                project_id=project_id  # ส่งค่า project_id หรือ None ไปยังเทมเพลต
            )
        else:
            abort(404, description="User not found")
    except Exception as e:
        return f"Error: {e}"



#folder
UPLOAD_FOLDER = '/flask_app/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ตรวจสอบว่าไฟล์มีนามสกุลที่อนุญาตหรือไม่
ALLOWED_EXTENSION = {'pdf','zip','docx','png','jpg','jpeg'}
def allowed_file(filename: str) -> bool:
     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSION 


@app.route('/project', methods=['GET', 'POST'])
def project():
    if request.method == 'POST':
        # Get the email from session
        email = session.get('email')  # Assuming you store the user's email in the session
        if not email:
            return jsonify({'error': 'User not authenticated'}), 401  # User must be logged in

        #Retrieve student ID using the email
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT stu_id FROM student WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result is None:
                return jsonify({'error': 'Student ID not found for the provided email'}), 404

            student_id = result[0]  # Retrieve the student ID
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()
            conn.close()

        # Check if there is a file in the request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']

        # Check if a file is selected
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Validate file type and save it
        if file and allowed_file(file.filename):
            filename = file.filename.encode('utf-8').decode('utf-8')  # บังคับใช้ UTF-8
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Get other form data
            project_name = request.form.get('project_name')
            year = request.form.get('academic_year')
            categoryName = request.form.get('category')
            degree = request.form.get('degree')          
            project_type = request.form.get('type')  
            instructor = request.form.get('instructor')
            description = request.form.get('abstract')

            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                # Check if the degree already exists
                cursor.execute("SELECT degreeID FROM degree WHERE degree = %s", (degree,))
                result = cursor.fetchone()
                if result is not None:
                    degree_id = result[0]  
                else:
                    # If not exist, insert new degree
                    cursor.execute("INSERT INTO degree (degree) VALUES (%s) RETURNING degreeID", (degree,))
                    degree_id = cursor.fetchone()[0]
                
                # Insert project data
                cursor.execute('''
                    INSERT INTO project (project_name, year, description, file_path)
                    VALUES (%s, %s, %s, %s) RETURNING projectID
                ''', (project_name, year, description, file_path))  
                project_id = cursor.fetchone()[0]

                # Link project and degree
                cursor.execute('''
                    INSERT INTO project_degree (projectID, degreeID) VALUES (%s, %s)
                ''', (project_id, degree_id))

                # Insert category
                cursor.execute("SELECT categoryID FROM category WHERE categoryName = %s", (categoryName,))
                result = cursor.fetchone()
                if result is not None:
                    category_id = result[0]  
                else:
                    cursor.execute("INSERT INTO category (categoryName) VALUES (%s) RETURNING categoryID", (categoryName,))
                    category_id = cursor.fetchone()[0]
                
                cursor.execute('''
                    INSERT INTO Project_Category (projectID, categoryID) VALUES (%s, %s)
                ''', (project_id, category_id))
                
                # Add project_student using retrieved student_id
                cursor.execute('''
                    INSERT INTO project_student (projectID, stu_id) VALUES (%s, %s)
                ''', (project_id, student_id))

                # Insert project type
                cursor.execute("SELECT fileID FROM file_Type WHERE file_type = %s", (project_type,))
                result = cursor.fetchone()
                if result is not None:
                    fileID = result[0]  
                else:
                    cursor.execute("INSERT INTO file_Type (file_type) VALUES (%s) RETURNING fileID", (project_type,))
                    fileID = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO project_FileType (projectID, fileID) VALUES (%s, %s)
                ''', (project_id, fileID))
                
                # Insert instructor
                cursor.execute("SELECT supervisorID FROM supervisor WHERE name = %s", (instructor,))
                result = cursor.fetchone()
                if result is not None:
                    supervisorID = result[0]  
                else:
                    cursor.execute("INSERT INTO supervisor (name) VALUES (%s) RETURNING supervisorID", (instructor,))
                    supervisorID = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO project_supervisor (projectID, supervisorID) VALUES (%s, %s)
                ''', (project_id, supervisorID))
                
                conn.commit()
                
                print("Data inserted successfully")
                encoded_project_id = encode_id(project_id)
                return jsonify({'success': True, 'message': 'File uploaded successfully', 'file_path': file_path,'encoded_project_id':encoded_project_id}), 201

            except Exception as e:
                conn.rollback()  # Rollback in case of error
                return jsonify({'success': False, 'error': str(e)}), 500

            finally:
                cursor.close()
                conn.close()

        return jsonify({'error': 'File type not allowed'}), 400

    # If GET method, show the upload form
    return render_template('temp/project.html')



@app.route('/check_edit_request_status')
def check_edit_request_status():
    # ต้องสร้างฟังก์ชันนี้ขึ้นเพื่อดึงข้อมูลจากฐานข้อมูล
    # เช่น สมมุติให้ status = 'approved' สำหรับทดสอบ
    status = get_request_status_from_db()  # ต้องมีการกำหนดฟังก์ชันนี้
    if status == 'approved':
        return jsonify({'approved': True})
    else:
        return jsonify({'approved': False})

def get_request_status_from_db():
    # ฟังก์ชันนี้ต้องทำการตรวจสอบฐานข้อมูลเพื่อดึงสถานะ
    # เช่น ค้นหาสถานะจากตารางที่เก็บคำขอแก้ไข
    return 'approved'  # เปลี่ยนกลับเป็นการดึงข้อมูลจริง


@app.route('/homerequest')
def homerequest():
    email = session.get('email')
    if not email:
        return redirect('/login')

    conn = get_db_connection()
    cursor = conn.cursor()

    project_id = None

    cursor.execute("SELECT stu_id FROM student WHERE email = %s", (email,))
    student = cursor.fetchone()

    if student is None:
        cursor.close()
        conn.close()
        return render_template('temp/homerequest.html', project_id=None)

    stu_id = student[0]
    print(f"Updating is_pending for stu_id: {stu_id}")
    # อัปเดต is_pending ให้เป็น FALSE สำหรับ student ที่กด request
    cursor.execute("""
        UPDATE student 
        SET is_pending = FALSE 
        WHERE stu_id = %s AND status = FALSE
    """, (stu_id,))
    conn.commit()

    cursor.execute("SELECT projectID FROM project_student WHERE stu_id = %s", (stu_id,))
    project_id_row = cursor.fetchone()

    cursor.close()
    conn.close()

    if project_id_row is None:
        project_id = None
    else:
        project_id = project_id_row[0]
    encoded_project_id = encode_id(project_id)  # ใช้ฟังก์ชันเข้ารหัส
    return render_template('temp/homerequest.html', project_id=encoded_project_id,stu_id=stu_id)

@app.route('/research')
def research():
    return render_template('temp/research.html')

@app.route('/myresearch/all', methods=['GET'])
def allmyresearch():
    
    email = session.get('email')
    if not email:
        return jsonify({'error': 'User not authenticated'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT stu_id FROM student WHERE email = %s", (email,))
    result = cursor.fetchone()
    conn.close()

    if result is None:
        return jsonify({'error': 'Student ID not found for the provided email'}), 404

    stu_id = result[0]
    return render_template('temp/allmyresearch.html', stu_id=stu_id)

@app.route('/api/projects/student/<int:student_id>', methods=['GET'])
def get_projects_by_student(student_id):
    # ดึงข้อมูลโปรเจกต์จากฐานข้อมูลตาม student_id
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
    SELECT 
        p.projectID, 
        p.project_name AS name, 
        p.description, 
        p.year, 
        d.degree AS degree, 
        string_agg(DISTINCT c.categoryName, ', ') AS categories, 
        string_agg(DISTINCT f.file_type, ', ') AS file_types, 
        string_agg(DISTINCT s.name, ', ') AS supervisors
    FROM 
        project p
    LEFT JOIN 
        project_student ps ON p.projectID = ps.projectID
    LEFT JOIN 
        student st ON ps.stu_id = st.stu_id
    LEFT JOIN 
        project_degree pd ON p.projectID = pd.projectID
    LEFT JOIN 
        degree d ON pd.degreeID = d.degreeID
    LEFT JOIN 
        project_category pc ON p.projectID = pc.projectID
    LEFT JOIN 
        category c ON pc.categoryID = c.categoryID
    LEFT JOIN 
        project_filetype pf ON p.projectID = pf.projectID
    LEFT JOIN 
        file_type f ON pf.fileID = f.fileID
    LEFT JOIN 
        project_supervisor psup ON p.projectID = psup.projectID
    LEFT JOIN 
        supervisor s ON psup.supervisorID = s.supervisorID
    WHERE 
        st.stu_id = %s
    GROUP BY 
        p.projectID, d.degree;
    """
    
    cursor.execute(query, (student_id,))
    projects = cursor.fetchall()  
    cursor.close()
    conn.close()
    
    # แปลงข้อมูลเป็นลิสต์ของ dictionary
    formatted_projects = []
    for row in projects:
        project_id = row[0]
        encoded_project_id = encode_id(project_id)  # ใส่ฟังก์ชันเข้ารหัส ID ที่คุณใช้อยู่
        formatted_projects.append({
            'encoded_project_id': encoded_project_id,
            'name': row[1],
            'description': row[2],
            'year': row[3],
            'degree': row[4],
            'categories': row[5],
            'file_types': row[6],
            'supervisors': row[7]
        })
        print(formatted_projects)
        
    
    return jsonify(formatted_projects)



# ฟังก์ชันเข้ารหัส ID ด้วย base64
def encode_id(id):
    encoded_bytes = base64.urlsafe_b64encode(str(id).encode("utf-8"))
    encoded_str = str(encoded_bytes, "utf-8")
    return encoded_str
# ฟังก์ชันถอดรหัส ID ด้วย base64
def decode_id(encoded_str):
    print(encoded_str)
    try:
        missing_padding = len(encoded_str) % 4
        if missing_padding:
            encoded_str += '=' * (4 - missing_padding) 
        # ถอดรหัส Base64
        decoded_bytes = base64.urlsafe_b64decode(encoded_str.encode("utf-8"))
        
        # แปลงเป็นสตริงและแปลงเป็นตัวเลข
        decoded_str = str(decoded_bytes, "utf-8")
        return int(decoded_str)  # แปลงเป็น integer
    except (ValueError, base64.binascii.Error) as e:
        # จัดการกรณีที่เกิดข้อผิดพลาดในการถอดรหัส
        app.logger.error(f"Error decoding base64 string: {str(e)}")
        return None

def generate_hashed_filename(filename):
    return hashlib.md5(filename.encode()).hexdigest()

@app.route('/readresearch/<encoded_project_id>')
def readresearch(encoded_project_id):
    # ถอดรหัส ID จาก URL
    print(encoded_project_id)
    try:
        project_id = decode_id(encoded_project_id)
        print(project_id)
    except Exception as e:
        return "Invalid encoded project ID", 400
    project = get_project_by_id(int(project_id))
    if project is None:
        return "Project not found", 404
    # สร้าง hash ของชื่อไฟล์
    original_filename = os.path.basename(project['file_path'])
    hashed_filename = generate_hashed_filename(original_filename)
    file_extension = project['file_path'].split('.')[-1].lower()
    is_pdf = file_extension == 'pdf'
    is_image = file_extension in ['png']
    is_document = file_extension in ['doc', 'docx']
    is_zip = file_extension == 'zip'
    # ส่งค่า hashed_filename และ encoded_project_id ไปยัง HTML template
    return render_template('temp/readresearch.html', 
                           project_name=project['name'], 
                           abstract=project['description'], 
                           category=project['category'], 
                           degree=project['degree'], 
                           type=project['file_types'], 
                           academicYear=project['year'], 
                           instructor=project['supervisors'], 
                           project_id=encoded_project_id,  # ส่ง ID ที่ถูกเข้ารหัส
                           hashed_filename=hashed_filename,  # ส่ง hashed filename
                           is_pdf=is_pdf,
                           is_image=is_image,
                           is_document=is_document,
                           is_zip=is_zip)

def get_project_by_id(project_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
    SELECT 
        p.project_name,
        p.description,
        ARRAY_AGG(DISTINCT c.categoryName) AS categories,
        ARRAY_AGG(DISTINCT d.degree) AS degrees,
        ARRAY_AGG(DISTINCT ft.file_type) AS file_types,
        ARRAY_AGG(DISTINCT sv.name) AS supervisors,
        p.year,
        p.file_path
    FROM 
        project p
    LEFT JOIN 
        project_Category pc ON p.projectID = pc.projectID
    LEFT JOIN 
        category c ON pc.categoryID = c.categoryID
    LEFT JOIN 
        project_degree pd ON p.projectID = pd.projectID
    LEFT JOIN 
        degree d ON pd.degreeID = d.degreeID
    LEFT JOIN 
        project_FileType pf ON p.projectID = pf.projectID
    LEFT JOIN 
        file_Type ft ON pf.fileID = ft.fileID
    LEFT JOIN 
        project_supervisor ps ON p.projectID = ps.projectID
    LEFT JOIN 
        supervisor sv ON ps.supervisorID = sv.supervisorID
    WHERE 
        p.projectID = %s
    GROUP BY 
        p.projectID;
    """
    cursor.execute(query, (project_id,))
    project = cursor.fetchone()
    cursor.close()
    conn.close()
    if project:
        print('file_path',project[7])
        return {
            'name': project[0],  # project_name        
            'description': project[1],  # description
            'category': ', '.join(project[2]) if project[2] else '',  # categories as string
            'degree': ', '.join(project[3]) if project[3] else '',  # degrees as string
            'file_types': ', '.join(project[4]) if project[4] else '',  # file_types as string
            'supervisors': ', '.join(project[5]) if project[5] else '',  # supervisors as string
            'year': project[6],  # year
            'file_path': project[7]  # file_path
        }
    else:
        return None

@app.route('/uploads/<encoded_project_id>/<hashed_filename>')
def research_file(encoded_project_id, hashed_filename):
    # ถอดรหัส project_id จาก URL
    try:
        project_id = decode_id(encoded_project_id)
    except Exception as e:
        return "Invalid encoded project ID", 400

    # ค้นหาไฟล์จาก project_id
    project = get_project_by_id(int(project_id))
    if project is None:
        return "Project not found", 404

    original_filename = os.path.basename(project['file_path'])

    # สร้าง hash ของชื่อไฟล์เพื่อเปรียบเทียบ
    hashed_original = generate_hashed_filename(original_filename)

    # ตรวจสอบว่า hash ที่สร้างตรงกับ hash ที่ได้รับจาก URL หรือไม่
    if hashed_original != hashed_filename:
        return "File not found", 404

    uploads_dir = os.path.join(app.root_path, '../uploads')
    return send_from_directory(uploads_dir, original_filename)


@app.route('/file', methods=['GET'])
@admin_required
def filemanagement():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT p.projectID, p.project_name, p.expire_after, ps.stu_id, p.year, c.categoryName 
            FROM project p
            LEFT JOIN project_student ps ON p.projectID = ps.projectID
            LEFT JOIN Project_Category pc ON p.projectID = pc.projectID
            LEFT JOIN category c ON pc.categoryID = c.categoryID
        """)
        files = cursor.fetchall()
        cursor.close()
        conn.close()

        file_list = []
        for file in files:
            file_list.append({
                'projectID': file[0],
                'project_name': file[1],
                'expire_after': file[2],
                'studentID': file[3],
                'year': file[4],
                'category': file[5]
            })    
        firstname = session.get('firstname')
        return render_template('temp/file.html', files=file_list, firstname=firstname)

    except Exception as e:
        print(f"Error connecting to database: {e}")
        abort(500, description="An error occurred while fetching the data.")



import os

@app.route('/api/projects/<int:id>', methods=['DELETE'])
def delete_project(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the project exists in the database
        cursor.execute('SELECT file_path FROM project WHERE projectID = %s', (id,))
        project = cursor.fetchone()
        if not project:
            return jsonify({'error': 'Project not found'}), 404

        file_path = project[0]
        uploads_dir = os.path.join(app.root_path, '../uploads')

        # First delete related records in project_student and other related tables
        cursor.execute('DELETE FROM project_student WHERE projectID = %s', (id,))
        cursor.execute('DELETE FROM project_degree WHERE projectID = %s', (id,))
        cursor.execute('DELETE FROM project_filetype WHERE projectID = %s', (id,))
        cursor.execute('DELETE FROM project_supervisor WHERE projectID = %s', (id,))
        cursor.execute('DELETE FROM project_category WHERE projectID = %s', (id,))

        # Now delete the project from the project table
        cursor.execute('DELETE FROM project WHERE projectID = %s', (id,))
        conn.commit()

        # Attempt to delete the file from the uploads directory
        if file_path:
            full_file_path = os.path.join(uploads_dir, file_path)
            if os.path.exists(full_file_path):
                os.remove(full_file_path)  # Delete the file
                print(f"Deleted file: {full_file_path}")
            else:
                print(f"File not found: {full_file_path}")

        return jsonify({'message': 'Project and associated file deleted successfully'}), 200

    except Exception as e:
        print(f"Error deleting project: {e}")
        return jsonify({'error': 'Internal Server Error while deleting project'}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/admin_send_request', methods=['POST'])
def admin_send_request():
    stu_id = session.get('stu_id')
    firstname = session.get('firstname')
    lastname = session.get('lastname')
    email = session.get('email')
    if not email:
        return jsonify({'message': 'User not logged in'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # อัปเดตสถานะของ student เป็น "FALSE" เพื่อบันทึกคำร้อง
        cursor.execute("""
            INSERT INTO student (stu_id, firstname, lastname, email, status)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (stu_id) DO UPDATE SET status = FALSE
        """, (stu_id, firstname, lastname, email, False))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'message': 'Request received successfully!'}), 200

    except Exception as e:
        print(f"Error sending request: {e}")
        return jsonify({'message': 'Internal Server Error while sending request'}), 500


@app.route('/check_status', methods=['GET'])
def check_status():
    email = session.get('email')
    if not email:
        return jsonify({'message': 'User not logged in'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ดึงสถานะของนักศึกษา
        cursor.execute('SELECT status FROM student WHERE email = %s', (email,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result:
            status = result[0]
            return jsonify({'approved': status}), 200

        return jsonify({'message': 'Student not found'}), 404

    except Exception as e:
        print(f"Error checking status: {e}")
        return jsonify({'message': 'Internal Server Error while checking status'}), 500

@app.route('/submit_project', methods=['POST'])
def submit_project():
    # รับข้อมูลจากฟอร์ม
    project_name = request.form.get('project_name')
    category = request.form.get('category')
    degree = request.form.get('degree')
    type = request.form.get('type')
    instructor = request.form.get('instructor')
    abstract = request.form.get('abstract')
    file = request.files.get('file')

    # ตรวจสอบว่าข้อมูลได้รับครบถ้วนและบันทึกข้อมูล
    if project_name and category and degree and type and instructor and abstract and file:
        return jsonify({'success': True})
    else:
        # ส่งกลับถ้าเกิดข้อผิดพลาด
        return jsonify({'success': False})


@app.route('/access', methods=['GET'])
@admin_required
def access():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()  
        
        cursor.execute('SELECT stu_id, email FROM student WHERE status = FALSE AND is_pending = FALSE')
        students = cursor.fetchall()
        cursor.close()
        conn.close()

        stu_list = [{'stu_id': stu[0], 'email': stu[1]} for stu in students]
        firstname = session.get('firstname', 'Admin')

        if students:
            for student in stu_list:
                message = f"New student request: {student['stu_id']} Email: {student['email']}"
                broadcast_line_notification(message)
                # ส่งข้อมูลไปยังไคลเอนต์ผ่าน WebSocket
                socketio.emit('new_student', {'stu_id': student['stu_id'], 'email': student['email']})

        return render_template('temp/access.html', students=stu_list, firstname=firstname)

    except Exception as e:
        print(f"Error connecting to database: {e}")
        abort(500, description="Internal Server Error while fetching data")

    except Exception as e:
        print(f"Error connecting to database: {e}")
        abort(500, description="Internal Server Error while fetching data")

@app.route('/delete_student/<int:stu_id>', methods=['DELETE'])
def delete_student(stu_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM student WHERE stu_id = %s', (stu_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        print(f"Error deleting student: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# ฟังก์ชันอนุมัตินักศึกษา (Approve)
@app.route('/approve_student/<int:stu_id>', methods=['PUT'])
def approve_student(stu_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # เปลี่ยนสถานะของนักศึกษาเป็น True เพื่ออนุมัติ
        cursor.execute('UPDATE student SET status = TRUE WHERE stu_id = %s', (stu_id,))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Student approved successfully'}), 200

    except Exception as e:
        print(f"Error approving student: {e}")
        return jsonify({'status': 'error', 'message': 'Internal Server Error while approving student'}), 500

# ฟังก์ชันยกเลิกนักศึกษา (Cancel)
@app.route('/cancel_student/<int:stu_id>', methods=['PUT'])
def cancel_student(stu_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # เปลี่ยนสถานะของนักศึกษาเป็น False เพื่อยกเลิกการอนุมัติ
        cursor.execute('UPDATE student SET status = FALSE WHERE stu_id = %s', (stu_id,))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Student request cancelled successfully'}), 200

    except Exception as e:
        print(f"Error cancelling student: {e}")
        return jsonify({'status': 'error', 'message': 'Internal Server Error while cancelling student'}), 500

#database
def get_db_connection():
    try:
        conn = psycopg2.connect(
            database="project", 
            user="hello_flask", 
            password="hello_flask", 
            host="db", 
            port="5432"
        )
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        abort(500, description="Database connection failed")

@app.route('/users', methods=['GET'])
def get_users():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, role, email FROM admin")
        users = cur.fetchall()
        cur.close()
        conn.close()

        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'role': user[1],
                'email': user[2]
            })

        return jsonify(user_list)
    except Exception as e:
        print(f"Error fetching users: {e}")
        abort(500, description="Internal Server Error while fetching users")

@app.route('/api/users', methods=['POST'])
def add_admin():
    data = request.json
    role = data.get('role')
    email = data.get('email')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO admin (role, email) VALUES (%s, %s) RETURNING id', (role, email))
        new_id = cursor.fetchone()[0]
        if new_id is None:
            raise ValueError("Failed to retrieve the new ID.")
        conn.commit()
        return jsonify({'message': 'Admin added successfully', 'id': new_id}), 201

    except Exception as e:
        conn.rollback()
        print(f"Error: {e}")
        return jsonify({'error': 'Failed to add admin', 'details': str(e)}), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/fetch_pending_students', methods=['GET'])
def fetch_pending_students():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ดึงข้อมูลนักเรียนที่ยังไม่ได้รับการอนุมัติ (status = FALSE)
        cursor.execute('SELECT stu_id, email FROM student WHERE status = FALSE')
        students = cursor.fetchall()
        cursor.close()
        conn.close()

        stu_list = [{'stu_id': stu[0], 'email': stu[1]} for stu in students]
        return jsonify(stu_list), 200
    
    except Exception as e:
        print(f"Error fetching pending students: {e}")
        return jsonify({'message': 'Internal Server Error while fetching students'}), 500

    
@app.route('/api/users/<int:id>', methods=['PUT'])
def update_user(id):
    data = request.json
    role = data.get('role')
    email = data.get('email')

    if not role or not email:
        return jsonify({'error': 'Role and email are required fields'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin WHERE id = %s', (id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        cursor.execute('UPDATE admin SET role = %s, email = %s WHERE id = %s', (role, email, id))
        conn.commit()
        return jsonify({'message': 'User updated successfully', 'role': role, 'email': email})

    except Exception as e:
        print(f"Error updating user: {e}")
        abort(500, description="Internal Server Error while updating user")
    finally:
        cursor.close()
        conn.close()

@app.route('/api/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin WHERE id = %s', (id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        cursor.execute('DELETE FROM admin WHERE id = %s', (id,))
        conn.commit()
        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        print(f"Error deleting user: {e}")
        abort(500, description="Internal Server Error while deleting user")
    finally:
        cursor.close()
        conn.close()



app.before_request
def make_session_permanent_and_check():
    session.permanent = True
    session.modified = True
    
    if request.endpoint not in ['login', 'auth_callback', 'static', 'homepage']:
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('homepage'))

@app.route('/crash')
def crash():
    return 1/0


# ใช้ดึงroleมาแสดงตรงsidebar
def get_user_role(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM admin WHERE email = %s', (email,))
        role = cursor.fetchone()
        cursor.close()
        conn.close()
        return role[0] if role else "User"
    except Exception as e:
        print(f"Error fetching user role: {e}")
        return "User"

@app.route('/api/projects', methods=['GET'])
def fetch_projects():
    projects = get_projects()  
    return jsonify(projects)  


def get_projects():
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
    SELECT 
        p.project_name,
        p.description,
        p.year,
        ARRAY_AGG(DISTINCT d.degree) AS degrees, 
        ARRAY_AGG(DISTINCT c.categoryName) AS categories,
        ARRAY_AGG(DISTINCT ft.file_type) AS file_types,
        ARRAY_AGG(DISTINCT sv.name) AS supervisors,
        p.projectID
    FROM 
        project p
    LEFT JOIN 
        project_degree pd ON p.projectID = pd.projectID
    LEFT JOIN 
        degree d ON pd.degreeID = d.degreeID
    LEFT JOIN 
        project_Category pc ON p.projectID = pc.projectID
    LEFT JOIN 
        category c ON pc.categoryID = c.categoryID
    LEFT JOIN 
        project_FileType pf ON p.projectID = pf.projectID
    LEFT JOIN 
        file_Type ft ON pf.fileID = ft.fileID
    LEFT JOIN 
        project_supervisor ps ON p.projectID = ps.projectID
    LEFT JOIN 
        supervisor sv ON ps.supervisorID = sv.supervisorID
    GROUP BY 
        p.projectID;
    """
    
    cursor.execute(query)
    projects = cursor.fetchall()
    
    project_list = []
    for project in projects:
        # เข้ารหัส projectID ก่อนส่งกลับ
        encoded_project_id = encode_id(project[7])  # ใช้ encode_id() ที่คุณสร้างไว้
        project_dict = {
            'name': project[0],
            'description': project[1],
            'year': project[2],
            'degree': project[3] if project[3] else [],
            'categories': project[4] if project[4] else [],
            'file_types': project[5] if project[5] else [],
            'supervisors': project[6] if project[6] else [],
            'encoded_project_id': encoded_project_id  # ส่งค่า ID ที่ถูกเข้ารหัสไป
        }
        project_list.append(project_dict)
    
    cursor.close()
    conn.close()
    return project_list


@app.route('/adminuploads', methods=['GET', 'POST'])
def adminuploads():
    if request.method == 'POST':

        # Check if there is a file in the request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']

        # Check if a file is selected
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Validate and save it
        if file and allowed_file(file.filename):
            filename = file.filename.encode('utf-8').decode('utf-8')  # บังคับใช้ UTF-8
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            
            firstName = request.form.get('firstName')
            lastName = request.form.get('lastName')
            student_id = request.form.get('student_id')
            email = request.form.get('email')
            project_name = request.form.get('project_name')
            year = request.form.get('academic_year')
            categoryName = request.form.get('category')
            degree = request.form.get('degree')          
            project_type = request.form.get('type')  
            instructor = request.form.get('instructor')
            description = request.form.get('abstract')

            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO student (stu_id, firstname, lastname, email)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (stu_id) DO NOTHING;
                ''', (student_id, firstName, lastName, email))

                
                # Check if the degree already exists
                cursor.execute("SELECT degreeID FROM degree WHERE degree = %s", (degree,))
                result = cursor.fetchone()
                if result is not None:
                    degree_id = result[0]  
                else:
                    # If not exist, insert new degree
                    cursor.execute("INSERT INTO degree (degree) VALUES (%s) RETURNING degreeID", (degree,))
                    degree_id = cursor.fetchone()[0]
                
                # Insert project data
                cursor.execute('''
                    INSERT INTO project (project_name, year, description, file_path)
                    VALUES (%s, %s, %s, %s) RETURNING projectID
                ''', (project_name, year, description, file_path))  
                project_id = cursor.fetchone()[0]

                # Link project and degree
                cursor.execute('''
                    INSERT INTO project_degree (projectID, degreeID) VALUES (%s, %s)
                ''', (project_id, degree_id))

                # Insert category
                cursor.execute("SELECT categoryID FROM category WHERE categoryName = %s", (categoryName,))
                result = cursor.fetchone()
                if result is not None:
                    category_id = result[0]  
                else:
                    cursor.execute("INSERT INTO category (categoryName) VALUES (%s) RETURNING categoryID", (categoryName,))
                    category_id = cursor.fetchone()[0]
                
                cursor.execute('''
                    INSERT INTO Project_Category (projectID, categoryID) VALUES (%s, %s)
                ''', (project_id, category_id))
                
                # Add project_student using retrieved student_id
                cursor.execute('''
                    INSERT INTO project_student (projectID, stu_id) VALUES (%s, %s)
                ''', (project_id, student_id))

                # Insert project type
                cursor.execute("SELECT fileID FROM file_Type WHERE file_type = %s", (project_type,))
                result = cursor.fetchone()
                if result is not None:
                    fileID = result[0]  
                else:
                    cursor.execute("INSERT INTO file_Type (file_type) VALUES (%s) RETURNING fileID", (project_type,))
                    fileID = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO project_FileType (projectID, fileID) VALUES (%s, %s)
                ''', (project_id, fileID))
                
                # Insert instructor
                cursor.execute("SELECT supervisorID FROM supervisor WHERE name = %s", (instructor,))
                result = cursor.fetchone()
                if result is not None:
                    supervisorID = result[0]  
                else:
                    cursor.execute("INSERT INTO supervisor (name) VALUES (%s) RETURNING supervisorID", (instructor,))
                    supervisorID = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO project_supervisor (projectID, supervisorID) VALUES (%s, %s)
                ''', (project_id, supervisorID))
                
                cursor.execute('''
                    INSERT INTO student (stu_id, firstname, lastname, email, status, is_pending)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (stu_id) DO UPDATE SET status = TRUE, is_pending = TRUE
                ''', (student_id, firstName, lastName, email, True, True))
                
                conn.commit()
                
                print("Data inserted successfully")

                return jsonify({'success': True, 'message': 'File uploaded successfully'}), 201

            except Exception as e:
                conn.rollback()  
                return jsonify({'success': False, 'error': str(e)}), 500

            finally:
                cursor.close()
                conn.close()

        return jsonify({'error': 'File type not allowed'}), 400

    # If GET
    return render_template('temp/adminuploads.html')



def hash_id(project_id):
    project_id_str = str(project_id)
    hashed_id = hashlib.sha256(project_id_str.encode()).hexdigest()
    return hashed_id[:10]  # ใช้เพียง 10 ตัวแรกของ hash

@app.route('/api/projects/search', methods=['POST'])
def search_projects():
    data = request.get_json()
    print("Received data:", data)
    category = data.get('category')
    degree = data.get('degree')
    project_type = data.get('type')
    instructor = data.get('instructor')
    academic_year = data.get('academicYear')
    keyword = data.get('keyword')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # สร้าง Query สำหรับค้นหาข้อมูลที่ตรงกับฟิลเตอร์และคำค้นหา
        query = """
        SELECT p.project_name, p.description, c.categoryName, d.degree, ft.file_type, sv.name, p.year, p.projectID
        FROM project p
        LEFT JOIN Project_Category pc ON p.projectID = pc.projectID
        LEFT JOIN category c ON pc.categoryID = c.categoryID
        LEFT JOIN project_degree pd ON p.projectID = pd.projectID
        LEFT JOIN degree d ON pd.degreeID = d.degreeID
        LEFT JOIN project_FileType pf ON p.projectID = pf.projectID
        LEFT JOIN file_Type ft ON pf.fileID = ft.fileID
        LEFT JOIN project_supervisor ps ON p.projectID = ps.projectID
        LEFT JOIN supervisor sv ON ps.supervisorID = sv.supervisorID
        WHERE TRUE
        """
        
        params = []

        # กรองข้อมูลตามเงื่อนไขที่ผู้ใช้กรอกเข้ามา
        if category:
            query += " AND LOWER(c.categoryName) = LOWER(%s)"
            params.append(category)
        if degree:
            query += " AND LOWER(d.degree) =  LOWER(%s)"
            params.append(degree)
        if project_type:
            query += " AND LOWER(ft.file_type) =  LOWER(%s)"
            params.append(project_type)
        if instructor:
            query += " AND LOWER(sv.name) = %s"
            params.append(instructor)
        if academic_year:
            query += " AND p.year = %s"
            params.append(academic_year)
        if keyword:
            query += " AND (LOWER(p.project_name) LIKE %s OR LOWER(p.description) LIKE %s)"
            params.append(f"%{keyword}%")
            params.append(f"%{keyword}%")

        cursor.execute(query, params)
        projects = cursor.fetchall()

        project_list = []
        for project in projects:
            project_dict = {
                'name': project[0],
                'description': project[1],
                'categories': project[2],
                'degree': project[3],
                'file_types': project[4],
                'supervisors': project[5],
                'year': project[6],
                'encoded_project_id': hash_id(project[7])
            }
            project_list.append(project_dict)

        cursor.close()
        conn.close()
        print("Query being executed:", query)
        print("Parameters:", params)

        return jsonify(project_list)

    except Exception as e:
        print(f"Error searching projects: {e}")
        return jsonify({'error': 'Internal Server Error while searching projects'}), 500



def get_or_create_entry(cursor, table, key_column, value, return_column):
    """
    Get or create an entry in the specified table and return the desired column.
    """
    cursor.execute(f"SELECT {return_column} FROM {table} WHERE {key_column} = %s", (value,))
    result = cursor.fetchone()
    if result is None:
        cursor.execute(f"INSERT INTO {table} ({key_column}) VALUES (%s) RETURNING {return_column}", (value,))
        return cursor.fetchone()[0]
    return result[0]



@app.route('/api/myresearch/<encoded_project_id>', methods=['GET', 'POST'])
def myresearch(encoded_project_id):
    try:
        try:
            project_id = decode_id(encoded_project_id)  
            print(project_id)
        except Exception as e:
            return jsonify({'error': 'Invalid encoded project ID', 'details': str(e)}), 400

        # Ensure the user is logged in by checking if the email is in session
        email = session.get('email')
        if not email:
            return jsonify({'error': 'User not logged in. Please login to continue.'}), 401

        # Get admin status from session
        is_admin = session.get('is_admin', False)

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'GET':
            # Logic for GET request (fetch project data)
            if not project_id and not is_admin:
                cursor.execute("SELECT stu_id FROM student WHERE email = %s", (email,))
                student = cursor.fetchone()
                if student is None:
                    return "ไม่พบนักเรียนที่ตรงกับ email", 404
                stu_id = student[0]

                cursor.execute("SELECT projectID FROM project_student WHERE stu_id = %s", (stu_id,))
                project_id_row = cursor.fetchone()
                if project_id_row is None:
                    return jsonify({'error': 'Project not found for this student'}), 404
                project_id = project_id_row[0]

            # Fetching the project details
            cursor.execute("""
                SELECT 
                p.project_name, p.year, c.categoryName, d.degree, ft.file_type, s.name, p.description, p.file_path
                FROM project p
                LEFT JOIN Project_Category pc ON p.projectID = pc.projectID
                LEFT JOIN category c ON pc.categoryID = c.categoryID
                LEFT JOIN project_degree pd ON p.projectID = pd.projectID
                LEFT JOIN degree d ON pd.degreeID = d.degreeID
                LEFT JOIN project_supervisor ps ON p.projectID = ps.projectID
                LEFT JOIN supervisor s ON ps.supervisorID = s.supervisorID
                LEFT JOIN project_FileType pf ON p.projectID = pf.projectID
                LEFT JOIN file_Type ft ON pf.fileID = ft.fileID
                WHERE p.projectID = %s
            """, (project_id,))
            project = cursor.fetchone()

            if project is None:
                return "ไม่พบโปรเจกต์", 404

            cursor.execute("SELECT stu_id, firstname, lastname, email FROM student WHERE email = %s", (email,))
            student = cursor.fetchone()
            if student is None:
                return "ไม่พบนักเรียนที่ตรงกับ email", 404

            file_path = project[7]  # ค่าที่ดึงมาจากฐานข้อมูล
            if file_path:
                try:
                    file_path = file_path.encode('utf-8').decode('utf-8')  # แก้ Encoding ป้องกันชื่อไฟล์หาย
                except UnicodeDecodeError:
                    pass  # ถ้ามีปัญหากับ encoding ให้ข้ามไป

            file_name = os.path.basename(file_path) if file_path else None

            # Prepare data for rendering
            project_data = {
                'project_name': project[0],
                'academic_year': project[1],
                'category': project[2],
                'degree': project[3],
                'project_type': project[4],
                'instructor': project[5],
                'description': project[6],
                'file_path': os.path.basename(project[7])
            }
            
            student_data = {
                'stu_id': student[0],
                'firstname': student[1],
                'lastname': student[2],
                'email': student[3]
            }

            return render_template('temp/editmyresearch.html', project=project_data, student=student_data, project_id=encoded_project_id)
        
        elif request.method == 'POST':
            # Logic for POST request (update project data)
            if not email:
                return jsonify({'error': 'User not logged in. Please login to continue.'}), 401

            # Check if there is a file in the request
            file = request.files.get('file')
            ALLOWED_EXTENSION = {'pdf','zip','docx','png','jpg','jpeg'}

            def allowed_file(filename: str) -> bool:
                return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSION 

            # Handle file if present and allowed
            file_path = None
            if file and allowed_file(file.filename):
                filename = filename = file.filename.encode('utf-8').decode('utf-8')  #ใช้ UTF-8
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                flash('File uploaded successfully!', 'success')
            else:
                flash('No file uploaded or invalid file type.', 'error')
                
            # Get other form data
            project_name = request.form.get('project_name')
            year = request.form.get('academic_year')
            categoryName = request.form.get('category')
            degree = request.form.get('degree')
            project_type = request.form.get('type')
            instructor = request.form.get('instructor')
            description = request.form.get('abstract')

            # Log data received for debugging
            app.logger.info(f"Received project_name: {project_name}")
            app.logger.info(f"Received academic_year: {year}")
            app.logger.info(f"Received categoryName: {categoryName}")
            app.logger.info(f"Received degree: {degree}")
            app.logger.info(f"Received project_type: {project_type}")
            app.logger.info(f"Received instructor: {instructor}")
            app.logger.info(f"Received description: {description}")
            app.logger.info(f"Received file: {file.filename if file else 'No file'}")

            # Update project data in the database
            cursor.execute("""
                UPDATE project
                SET project_name = %s, year = %s, description = %s, file_path = %s
                WHERE projectID = %s
            """, (project_name, year, description, file_path, project_id))

            # Update or insert related fields: file_type, category, instructor, and degree
            # Update project_FileType
            cursor.execute("SELECT fileID FROM file_Type WHERE file_type = %s", (project_type,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("INSERT INTO file_Type (file_type) VALUES (%s) RETURNING fileID", (project_type,))
                file_id = cursor.fetchone()[0]
            else:
                file_id = result[0]
            cursor.execute("UPDATE project_FileType SET fileID = %s WHERE projectID = %s", (file_id, project_id))

            # Update Project_Category
            cursor.execute("SELECT categoryID FROM category WHERE categoryName = %s", (categoryName,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("INSERT INTO category (categoryName) VALUES (%s) RETURNING categoryID", (categoryName,))
                categoryID = cursor.fetchone()[0]
            else:
                categoryID = result[0]
            cursor.execute("UPDATE Project_Category SET categoryID = %s WHERE projectID = %s", (categoryID, project_id))

            # Update project_supervisor
            cursor.execute("SELECT supervisorID FROM supervisor WHERE name = %s", (instructor,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("INSERT INTO supervisor (name) VALUES (%s) RETURNING supervisorID", (instructor,))
                supervisorID = cursor.fetchone()[0]
            else:
                supervisorID = result[0]
            cursor.execute("UPDATE project_supervisor SET supervisorID = %s WHERE projectID = %s", (supervisorID, project_id))

            # Update project_degree
            cursor.execute("SELECT degreeID FROM degree WHERE degree = %s", (degree,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("INSERT INTO degree (degree) VALUES (%s) RETURNING degreeID", (degree,))
                degreeID = cursor.fetchone()[0]
            else:
                degreeID = result[0]
            cursor.execute("UPDATE project_degree SET degreeID = %s WHERE projectID = %s", (degreeID, project_id))

            # Commit the changes
            conn.commit()

            return jsonify({'success': True, 'message': 'Data updated successfully'}), 201

    except Exception as e:
        app.logger.error(f'Error occurred: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if 'cursor' in locals() and cursor is not None:
            cursor.close()
        if 'conn' in locals() and conn is not None:
            conn.close()



                
@app.route('/api/adminedit/<int:project_id>', methods=['GET', 'POST'])
def myresearch_admin(project_id):
    try:
        email = session.get('email')
        if not email:
            return redirect('/login')

        print(f"Email from session: {email}")

        conn = get_db_connection()
        cursor = conn.cursor()
        print(project_id)
        
        if request.method == 'GET':
            # ดึงรายละเอียดโปรเจกต์จากฐานข้อมูลตาม ID ของโปรเจกต์ที่ระบุ
            cursor.execute("""
                SELECT 
                p.project_name, p.year, c.categoryName, d.degree, ft.file_type, s.name, p.description, p.file_path
                FROM project p
                LEFT JOIN Project_Category pc ON p.projectID = pc.projectID
                LEFT JOIN category c ON pc.categoryID = c.categoryID
                LEFT JOIN project_degree pd ON p.projectID = pd.projectID
                LEFT JOIN degree d ON pd.degreeID = d.degreeID
                LEFT JOIN project_supervisor ps ON p.projectID = ps.projectID
                LEFT JOIN supervisor s ON ps.supervisorID = s.supervisorID
                LEFT JOIN project_FileType pf ON p.projectID = pf.projectID
                LEFT JOIN file_Type ft ON pf.fileID = ft.fileID
                WHERE p.projectID = %s
            """, (project_id,))
            project = cursor.fetchone()

            if project is None:
                return "ไม่พบโปรเจกต์", 404

            # ดึงข้อมูล student ที่เป็นเจ้าของ project_id
            cursor.execute("""
                SELECT st.stu_id, st.firstname, st.lastname, st.email 
                FROM student st
                JOIN project_student ps ON st.stu_id = ps.stu_id
                WHERE ps.projectID = %s
            """, (project_id,))
            student = cursor.fetchone()

            if student is None:
                return "ไม่พบนักเรียนที่ตรงกับโปรเจกต์นี้", 404

            # แปลงข้อมูลของโปรเจกต์ให้เป็น dictionary
            project_data = {
                'project_name': project[0],
                'academic_year': project[1],
                'category': project[2],
                'degree': project[3],
                'project_type': project[4],
                'instructor': project[5],
                'description': project[6],
                'file_path': os.path.basename(project[7])
            }

            # แปลงข้อมูลของนักเรียนให้เป็น dictionary
            student_data = {
                'stu_id': student[0],
                'firstname': student[1],
                'lastname': student[2],
                'email': student[3]
            }

            # ส่งข้อมูลไปยังเทมเพลตเพื่อการแก้ไข
            return render_template('temp/adminedit.html', project=project_data, student=student_data, project_id=project_id)

        elif request.method == 'POST':
            file = request.files.get('file')
            ALLOWED_EXTENSION = {'pdf','zip','docx','png','jpg','jpeg'}
            def allowed_file(filename: str) -> bool:
                return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSION 

            file_path = None
            if file and allowed_file(file.filename):
                filename = filename = file.filename.encode('utf-8').decode('utf-8')  #ใช้ UTF-8
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                flash('File uploaded successfully!', 'success')
            else:
                flash('No file uploaded or invalid file type.', 'error')

            project_name = request.form.get('project_name')
            year = request.form.get('academic_year')
            categoryName = request.form.get('category')
            degree = request.form.get('degree')
            project_type = request.form.get('type')
            instructor = request.form.get('instructor')
            description = request.form.get('abstract')
             # Log data received for debugging
            app.logger.info(f"Received project_name: {project_name}")
            app.logger.info(f"Received academic_year: {year}")
            app.logger.info(f"Received categoryName: {categoryName}")
            app.logger.info(f"Received degree: {degree}")
            app.logger.info(f"Received project_type: {project_type}")
            app.logger.info(f"Received instructor: {instructor}")
            app.logger.info(f"Received description: {description}")
            app.logger.info(f"Received file: {file.filename if file else 'No file'}")

            cursor.execute("""
                UPDATE project
                SET project_name = %s, year = %s, description = %s, file_path = %s
                WHERE projectID = %s
            """, (project_name, year, description, file_path, project_id))
           # ตรวจสอบว่ามี file_type อยู่ในตาราง file_Type หรือไม่
            cursor.execute("""
                SELECT fileID FROM file_Type WHERE file_type = %s
            """, (project_type,))
            result = cursor.fetchone()
            if result is None:
                # ถ้าไม่มี ให้เพิ่ม file_type ใหม่และรับ fileID ที่ถูกสร้างขึ้น
                cursor.execute("""
                    INSERT INTO file_Type (file_type) VALUES (%s) RETURNING fileID
                """, (project_type,))
                file_id = cursor.fetchone()[0]  # รับค่า fileID ที่ถูกสร้างขึ้น
            else:
                # ถ้ามีอยู่แล้ว ให้ใช้ fileID เดิม
                file_id = result[0]
            # ตอนนี้เรามี file_id แล้ว ทำการอัปเดต project_FileType
            cursor.execute("""
                UPDATE project_FileType
                SET fileID = %s
                WHERE projectID = %s
                """, (file_id, project_id))
            
            
            #categoryName
            cursor.execute("""
                SELECT categoryID FROM category WHERE categoryName = %s
            """, (categoryName,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("""
                    INSERT INTO category (categoryName) VALUES (%s) RETURNING categoryID
                """, (categoryName,))
                categoryID = cursor.fetchone()[0] 
            else:
                categoryID = result[0]
            #อัปเดต
            cursor.execute("""
                UPDATE Project_Category
                SET categoryID = %s
                WHERE projectID = %s
                """, (categoryID, project_id))
            
            
            #instructor
            cursor.execute("""
                SELECT supervisorID FROM supervisor WHERE name = %s
            """, (instructor,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("""
                    INSERT INTO supervisor (name) VALUES (%s) RETURNING supervisorID
                """, (instructor,))
                supervisorID = cursor.fetchone()[0] 
            else:
                supervisorID = result[0]
            #อัปเดต
            cursor.execute("""
                UPDATE project_supervisor
                SET supervisorID = %s
                WHERE projectID = %s
                """, (supervisorID, project_id))
            
            #degree
            cursor.execute("""
                SELECT degreeID FROM degree WHERE degree = %s
            """, (degree,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("""
                    INSERT INTO degree (degree) VALUES (%s) RETURNING degreeID
                """, (degree,))
                degreeID = cursor.fetchone()[0] 
            else:
                degreeID = result[0]
            #อัปเดต
            cursor.execute("""
                UPDATE project_degree
                SET degreeID = %s
                WHERE projectID = %s
                """, (degreeID, project_id))

            conn.commit()
            print("Data updated successfully")

            return jsonify({'success': True, 'message': 'Data updated successfully', 'file_path': file_path, 'project_id': project_id}), 201

    except Exception as e:
        app.logger.error(f'Error occurred: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if 'cursor' in locals() and cursor is not None:
            cursor.close()
        if 'conn' in locals() and conn is not None:
            conn.close()
            
