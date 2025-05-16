# Team02
เว็บไซต์ฐานข้อมูลผลงานนักศึกษา
# Tools and Technology
1. Flask (Python Web Framwork): ใช้เป็น framwork สำหรับสร้างเว็บแอปพลิเคชันเพื่อจัดการ routing, templating และการเชื่อมต่อกับฐานข้อมูล
2. PostgreSQL: ใช้เป็นฐานข้อมูลหลักสำหรับเก็บข้อมูลของโปรเจกต์
3. SQLAlchemy(ORM): ใช้จัดการการเชื่อมต่อและการดำเนินการกับฐานข้อมูล PostgreSQL ผ่าน db
4. JavaScript(Vanilla JS) and jQuery
5. HTML and CSS
# ขั้นตอนการติดตั้ง
1. ติดตั้ง Docker ลงเครื่อง
2. ใช้คำสั่งต่อไปนี้เพื่อโคลน Repository:
   ```bash
   git clone https://github.com/supercplus/website.git
   ```
3. เข้าไปที่โฟลเดอร์โปรเจกต์:
   ```bash
   cd website
   ```
4. ใช้คำสั่งเพื่อรัน Docker Compose:
   ```bash
   ./run_docker_compose.sh
   ```
5. เมื่อ Docker สร้างและรันคอนเทนเนอร์เสร็จแล้ว ให้เปิด Browser และพิมพ์:
   ```bash
   http://localhost:56733
   ```
# หากต้องการเปลี่ยนพอร์ตของเว็บไซต์
   1. main.py เปลี่ยนพอร์ตที่ Flask รันอยู่:
      ```bash
      if __name__ == '__main__':
         app.run(host='0.0.0.0', port=<NEW_PORT>)
      ```
   2. gunicorn_starter.sh แก้ไขพอร์ตของ Gunicorn:
      ```bash
      gunicorn main:app --chdir app -w 2 --threads 2 -b 0.0.0.0:<NEW_PORT>
      ```
   3. .env.dev เปลี่ยนค่าพอร์ตของฐานข้อมูล PostgreSQL (ถ้าจำเป็น):
      ```bash
      DATABASE_PORT=<NEW_DB_PORT>
      DATABASE_URL=postgresql://hello_flask:hello_flask@db:$DATABASE_PORT/project
      ```
   4. docker-compose.yml แก้ไขพอร์ตของ Flask และ PostgreSQL:
      ```
      services:
        flask:
          ports:
            - "<NEW_PORT>:8080"  # เปลี่ยน <NEW_PORT> เป็นค่าที่ต้องการ
          environment:
            FLASK_RUN_PORT: <NEW_PORT>

        db:
          ports:
            - "<NEW_DB_PORT>:5432"  # เปลี่ยน <NEW_DB_PORT> เป็นพอร์ตของ PostgreSQL
      ```
   5. build_docker.sh แก้ไขพอร์ตของ Docker:
      ```
      docker run -p <NEW_PORT>:8080 -d \
      ```
   6. รีสตาร์ท Docker เพื่อใช้ค่าพอร์ตใหม่
      ```
      docker-compose down
      ```
      ```
      docker-compose up --build
      ```
   7. จากนั้นลองเข้าผ่าน:
      ```
      http://localhost:<NEW_PORT>/
      ```
# User and Password ของ Database อยู่ในไฟล์ docker-compose.yml
   ```
   environment:
      - POSTGRES_USER=hello_flask
      - POSTGRES_PASSWORD=hello_flask
      - POSTGRES_DB=project
   ```
# การเพิ่ม Super Admin
1. เข้าไฟล์ flask-app1_db_1.session.sql จากนั้นใส่ข้อมูล ดังตัวอย่าง
   ```
   -- INSERT INTO admin (id, role, email)
   -- VALUES (1,
   --     'Super_Admin',
   --     'tanom.k@cmu.ac.th'
   --   );
   ```



