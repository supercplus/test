# Team02
เว็บไซต์ฐานข้อมูลผลงานนักศึกษา
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
# รายละเอียดเกี่ยวกับโฟลเดอร์และไฟล์ในโปรเจกต์
   1. หากต้องการเปลี่ยนพอร์ตของเว็บไซต์ ต้องแก้ในไฟล์ .env.dev ดังนี้
      ```bash
      DATABASE_PORT=<NEW_PORT>
      DATABASE_URL=postgresql://hello_flask:hello_flask@db:$DATABASE_PORT/project
      ```
      และ docker-compose.yml ดังนี้
      ```bash
      services:
        db:
          image: postgres
          ports:
            - "<NEW_PORT>:5432"  # เปลี่ยน <NEW_PORT> เป็นค่าที่คุณต้องการ
      ```
   2. รีสตาร์ทคอนเทนเนอร์เพื่อให้ค่าพอร์ตใหม่ทำงาน
      ```bash
      docker-compose down
      ```
      ```bash
      docker-compose up --build
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


