# Team02
เว็บไซต์ฐานข้อมูลผลงานนักศึกษา
# ขั้นตอนการติดตั้ง
1. ติดตั้ง Docker ลงเครื่อง
2. ใช้คำสั่งต่อไปนี้เพื่อโคลน Repository:
   git clone https://github.com/supercplus/website.git
3. เข้าไปที่โฟลเดอร์โปรเจกต์:
   cd website
4. ใช้คำสั่งเพื่อรัน Docker Compose:
   ./run_docker_compose.sh
5. เมื่อ Docker สร้างและรันคอนเทนเนอร์เสร็จแล้ว ให้เปิด Browser และพิมพ์:
   http://localhost:<PORT>
