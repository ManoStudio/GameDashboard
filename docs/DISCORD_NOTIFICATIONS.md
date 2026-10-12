# แจ้งเตือน upload build เสร็จผ่าน Discord

ระบบแจ้งเตือนอยู่ใน GameDashboard Worker ใช้ได้ทั้งการอัปโหลดจากหน้าเว็บและ GitHub Actions workflow เดิม ไม่ต้องเพิ่ม Discord step หรือ Discord Secret ใน GitHub

## เปิดใช้งาน

1. สร้าง Incoming Webhook ใน Discord channel ปลายทาง แล้วคัดลอก webhook URL ดู [Discord Intro to Webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)
2. ลงชื่อเข้า GameDashboard ด้วยบัญชี admin เลือก project → Settings → Discord notifications
3. วาง URL เลือก Enable build upload notifications และเลือก channel ของ build ที่ต้องการแจ้ง เช่น dev/qa/live
4. กด Save notifications แล้วกด Send test message เพื่อตรวจการเชื่อมต่อ

แต่ละ project เก็บ webhook ของตัวเอง เปลี่ยน URL ได้โดยวาง URL ใหม่และ Save ปล่อยช่อง URL ว่างเพื่อเก็บค่าเดิม ปิด Enable เพื่อหยุดส่งโดยเก็บ URL ไว้ หรือกด Remove webhook เพื่อลบการตั้งค่าทั้งหมด

URL ที่รองรับคือ HTTPS Discord incoming webhook (`discord.com/api/webhooks/{id}/{token}` และรูปแบบที่มี API version) รองรับ URL เดิมจาก discordapp.com โดยใช้ปลายทาง discord.com ถ้าใช้ forum/thread ให้เติม `?thread_id={threadId}` ตาม [Discord webhook API](https://docs.discord.com/developers/resources/webhook#execute-webhook)

## เมื่ออัปโหลดสำเร็จ

Worker เริ่มส่งหลังสร้าง build ใน D1 และจบ upload session แล้วเท่านั้น ข้อความมีชื่อ project, version, upload channel, จำนวนไฟล์/ขนาด, tag/branch/commit หากมี, release notes แบบย่อ และลิงก์เปิด build บน Dashboard

ชื่อผู้ส่งคือ **ManoBuild Reporter** ทั้งข้อความจริงและ test ใช้ Discord embed การ์ดแบบเดียวกัน: แถบสีม่วง หัวข้อเวอร์ชันที่กดเปิด build ได้ Project เป็นลิงก์ ช่อง Channel/Package และ Branch/Commit/Tag เมื่อมีข้อมูล หัวข้อและรายการใน release notes จัดรูปแบบให้อ่านง่าย ส่วน footer แสดงว่าเป็น Upload complete หรือ Test message พร้อมเวลาส่ง

Send test message ใช้ข้อมูล build ล่าสุดของ project เพื่อดูหน้าตาข้อความจริงได้ โดยมีป้าย Test message ชัดเจน และไม่สร้าง build/จองเลขเวอร์ชันเพิ่ม ถ้า project ยังไม่มี build จะเป็นการ์ด Preview ที่ลิงก์ไปหน้า Builds

ใช้ `ctx.waitUntil()` ส่งหลังตอบ upload ได้ และตั้ง timeout 8 วินาที Discord หรือฐานข้อมูลสถานะแจ้งเตือนล้มเหลวจะไม่เปลี่ยนผล upload ที่เสร็จแล้วเป็น error การตั้งค่านี้เป็น best effort ไม่มี automatic retry ที่อาจสร้างข้อความซ้ำ หาก Discord ไม่รับข้อความ ให้ดูสถานะครั้งล่าสุดใน Settings หรือ Worker logs แล้วกด Send test message เพื่อตรวจ URL

การแก้ build details ภายหลัง เปลี่ยน channel หรือ rollback ไม่ส่งข้อความ upload ใหม่ ลิงก์ในข้อความจะเปิดรายละเอียดล่าสุดของ build

## การเก็บ webhook URL

URL มี credential สำหรับส่งข้อความ จึงเก็บในตาราง D1 `project_discord_webhooks` แยกจากข้อมูล project/Launcher ไม่ส่ง URL กลับจาก API ไม่เติมลงในฟอร์ม และไม่ใส่ใน logs หรือข้อความ Discord ผู้ที่เข้าถึงฐานข้อมูลโดยตรงยังอ่านค่าได้ จำกัดสิทธิ์ D1 ตามการใช้งาน

เฉพาะ admin ที่ลงชื่อเข้าใช้ผ่าน session เท่านั้นที่ตั้งค่าและส่งข้อความทดสอบได้ API tokens ของ CI ไม่มีสิทธิ์อ่านหรือแก้ webhook ข้อความปิด automatic mentions เพื่อป้องกันข้อความใน changelog ทำให้เกิด ping ที่ไม่ตั้งใจ

## Deploy

Apply migration `0010_project_discord_webhooks.sql` ก่อน deploy Worker:

```powershell
npx wrangler d1 migrations apply game-dashboard-db --remote
npm run deploy
```

คำสั่งนี้ apply migrations ที่ยังไม่ได้ทำตามลำดับ รวม `0009_project_api_tokens.sql` หากยังไม่ได้ apply ตรวจ target account/Worker ใน `wrangler.toml` ก่อนรัน

ทดสอบด้วย SQLite และ Workers runtime/D1/R2 ในเครื่อง โดยจับ outbound request จำลอง ไม่มีการส่งข้อความไป Discord จริงระหว่างทดสอบ
