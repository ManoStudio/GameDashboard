# แก้รายละเอียด build หลังอัปโหลด

บัญชี admin และ dev สามารถเลือก project → Builds → เปิด build ที่ต้องการ → Edit build details เพื่อแก้ได้ทุกเวลา รวมถึง build เก่าหรือ build ที่เผยแพร่ live แล้ว

ช่องที่แก้ได้:

- Release tag
- Test Focus (หนึ่งรายการต่อบรรทัด)
- Test instructions
- Known Issues (หนึ่งรายการต่อบรรทัด)
- Release notes
- Save path hint และ Config path hint

กด Save details แล้วข้อมูลจะบันทึกกับ build เดิม และโหลดหน้ารายละเอียดใหม่ ถ้า Test Focus/ Known Issues เดิมอยู่ในหัวข้อ Markdown ของ release notes แบบที่หน้า upload สร้างไว้ ช่องแก้ไขจะดึงข้อมูลเดิมมาให้ เมื่อบันทึกจะอัปเดตทั้งหัวข้อใน notes และ testing metadata ที่ Launcher อ่าน

API สำหรับแก้รายละเอียด: `PATCH /api/builds/{buildId}/details` โดยใช้ session ของ admin/dev หรือ legacy admin Bearer token ตัวอย่าง body ที่แก้เฉพาะ Test Focus และวิธีทดสอบ:

```json
{
  "focus_areas": ["ทดสอบโหลด save เก่า", "ทดสอบ multiplayer หลัง reconnect"],
  "test_instructions": "1. โหลด save จาก build ก่อนหน้า\n2. ตรวจ inventory และ quest"
}
```

API รองรับ partial updates ฟิลด์ที่ไม่ส่งจะคงค่าเดิมไว้ ส่ง `""` หรือ `[]` ในฟิลด์รายการเพื่อเคลียร์ข้อมูล Version, build ID, channel, manifest, checksums และไฟล์ artifact ไม่อยู่ใน endpoint นี้ การเลือก channel ยังใช้ Release actions เหมือนเดิม

project API tokens ที่สร้างสำหรับ CI ใช้ได้เฉพาะ upload ตาม scope จึงไม่สามารถแก้ข้อมูลย้อนหลังผ่าน endpoint นี้

Launcher จะได้รับรายละเอียดใหม่เมื่อโหลด library/API ครั้งถัดไป ใน Launcher ปัจจุบันให้กด refresh หากยังเห็นข้อมูลเก่า

ฟีเจอร์นี้ใช้คอลัมน์ในฐานข้อมูลที่มีอยู่แล้ว ไม่ต้องเพิ่ม migration สำหรับการแก้รายละเอียด
