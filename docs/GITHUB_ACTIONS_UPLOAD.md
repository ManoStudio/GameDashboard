# Build เกมแล้วอัปโหลดเข้า GameDashboard ด้วย GitHub Actions

ตัวอย่างนี้ใช้ API ปัจจุบันของ GameDashboard: init → PUT ไฟล์ตรงเข้า R2 → complete บันทึก build ลง D1 ไม่ต้องแก้ Worker และไม่ต้องแจก R2 credentials ให้ repository ของเกม

## 1. เตรียมฝั่ง Dashboard

- สร้าง project ของเกมใน Dashboard ก่อน
- ใช้ project ID จาก URL `?project=project-...` หรือจาก `GET /api/projects` ไม่ใช่ชื่อเกมหรือ bundle ID
- Worker ต้องตั้ง `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` รวมทั้ง R2/D1 bindings และ migrations ตาม `CLOUDFLARE_SETUP.md` โดยต้องใช้ migration `0009_project_api_tokens.sql` สำหรับระบบ token ใหม่
- ลงชื่อเข้าใช้ Dashboard ด้วยบัญชี admin → เลือก project เกม → Settings → API tokens → ตั้งชื่อ เช่น `GitHub Windows build` เลือกช่องทางอัปโหลดและอายุ token → Create token
- คัดลอกค่า token ที่แสดงครั้งเดียวไปเก็บใน GitHub Secret `DASHBOARD_API_TOKEN` ของ repository เกมนั้น ไม่ต้องนำ token นี้ไปตั้งเป็น Worker secret
- สร้างหลาย token ในโปรเจกต์เดียวกันได้ เช่น แยก Windows/macOS หรือคนละ workflow และสร้าง token ของแต่ละโปรเจกต์แยกกัน
- token ใหม่ใช้ได้เฉพาะอัปโหลดให้ project ที่ผูกไว้และ channel ที่เลือก ไม่มีสิทธิ์จัดการ users, ลบ project/build หรือจัดการ token
- Worker secret `DASHBOARD_API_TOKEN` เดิมยังรองรับเพื่อให้ workflow เก่าใช้ต่อได้ แต่เป็น token กลางที่มีสิทธิ์ admin แนะนำเปลี่ยน workflow มาใช้ token จากหน้า Settings

## 2. เตรียม repository ของเกม

คัดลอกไฟล์สองไฟล์จาก GameDashboard:

| ไฟล์ต้นทาง | ตำแหน่งใน repository ของเกม |
| --- | --- |
| `examples/github-actions/build-and-upload.yml` | `.github/workflows/build-and-upload.yml` |
| `examples/github-actions/upload-game.mjs` | `tools/upload-game.mjs` |

ไปที่ Settings → Secrets and variables → Actions และเพิ่ม:

| ประเภท | ชื่อ | ค่า |
| --- | --- | --- |
| Variable | `GAME_DASHBOARD_URL` | `https://game.manostudio.app` (ไม่ต่อ `/api`) |
| Variable | `GAME_PROJECT_ID` | ID ของ project เกมที่สร้างแล้ว |
| Secret | `DASHBOARD_API_TOKEN` | ค่า token ที่สร้างจาก Settings → API tokens ของ project นี้ |

`DASHBOARD_API_TOKEN` เป็น token ของ Dashboard ไม่ใช่ `GITHUB_TOKEN`, GitHub PAT หรือ Cloudflare API token

## 3. ใส่ขั้นตอน build ของเกม

แก้ step `Build and package game` ใน YAML: เอา `throw` ออก และใส่ขั้นตอนติดตั้ง engine, เปิดใช้ license หากจำเป็น, build และสร้าง `artifacts/game-windows.zip` ใช้ engine/version/platform เดียวกับเกมของคุณ ถ้ามี workflow build อยู่แล้ว ให้เพิ่ม setup Node.js และ step upload ต่อท้าย หลังได้ ZIP สำเร็จใน job เดียวกัน

ZIP ต้องรวมเกมที่รันได้ทั้งหมด ไม่ใช่ source code หรือเฉพาะ EXE ตัวอย่าง Unity Windows:

```text
game-windows.zip
├── MyGame.exe
├── MyGame_Data/
├── UnityPlayer.dll
└── ไฟล์ runtime อื่นที่ engine สร้าง
```

Launcher ปัจจุบันดาวน์โหลดไฟล์หลักของ build เป็น ZIP แล้วแตกไฟล์ แนะนำส่ง ZIP เดียวรวม runtime ทั้งหมด

หาก build สำเร็จแล้วได้ไฟล์ใน `Build/Windows/` สามารถใช้ Python ที่ติดตั้งไว้ใน runner เพื่อแพ็ก ZIP ได้ ตัวอย่าง `tools/package-game.py`:

```python
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

source = Path("Build/Windows")
files = sorted(path for path in source.rglob("*") if path.is_file())
if not files:
    raise SystemExit("No game build files found in Build/Windows")
output = Path("artifacts/game-windows.zip")
output.parent.mkdir(parents=True, exist_ok=True)
with ZipFile(output, "w", ZIP_DEFLATED, allowZip64=True) as archive:
    for path in files:
        archive.write(path, path.relative_to(source))
```

เรียก `python tools/package-game.py` หลัง build; หาก runner ไม่มี Python ให้เพิ่ม `actions/setup-python` หรือใช้เครื่องมือ ZIP ของ build pipeline

## 4. การทำงานของสคริปต์ upload

ใช้ Node.js 24 โดยไม่ต้อง `npm install`:

```text
node tools/upload-game.mjs artifacts/game-windows.zip
```

1. ตรวจไฟล์และคำนวณ SHA-256 แบบอ่านเป็น stream
2. POST `/api/projects/{projectId}/uploads/init` ด้วย Bearer token และ JSON ของไฟล์/channel
3. รับ `build_id`, `version`, `uploads[0].upload_url`, `object_path`, `content_type`
4. PUT bytes ของ ZIP ไป URL ที่ได้รับ โดยใช้ Content-Type ตรงกับ session และไม่ส่ง Dashboard token ไป R2
5. เมื่อ PUT สำเร็จจึง POST `/api/projects/{projectId}/uploads/{buildId}/complete` พร้อมข้อมูลไฟล์, SHA-256, object_path และ metadata ของ GitHub

Dashboard เป็นผู้กำหนด version รูปแบบ `<project icon>-Build-<number>` ไม่ใช้ Git tag เป็น version; tag, commit SHA และ branch เก็บเป็น metadata

## 5. เริ่มใช้งาน

- commit สองไฟล์พร้อมขั้นตอน build ที่แก้แล้วลง repository ของเกม
- push `main` จะ build และอัปโหลด channel `dev`
- หรือเปิด Actions → Build game and upload to GameDashboard → Run workflow เลือก `dev`/`qa` ได้ เมื่อ workflow อยู่ใน default branch
- เมื่อสำเร็จ log จะมี build ID/version/channel และ build ปรากฏใน project นั้น ผู้ใช้ Launcher เห็น build ตามสิทธิ์และ channel
- ถ้า build กับ upload อยู่คนละ job ต้องถ่ายโอน ZIP ด้วย GitHub artifacts และ download ใน job upload ก่อนเรียกสคริปต์

## ตรวจปัญหา

- `401`: token ไม่มีหรือไม่ตรงกับ Worker
- `403` หรือ redirect/JSON error: ตรวจสิทธิ์ และ Cloudflare Access หากเปิดใช้กับโดเมนนี้ ตัวอย่างนี้ไม่ได้ใส่ Access service token headers
- `404`: ตรวจ URL และ project ID
- init `500`: ตรวจ R2 secrets และ D1 migrations ใน Worker logs
- R2 PUT ไม่สำเร็จ: ตรวจ R2 credentials/permissions และ Content-Type ให้ตรงกับค่าที่เซ็น URL

Signed upload URL มีอายุ 30 นาที สคริปต์จำกัด PUT ไว้ 25 นาที ไม่มี automatic retry ของ init/complete เพราะอาจจองเลขหรือสร้าง build เพิ่ม การรันใหม่จองเลขใหม่; upload ที่หยุดกลางทางอาจทิ้งไฟล์ใน R2 และทำให้เลข build ข้าม

สามารถ Revoke token ได้จาก Settings → API tokens การเรียก API ครั้งต่อไปจะถูกปฏิเสธทันที ส่วน signed R2 URL ที่ออกไปก่อน revoke ยังคงมีอายุไม่เกิน 30 นาที แต่ token ที่ถูก revoke ไม่สามารถ complete เพื่อบันทึก build ได้ เมื่อ token หมดอายุหรือสูญหาย ให้สร้างใหม่แล้วเปลี่ยนค่า GitHub Secret

ตัวอย่างผ่านการทดสอบด้วย transport จำลองและ API ของ Worker ในเครื่อง ระบบ project tokens ผ่านการทดสอบกับ workerd + D1/R2 ในเครื่อง ยังไม่ได้รัน GitHub Actions หรืออัปโหลดบน production

อ้างอิง GitHub: [Workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [Variables](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-variables), [Checkout](https://github.com/actions/checkout), [Setup Node.js](https://github.com/actions/setup-node)
## Upload queue

สคริปต์ `examples/github-actions/upload-game.mjs` เวอร์ชันปัจจุบันจะเข้าคิวของโปรเจกต์ก่อนส่ง ZIP ให้อัปเดตไฟล์ที่คัดลอกไปใช้ในแต่ละ repository เกม เพื่อให้เห็นและจัดลำดับ CI build ที่รออยู่ในหน้า **Upload queue** สคริปต์เก่ายังอัปโหลดได้ แต่จะแสดงเป็น legacy transfer ซึ่งจัดลำดับก่อนส่งไม่ได้ อ่านรายละเอียดได้ใน [Upload queue](UPLOAD_QUEUE.md)
