import hashlib
import json
import os
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import firebase_admin
from google.api_core import exceptions as google_exceptions
from firebase_admin import credentials, firestore
from werkzeug.security import check_password_hash, generate_password_hash

# Try to load environment variables from a .env file for local development.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024
app.secret_key = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "change-me-in-vercel"

CHANNELS = ["dev", "qa", "live"]
ROLES = ["admin", "dev", "QA"]
USER_ROLES = ["admin", "dev", "QA", "viewer"]
BUILD_STATUSES = ["uploaded", "manifest-ready", "stored", "assigned"]
db = None
firebase_error = None
demo_projects = []
demo_builds = {}
demo_users = {}


def init_firebase():
    private_key_content = os.getenv("private_key", "").replace("\\n", "\n")
    cred_dict = {
        "type": os.getenv("type", ""),
        "project_id": os.getenv("project_id", ""),
        "private_key_id": os.getenv("private_key_id", ""),
        "private_key": private_key_content,
        "client_email": os.getenv("client_email", ""),
        "client_id": os.getenv("client_id", ""),
        "auth_uri": os.getenv("auth_uri", ""),
        "token_uri": os.getenv("token_uri", ""),
        "auth_provider_x509_cert_url": os.getenv("auth_provider_x509_cert_url", ""),
        "client_x509_cert_url": os.getenv("client_x509_cert_url", ""),
    }

    if cred_dict.get("type") != "service_account":
        raise ValueError('Invalid service account certificate. "type" must be "service_account".')

    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)

    return firestore.client()


try:
    db = init_firebase()
except Exception as exc:
    firebase_error = str(exc)
    print(f"Failed to initialize Firebase with environment variables: {exc}")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def wants_json():
    return request.path.startswith("/api/") or "application/json" in request.headers.get("Accept", "")


def document_with_id(document):
    data = document.to_dict()
    data["id"] = document.id
    return data


def user_id_from_email(email):
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def normalize_role(role):
    return role if role in USER_ROLES else "viewer"


def bootstrap_admin_user():
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email or not password:
        return

    user_id = user_id_from_email(email)
    user = {
        "email": email,
        "role": "admin",
        "password_hash": generate_password_hash(password),
        "updated_at": now_iso(),
    }

    if db is None:
        demo_users.setdefault(user_id, {**user, "created_at": now_iso()})
        return

    ref = db.collection("users").document(user_id)
    if not ref.get().exists:
        user["created_at"] = now_iso()
        ref.set(user)


def get_user_by_email(email):
    user_id = user_id_from_email(email)
    if db is None:
        user = demo_users.get(user_id)
        return {**user, "id": user_id} if user else None

    snapshot = db.collection("users").document(user_id).get()
    if not snapshot.exists:
        return None
    return document_with_id(snapshot)


def list_users():
    if db is None:
        return sorted(
            ({**user, "id": user_id} for user_id, user in demo_users.items()),
            key=lambda user: user.get("email", ""),
        )

    users = db.collection("users").order_by("email").stream()
    return [document_with_id(user) for user in users]


def save_user(data):
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = normalize_role(data.get("role", "viewer"))
    if not email:
        raise ValueError("email is required")

    user_id = user_id_from_email(email)
    now = now_iso()
    user = {"email": email, "role": role, "updated_at": now}
    if password:
        user["password_hash"] = generate_password_hash(password)

    if db is None:
        existing = demo_users.get(user_id, {})
        if not existing and not password:
            raise ValueError("password is required for a new user")
        existing.update(user)
        existing.setdefault("created_at", now)
        demo_users[user_id] = existing
        return {**existing, "id": user_id}

    ref = db.collection("users").document(user_id)
    snapshot = ref.get()
    if not snapshot.exists and not password:
        raise ValueError("password is required for a new user")
    if not snapshot.exists:
        user["created_at"] = now
    ref.set(user, merge=True)
    saved = ref.get()
    return document_with_id(saved)


def get_token_user():
    token = os.getenv("DASHBOARD_API_TOKEN", "")
    header = request.headers.get("Authorization", "")
    if not token or not header.startswith("Bearer "):
        return None
    if header.removeprefix("Bearer ").strip() != token:
        return None
    return {"id": "api-token", "email": "api-token", "role": "admin"}


def current_user():
    token_user = get_token_user()
    if token_user:
        return token_user

    email = session.get("user_email")
    if not email:
        return None
    user = get_user_by_email(email)
    if not user:
        session.clear()
        return None
    return user


def has_role(*allowed_roles):
    user = current_user()
    return bool(user and user.get("role") in allowed_roles)


def can_assign_channel(role, channel):
    if role == "admin":
        return True
    if role == "dev":
        return channel in {"dev", "qa"}
    if role == "QA":
        return channel == "qa"
    return False


def unauthorized_response(status_code=401):
    if wants_json():
        return jsonify({"error": "unauthorized"}), status_code
    return redirect(url_for("login", next=request.full_path))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return unauthorized_response()
        return view(*args, **kwargs)

    return wrapped


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user():
                return unauthorized_response()
            if not has_role(*allowed_roles):
                if wants_json():
                    return jsonify({"error": "forbidden"}), 403
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def seed_projects():
    return [
        {
            "id": "project-demo-racer",
            "name": "Neon Drift",
            "icon": "ND",
            "bundle_id": "com.mano.neondrift",
            "role": "admin",
            "created_at": now_iso(),
        },
        {
            "id": "project-demo-arena",
            "name": "Sky Arena",
            "icon": "SA",
            "bundle_id": "com.mano.skyarena",
            "role": "dev",
            "created_at": now_iso(),
        },
    ]


def seed_builds(project_id):
    return [
        {
            "id": f"{project_id}-build-100",
            "project_id": project_id,
            "version": "1.0.0",
            "channel": "qa",
            "tag": "stable",
            "changelog": "Initial QA candidate",
            "status": "assigned",
            "file_count": 128,
            "total_size": 73400320,
            "storage_path": f"/{project_id}/{project_id}-build-100/files",
            "manifest_path": f"/{project_id}/{project_id}-build-100/manifest.json",
            "created_at": now_iso(),
        }
    ]


demo_projects = seed_projects()
demo_builds = {project["id"]: seed_builds(project["id"]) for project in demo_projects}
bootstrap_admin_user()


def list_projects():
    if db is None:
        return sorted(demo_projects, key=lambda project: project.get("created_at", ""), reverse=True)
    projects = db.collection("projects").order_by("created_at", direction=firestore.Query.DESCENDING).stream()
    return [document_with_id(project) for project in projects]


def get_project(project_id):
    if db is None:
        return next((project for project in demo_projects if project["id"] == project_id), None)
    snapshot = db.collection("projects").document(project_id).get()
    if not snapshot.exists:
        return None
    return document_with_id(snapshot)


def list_builds(project_id):
    if db is None:
        builds = demo_builds.get(project_id, [])
        return sorted(builds, key=lambda build: build.get("created_at", ""), reverse=True)
    query = db.collection("builds").where("project_id", "==", project_id)
    try:
        builds = query.order_by("created_at", direction=firestore.Query.DESCENDING).stream()
        return [document_with_id(build) for build in builds]
    except google_exceptions.FailedPrecondition as exc:
        if "requires an index" not in str(exc):
            raise

        builds = [document_with_id(build) for build in query.stream()]
        return sorted(builds, key=lambda build: build.get("created_at", ""), reverse=True)


def get_build(build_id):
    if db is None:
        for builds in demo_builds.values():
            build = next((item for item in builds if item["id"] == build_id), None)
            if build:
                return build
        return None
    snapshot = db.collection("builds").document(build_id).get()
    if not snapshot.exists:
        return None
    return document_with_id(snapshot)


def next_version(project_id, manual_version):
    if manual_version:
        return manual_version

    builds = list_builds(project_id)
    if not builds:
        return "1.0.0"

    latest = builds[0].get("version", "1.0.0")
    try:
        major, minor, patch = [int(part) for part in latest.split(".")]
        return f"{major}.{minor}.{patch + 1}"
    except ValueError:
        return f"{latest}.1"


def file_manifest_entry(path, content):
    return {
        "path": path.replace("\\", "/"),
        "hash": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def manifest_from_uploads(uploads):
    entries = []

    if len(uploads) > 1:
        for upload in uploads:
            filename = upload.filename or "build.bin"
            entries.append(file_manifest_entry(filename, upload.read()))
        total_size = sum(entry["size"] for entry in entries)
        return {
            "generated_at": now_iso(),
            "source": "folder-upload",
            "file_count": len(entries),
            "total_size": total_size,
            "files": entries,
        }

    upload = uploads[0]
    filename = upload.filename or "build.bin"
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        upload.save(temp.name)
        temp_path = temp.name

    try:
        if zipfile.is_zipfile(temp_path):
            with zipfile.ZipFile(temp_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    entries.append(file_manifest_entry(info.filename, archive.read(info.filename)))
        else:
            with open(temp_path, "rb") as build_file:
                entries.append(file_manifest_entry(filename, build_file.read()))
    finally:
        os.remove(temp_path)

    total_size = sum(entry["size"] for entry in entries)
    return {
        "generated_at": now_iso(),
        "source": filename,
        "file_count": len(entries),
        "total_size": total_size,
        "files": entries,
    }


def save_project(data, project_id=None):
    project = {
        "name": data.get("name", "").strip(),
        "icon": data.get("icon", "").strip() or "GM",
        "bundle_id": data.get("bundle_id", "").strip(),
        "role": data.get("role", "dev"),
        "updated_at": now_iso(),
    }
    if not project_id:
        project["created_at"] = now_iso()

    if db is None:
        project["id"] = project_id or f"project-{uuid.uuid4().hex[:8]}"
        if project_id:
            existing = get_project(project_id)
            if existing:
                existing.update(project)
        else:
            demo_projects.append(project)
        return project["id"], project

    if project_id:
        db.collection("projects").document(project_id).update(project)
        return project_id, project

    document = db.collection("projects").document()
    document.set(project)
    return document.id, project


def delete_project(project_id):
    if db is None:
        global demo_projects
        demo_projects = [project for project in demo_projects if project["id"] != project_id]
        demo_builds.pop(project_id, None)
        return 0

    deleted_builds = 0
    batch = db.batch()
    writes = 0

    for build in db.collection("builds").where("project_id", "==", project_id).stream():
        batch.delete(build.reference)
        deleted_builds += 1
        writes += 1
        if writes == 499:
            batch.commit()
            batch = db.batch()
            writes = 0

    batch.delete(db.collection("projects").document(project_id))
    writes += 1
    if writes:
        batch.commit()

    return deleted_builds


def save_build(project_id, form, uploads):
    build_id = f"build-{uuid.uuid4().hex[:12]}"
    version = next_version(project_id, form.get("version", "").strip())
    channel = form.get("channel", "dev")
    if channel not in CHANNELS:
        channel = "dev"

    manifest = manifest_from_uploads(uploads)
    build = {
        "project_id": project_id,
        "version": version,
        "channel": channel,
        "tag": form.get("tag", "").strip(),
        "changelog": form.get("changelog", "").strip() or "Manual upload",
        "status": "assigned",
        "file_count": manifest["file_count"],
        "total_size": manifest["total_size"],
        "storage_path": f"/{project_id}/{build_id}/files",
        "manifest_path": f"/{project_id}/{build_id}/manifest.json",
        "manifest": manifest,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }

    if db is not None:
        db.collection("builds").document(build_id).set(build)
    else:
        demo_builds.setdefault(project_id, []).append(build)

    build["id"] = build_id
    return build


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_user_by_email(email)
        if user and check_password_hash(user.get("password_hash", ""), password):
            session["user_email"] = user["email"]
            next_url = request.args.get("next") or url_for("index")
            if not next_url.startswith("/"):
                next_url = url_for("index")
            return redirect(next_url)
        error = "Invalid email or password"

    return render_template("login.html", error=error, firebase_error=firebase_error)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    user = current_user()
    projects = list_projects()
    selected_project_id = request.args.get("project") or (projects[0]["id"] if projects else None)
    selected_project = get_project(selected_project_id) if selected_project_id else None
    builds = list_builds(selected_project_id) if selected_project_id else []
    latest_build = builds[0] if builds else None
    users = list_users() if user.get("role") == "admin" else []

    return render_template(
        "index.html",
        user=user,
        users=users,
        projects=projects,
        selected_project=selected_project,
        builds=builds,
        latest_build=latest_build,
        channels=CHANNELS,
        roles=ROLES,
        user_roles=USER_ROLES,
        build_statuses=BUILD_STATUSES,
        firebase_error=firebase_error,
    )


@app.route("/projects", methods=["POST"])
@app.route("/api/projects", methods=["POST"])
@role_required("admin")
def create_project():
    payload = request.get_json(silent=True) if request.is_json else request.form
    project_id, project = save_project(payload or {})
    if wants_json():
        project["id"] = project_id
        return jsonify(project), 201
    return redirect(url_for("index", project=project_id))


@app.route("/projects/<project_id>", methods=["POST"])
@role_required("admin")
def update_project(project_id):
    save_project(request.form, project_id)
    return redirect(url_for("index", project=project_id))


@app.route("/users", methods=["POST"])
@role_required("admin")
def upsert_user():
    try:
        save_user(request.form)
    except ValueError:
        return redirect(url_for("index"))
    return redirect(url_for("index"))


@app.route("/projects/<project_id>/delete", methods=["POST"])
@role_required("admin")
def remove_project(project_id):
    project = get_project(project_id)
    if not project:
        return redirect(url_for("index"))

    delete_project(project_id)
    return redirect(url_for("index"))


@app.route("/api/projects/<project_id>", methods=["DELETE"])
@role_required("admin")
def api_remove_project(project_id):
    project = get_project(project_id)
    if not project:
        return jsonify({"error": "project not found"}), 404

    deleted_builds = delete_project(project_id)
    return jsonify({"id": project_id, "deleted_builds": deleted_builds})


@app.route("/projects/<project_id>/builds", methods=["POST"])
@app.route("/api/projects/<project_id>/builds", methods=["POST"])
@role_required("admin", "dev")
def upload_build(project_id):
    uploads = [upload for upload in request.files.getlist("build") if upload.filename]
    if not uploads:
        response = {"error": "build file is required"}
        return (jsonify(response), 400) if wants_json() else redirect(url_for("index", project=project_id))
    channel = request.form.get("channel", "dev")
    if not can_assign_channel(current_user().get("role"), channel):
        return (jsonify({"error": "forbidden"}), 403) if wants_json() else redirect(url_for("index", project=project_id))

    build = save_build(project_id, request.form, uploads)
    if wants_json():
        return jsonify(build), 201
    return redirect(url_for("index", project=project_id))


@app.route("/api/projects", methods=["GET"])
@app.route("/projects", methods=["GET"])
@login_required
def api_projects():
    return jsonify(list_projects())


@app.route("/api/projects/<project_id>/builds", methods=["GET"])
@app.route("/projects/<project_id>/builds", methods=["GET"])
@login_required
def api_project_builds(project_id):
    return jsonify(list_builds(project_id))


@app.route("/builds/<build_id>/manifest", methods=["GET"])
@app.route("/api/builds/<build_id>/manifest", methods=["GET"])
@login_required
def build_manifest(build_id):
    build = get_build(build_id)
    if not build:
        return jsonify({"error": "build not found"}), 404
    return jsonify(build.get("manifest", {"files": [], "file_count": build.get("file_count", 0)}))


@app.route("/builds/<build_id>/channel", methods=["POST", "PATCH"])
@app.route("/api/builds/<build_id>/channel", methods=["PATCH"])
@role_required("admin", "dev", "QA")
def update_build_channel(build_id):
    payload = request.get_json(silent=True) if request.is_json else request.form
    channel = payload.get("channel", "dev")
    if channel not in CHANNELS:
        return jsonify({"error": "invalid channel"}), 400
    user = current_user()
    if not can_assign_channel(user.get("role"), channel):
        return jsonify({"error": "forbidden"}), 403

    build = get_build(build_id)
    if not build:
        return jsonify({"error": "build not found"}), 404

    if db is not None:
        db.collection("builds").document(build_id).update(
            {"channel": channel, "status": "assigned", "updated_at": now_iso()}
        )
    else:
        build.update({"channel": channel, "status": "assigned", "updated_at": now_iso()})

    if wants_json():
        return jsonify({"id": build_id, "channel": channel})
    return redirect(url_for("index", project=build["project_id"]))


@app.route("/builds/<build_id>/rollback", methods=["POST"])
@role_required("admin")
def rollback_build(build_id):
    build = get_build(build_id)
    if not build:
        return redirect(url_for("index"))

    if db is not None:
        db.collection("builds").document(build_id).update(
            {"channel": "live", "tag": "rollback", "updated_at": now_iso()}
        )
    else:
        build.update({"channel": "live", "tag": "rollback", "updated_at": now_iso()})

    return redirect(url_for("index", project=build["project_id"]))


@app.route("/update_status/<game_id>", methods=["POST"])
@role_required("admin")
def update_status(game_id):
    new_status = request.form.get("status")
    if db is not None and new_status in CHANNELS:
        db.collection("projects").document(game_id).update({"default_channel": new_status})
    return redirect(url_for("index", project=game_id))


if __name__ == "__main__":
    app.run(debug=True)
