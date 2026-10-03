# SECURESHADOW

**Detecting security controls that become ineffective without actually failing.**

Traditional security tools ask: "Is this control configured correctly?"  
SECURESHADOW asks: "Does this control still enforce the security property it was designed to enforce?"

When the environment changes—a new API, a new microservice, a new data path—a control can remain perfectly configured but silently lose its protective power. SECURESHADOW detects that silent architectural drift and quantifies the security decay.

## How It Works

1. **Model** — Every security control gets a formal Security Property with explicit Assumptions.
2. **Graph** — The entire architecture (assets, paths, controls) is represented as a directed graph.
3. **Baseline** — A "known good" snapshot is taken (via manual demo or Terraform IaC parsing).
4. **Drift Detection** — The current state is compared against the baseline to produce ChangeEvents.
5. **Assumption Analysis** — Changes are checked to see if they invalidate security assumptions.
6. **Protection Decay Score** — A deterministic score shows how much protection eroded and why.
7. **Repair Engine** — Candidate repairs are generated, costed, and the most cost-effective is recommended.

## Architecture & Project Structure

The project has been refactored into a modern Python package (`secureshadow/`) containing the core domain logic, a FastAPI backend, and an integrated Single Page Application (SPA) dashboard.

```text
secureshadow-main/
├── secureshadow/
│   ├── core components (models.py, graph.py, drift.py, decay.py, repair.py)
│   ├── api/       # FastAPI REST endpoints and JWT Auth
│   ├── db/        # SQLAlchemy ORM and SQLite/PostgreSQL persistence
│   ├── loaders/   # Terraform JSON parsers
│   ├── static/    # Vanilla JS/HTML SPA Web Dashboard
│   └── cli.py     # Command-line interface entry point
├── tests/         # Comprehensive pytest suite
├── .env.example   # Environment variable templates
├── docker-compose.yml 
└── Dockerfile
```

## Requirements

- Python 3.11+
- Requirements mapped in `pyproject.toml` (FastAPI, NetworkX, SQLAlchemy, etc.)

**Installation:**
```powershell
pip install -e .
```

## Running the Application

### Option 1: FastAPI Web Server & Dashboard (Recommended)

Start the local server with Uvicorn:

```powershell
py -m uvicorn secureshadow.api.app:app --host 127.0.0.1 --port 8000
```
Open your browser to `http://127.0.0.1:8000`. 
The default admin credentials (if not changed in `.env`) are `admin` / `secureshadowadmin`.

### Option 2: Command Line Interface (CLI)

Run the canonical demo scenario directly in the terminal:

```powershell
py secureshadow/cli.py demo
```

Run against actual Terraform Infrastructure-as-Code state files:

```powershell
py secureshadow/cli.py terraform tests/fixtures/terraform_baseline.json --current tests/fixtures/terraform_drifted.json
```

### Option 3: Docker Compose

If you have Docker installed, you can spin up the API and a PostgreSQL database:

```bash
docker compose up --build
```

## Running Tests

The project uses `pytest` for unit and integration testing.

```powershell
py -m pytest -v
```

## Configuration

Copy `.env.example` to `.env` to configure settings securely for production:
- `JWT_SECRET`: Secret for signing auth tokens
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`: Default credentials
- `DATABASE_URL`: Connection string (defaults to local SQLite `secureshadow.db`)
- `CORS_ORIGINS`: Allowed origins for the API

## Database Backup & Restore (PostgreSQL / Docker)

When running the containerized PostgreSQL setup (`secureshadow-db`), perform backups and restores using standard `pg_dump` and `pg_restore` / `psql` commands executed against the container.

### 1. Taking a Backup
Create a full SQL dump of the `secureshadow` database:

```bash
docker compose exec -T db pg_dump -U secureshadow secureshadow > backup_$(date +%Y%m%d_%H%M%S).sql
```

Or binary custom format (`.dump`):
```bash
docker compose exec -T db pg_dump -U secureshadow -Fc secureshadow > backup_secureshadow.dump
```

### 2. Restoring from a Backup
To restore a SQL dump into a clean or running PostgreSQL container:

```bash
docker compose exec -T db psql -U secureshadow -d secureshadow < backup_secureshadow.sql
```

For binary custom format:
```bash
docker compose exec -T db pg_restore -U secureshadow -d secureshadow --clean --if-exists backup_secureshadow.dump
```

---
*Built as a prototype to demonstrate the concept of silent security control degradation detection.*