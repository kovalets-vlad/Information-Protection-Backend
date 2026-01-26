Key Features
LCG (Linear Congruential Generator): Implements stateful PRNG with seed persistence in PostgreSQL to ensure true pseudo-random continuity across restarts.

RC5 Block Cipher: Customizable symmetric encryption.

RSA & DSA: Implementation of asymmetric encryption and digital signature algorithms.

Database Integration: Uses SQLModel (SQLAlchemy + Pydantic) for managing cryptographic states.

Dockerized: Fully containerized environment for consistent deployment.

🛠️ Configuration (.env)
The application requires specific environment variables for the cryptographic engines and database connectivity. Create a .env file in the root directory:

# --- Database Settings ---

POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_DB=crypto_db
DATABASE_URL=postgresql://user:password@db:5432/crypto_db

# --- LCG Parameters (Linear Congruential Generator) ---

MULTIPLIER=3125
INCREASE=3
COMPARISON_MODULE=8191
INITIAL_NUMBER=16

# --- RC5 Parameters ---

RC5_WORD_SIZE=16
RC5_ROUNDS=20
KEY_SIZE=16

# --- System Settings ---

STREAM_CHUNK_SIZE=1048576
🚀 Deployment
Using Docker Compose
Run the entire stack (API + PostgreSQL) with a single command:

Bash
docker-compose up --build
Accessing the API
Once the containers are running:

Swagger UI: http://localhost:8000/docs

ReDoc: http://localhost:8000/redoc

🏗️ Technical Architecture
Persistence: On every PRNG call, the LCG updates its state in the database. This prevents sequence repetition upon service reboot.

Performance: Heavy mathematical operations are optimized for FastAPI's asynchronous nature.

Security: Secrets and cryptographic parameters are managed via environment variables to keep the codebase clean and secure.

🧪 Development
To run tests using pytest:

Bash
docker exec -it <container_id> pytest
