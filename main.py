# main.py
import uvicorn
import logging
import pathlib
import os
import motor.motor_asyncio
import beanie
import jwt # Using PyJWT for token handling
from logging.config import dictConfig
from typing import Optional, Annotated, Any
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, Request, Response, HTTPException, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from pydantic_settings import BaseSettings
from beanie import PydanticObjectId, Link, Document
from pwdlib import PasswordHash
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- CSFLE / BSON Imports ---
import pymongo
from pymongo.encryption import ClientEncryption, Algorithm
from bson.binary import Binary, STANDARD
from bson.codec_options import CodecOptions
from bson import ObjectId

# --- LangChain Imports ---
from langchain_openai import AzureChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain.tools import tool

# --- Logging Configuration ---
class LogConfig(BaseSettings):
    LOGGER_NAME: str = "my_app"
    LOG_FORMAT: str = "%(levelprefix)s | %(asctime)s | %(message)s"
    LOG_LEVEL: str = "INFO"
    version: int = 1
    disable_existing_loggers: bool = False
    formatters: dict = {"default": {"()": "uvicorn.logging.DefaultFormatter", "fmt": LOG_FORMAT, "datefmt": "%Y-%m-%d %H:%M:%S"}}
    handlers: dict = {"default": {"formatter": "default", "class": "logging.StreamHandler", "stream": "ext://sys.stderr"}}
    loggers: dict = {"my_app": {"handlers": ["default"], "level": LOG_LEVEL}}
dictConfig(LogConfig().model_dump())
logger = logging.getLogger("my_app")


# --- Application Settings ---
class Settings(BaseSettings):
    DATABASE_NAME: str = "manual_auth_db"
    MONGO_URI: str = "mongodb://localhost:27017"
    ALLOWED_ORIGINS: list[str] = ["https://127.0.0.1:8080", "https://localhost:8080", "null"]
    PRIVATE_KEY_PATH: pathlib.Path = pathlib.Path("private_key.pem")
    PUBLIC_KEY_PATH: pathlib.Path = pathlib.Path("public_key.pem")
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    AUTH_COOKIE_NAME: str = "fastapi_auth"
    AZURE_OPENAI_CHAT_DEPLOYMENT_NAME: str
    OPENAI_API_VERSION: str
    AZURE_OPENAI_ENDPOINT: str
    AZURE_OPENAI_API_KEY: str
    MONGO_DB_NAME: str
    MONGO_COLLECTION_NAME_INSECURE: str
    MONGO_COLLECTION_NAME_SECURE: str
    class Config:
        env_file = ".env"

settings = Settings()

# --- CSFLE Helper Class ---
class CSFLEHelper:
    def __init__(self, mongo_uri: str):
        key_path = pathlib.Path("master-key.bin")
        if key_path.exists(): local_master_key = key_path.read_bytes()
        else:
            local_master_key = os.urandom(96)
            key_path.write_bytes(local_master_key)
        self.kms_providers = {"local": {"key": local_master_key}}
        self.key_vault_namespace = "encryption.__pymongoTestKeyVault"
        key_vault_client = pymongo.MongoClient(mongo_uri)
        db_name, coll_name = self.key_vault_namespace.split(".", 1)
        if coll_name not in key_vault_client[db_name].list_collection_names():
            key_vault_client[db_name].create_collection(coll_name)
        self.client_encryption = ClientEncryption(
            self.kms_providers, self.key_vault_namespace, key_vault_client,
            CodecOptions(uuid_representation=STANDARD),
        )
        self.data_key_id = self._get_or_create_data_key()
    def _get_or_create_data_key(self) -> Binary:
        key_vault_client = self.client_encryption._key_vault_client
        key_vault_db, key_vault_coll = self.key_vault_namespace.split(".", 1)
        key = key_vault_client[key_vault_db][key_vault_coll].find_one()
        if key: return key["_id"]
        return self.client_encryption.create_data_key("local")
    def encrypt(self, value: Any, deterministic: bool = True) -> Binary:
        algo = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic if deterministic else Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random
        return self.client_encryption.encrypt(value, algo, key_id=self.data_key_id)
    def decrypt(self, value: Binary) -> Any:
        decrypted = self.client_encryption.decrypt(value)
        return decrypted.decode('utf-8') if isinstance(decrypted, bytes) else decrypted


# --- Security Setup ---
pwd_hasher = PasswordHash.recommended()
limiter = Limiter(key_func=get_remote_address)
try:
    private_key = settings.PRIVATE_KEY_PATH.read_text()
    public_key = settings.PUBLIC_KEY_PATH.read_text()
except FileNotFoundError:
    logger.critical("Missing RSA key files. Please generate them.")
    raise SystemExit(1)


# --- Database Models ---
class User(Document):
    email: EmailStr = Field(..., unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    class Settings: name = "users"

class UserProfile(Document):
    user: Link[User]
    full_name: str
    ssn: Binary
    salary: Binary
    medical_notes: Binary
    model_config = ConfigDict(arbitrary_types_allowed=True)
    class Settings: name = "user_profiles"
    
class SecureAgentTrace(Document):
    user_input: str
    final_answer: Binary
    trace: list[dict[str, Any]]
    created_at: datetime = Field(default_factory=datetime.now)
    model_config = ConfigDict(arbitrary_types_allowed=True)
    class Settings: name = settings.MONGO_COLLECTION_NAME_SECURE

# --- Pydantic API Schemas ---
class UserSchema(BaseModel):
    id: PydanticObjectId
    email: EmailStr
    is_active: bool
class UserProfileOut(BaseModel):
    full_name: str
    ssn: str
    salary: float
    medical_notes: str
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    ssn: str
    salary: float
    medical_notes: str
class TokenData(BaseModel):
    sub: str | None = None
class AgentQuery(BaseModel):
    query: str
class AgentResponse(BaseModel):
    answer: str
    insecure_trace_id: str
    secure_trace_id: str

# --- Utilities and Auth Dependencies ---
def verify_password(plain_password: str, hashed_password: str) -> bool: return pwd_hasher.verify(plain_password, hashed_password)
def get_password_hash(password: str) -> str: return pwd_hasher.hash(password)
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, private_key, algorithm=settings.JWT_ALGORITHM)
async def get_current_user(request: Request) -> User:
    token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    credentials_exception = HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not validate credentials")
    if not token: raise credentials_exception
    try:
        payload = jwt.decode(token, public_key, algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None: raise credentials_exception
    except jwt.PyJWTError: raise credentials_exception
    user = await User.get(PydanticObjectId(user_id))
    if user is None: raise credentials_exception
    return user
async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if not current_user.is_active: raise HTTPException(status.HTTP_403_FORBIDDEN, "Inactive user")
    return current_user


# --- LangChain Agent Setup ---
csfle_helper_for_tools: CSFLEHelper | None = None

@tool
async def get_user_profile_data(user_id: str) -> dict:
    """Fetches the current user's complete profile data given their user_id. Use this tool for any questions about the user's personal, financial, or medical information (e.g., questions about 'me', 'my', or 'I')."""
    logger.info(f"AGENT TOOL CALLED: get_user_profile_data(user_id='{user_id}')")
    try:
        user_obj_id = PydanticObjectId(user_id)
        profile = await UserProfile.find_one(UserProfile.user.id == user_obj_id)
        if not profile or not csfle_helper_for_tools:
            return {"error": "Profile not found."}
        user_doc = await profile.user.fetch()
        if not user_doc:
             return {"error": "Linked user document could not be fetched."}
        
        # The tool decrypts all sensitive data into memory for the agent to use.
        return {
            "full_name": profile.full_name, "email": user_doc.email,
            "ssn": csfle_helper_for_tools.decrypt(profile.ssn),
            "salary": csfle_helper_for_tools.decrypt(profile.salary),
            "medical_notes": csfle_helper_for_tools.decrypt(profile.medical_notes),
        }
    except Exception as e:
        logger.error(f"Error in agent tool: {e}", exc_info=True)
        return {"error": str(e)}

# --- FastAPI Application & Routers ---
fastapi_app = FastAPI(title="Manual Auth App with CSFLE & AI Agent")
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
users_router = APIRouter(prefix="/users", tags=["Users"])
agent_router = APIRouter(prefix="/agent", tags=["AI Agent"])

# --- Auth & User Endpoints ---
@auth_router.post("/register", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(request: Request, user_in: UserCreate):
    if await User.find_one(User.email == user_in.email): raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")
    csfle: CSFLEHelper = request.app.state.csfle
    new_user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))
    await new_user.insert()
    profile = UserProfile(
        user=new_user, full_name=user_in.full_name, ssn=csfle.encrypt(user_in.ssn),
        salary=csfle.encrypt(user_in.salary, deterministic=False),
        medical_notes=csfle.encrypt(user_in.medical_notes, deterministic=False)
    )
    await profile.insert()
    return new_user

@auth_router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await User.find_one(User.email == form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password) or not user.is_active: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": str(user.id)}, expires_delta=expires)
    response.set_cookie(key=settings.AUTH_COOKIE_NAME, value=token, httponly=True, secure=True, samesite="none", max_age=int(expires.total_seconds()))
    return {"message": "Login successful"}
@auth_router.post("/logout")
def logout(response: Response):
    response.delete_cookie(settings.AUTH_COOKIE_NAME)
    return {"message": "Logout successful"}
@users_router.get("/me", response_model=UserSchema)
def get_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user
@users_router.get("/me/profile", response_model=UserProfileOut)
async def get_profile(request: Request, current_user: Annotated[User, Depends(get_current_active_user)]):
    profile = await UserProfile.find_one(UserProfile.user.id == current_user.id)
    if not profile: raise HTTPException(status.HTTP_404_NOT_FOUND, "Profile not found")
    csfle: CSFLEHelper = request.app.state.csfle
    try:
        return UserProfileOut(
            full_name=profile.full_name, ssn=csfle.decrypt(profile.ssn),
            salary=csfle.decrypt(profile.salary), medical_notes=csfle.decrypt(profile.medical_notes)
        )
    except Exception as e:
        logger.error(f"Failed to decrypt profile: {e}")
        raise HTTPException(500, "Could not decrypt profile data.")

# --- AI Agent Endpoints ---
@agent_router.post("/ask", response_model=AgentResponse)
async def ask_agent(request: Request, query: AgentQuery, user: Annotated[User, Depends(get_current_active_user)]):
    agent_executor: AgentExecutor = request.app.state.agent_executor
    csfle: CSFLEHelper = request.app.state.csfle
    
    # The agent is provided with the current user's ID for context.
    input_with_context = (
        f"{query.query}\n\n---\nIMPORTANT CONTEXT: The question is being asked by the user with user_id '{user.id}'. "
        f"Use this ID for any lookups related to 'me', 'my', or 'I'."
    )
    
    response = await agent_executor.ainvoke({"input": input_with_context})
    insecure_trace_doc_id, secure_trace_doc_id = None, None
    try:
        # DEMO: Log the raw, decrypted tool output to an insecure collection
        insecure_trace_client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGO_URI)
        insecure_collection = insecure_trace_client[settings.MONGO_DB_NAME][settings.MONGO_COLLECTION_NAME_INSECURE]
        serializable_trace = [{"tool_name": a.tool, "tool_input": a.tool_input, "tool_output": o} for a, o in response.get("intermediate_steps", [])]
        insecure_log_doc = {"user_input": response.get("input"), "final_answer": response.get("output"), "trace": serializable_trace, "created_at": datetime.now()}
        result = await insecure_collection.insert_one(insecure_log_doc)
        insecure_trace_doc_id = str(result.inserted_id)
    finally:
        if 'insecure_trace_client' in locals(): insecure_trace_client.close()
    
    try:
        # DEMO: Manually re-encrypt PII before saving to the secure trace collection
        secure_trace_payload = []
        for action, observation in response.get("intermediate_steps", []):
            secure_observation = observation.copy()
            # Find sensitive keys in the tool output and encrypt them before logging
            for key in ['ssn', 'salary', 'medical_notes']:
                if key in secure_observation and not isinstance(secure_observation[key], Binary):
                    secure_observation[key] = csfle.encrypt(secure_observation[key], deterministic=False)
            secure_trace_payload.append({"tool_name": action.tool, "tool_input": action.tool_input, "tool_output": secure_observation})
        
        # Encrypt the final answer as well
        secure_trace = SecureAgentTrace(
            user_input=response.get("input"),
            final_answer=csfle.encrypt(response.get("output"), deterministic=False),
            trace=secure_trace_payload
        )
        await secure_trace.insert()
        secure_trace_doc_id = str(secure_trace.id)
    except Exception as e:
        logger.error(f"Error creating secure trace: {e}", exc_info=True)

    return AgentResponse(answer=response.get("output"), insecure_trace_id=insecure_trace_doc_id or "error", secure_trace_id=secure_trace_doc_id or "error")

@agent_router.get("/traces/{trace_id}")
async def get_trace(request: Request, trace_id: str, secure: bool = False):
    if secure:
        trace_doc = await SecureAgentTrace.get(PydanticObjectId(trace_id))
        if not trace_doc: raise HTTPException(404, "Secure trace not found")
        
        # Sanitize BSON Binary types for clean JSON display
        trace_doc_dict = trace_doc.model_dump(by_alias=True)
        def sanitize_for_display(data: Any) -> Any:
            if isinstance(data, dict):
                return {k: sanitize_for_display(v) for k, v in data.items()}
            if isinstance(data, list):
                return [sanitize_for_display(i) for i in data]
            if isinstance(data, Binary):
                return "<ENCRYPTED DATA>"
            return data
        return sanitize_for_display(trace_doc_dict)
    else:
        client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGO_URI)
        try:
            collection = client[settings.MONGO_DB_NAME][settings.MONGO_COLLECTION_NAME_INSECURE]
            trace_doc = await collection.find_one({"_id": ObjectId(trace_id)})
            if not trace_doc: raise HTTPException(404, "Insecure trace not found")
            trace_doc["_id"] = str(trace_doc["_id"]) # Convert ObjectId to string for JSON
            return trace_doc
        finally:
            client.close()


# --- App Initialization & Global Handlers ---
@fastapi_app.on_event("startup")
async def on_startup():
    global csfle_helper_for_tools
    csfle_helper = CSFLEHelper(settings.MONGO_URI)
    fastapi_app.state.csfle = csfle_helper
    csfle_helper_for_tools = csfle_helper
    client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGO_URI)
    await beanie.init_beanie(database=client[settings.DATABASE_NAME], document_models=[User, UserProfile, SecureAgentTrace])
    llm = AzureChatOpenAI(deployment_name=settings.AZURE_OPENAI_CHAT_DEPLOYMENT_NAME, openai_api_version=settings.OPENAI_API_VERSION, azure_endpoint=settings.AZURE_OPENAI_ENDPOINT, api_key=settings.AZURE_OPENAI_API_KEY, temperature=0)
    
    tools = [get_user_profile_data]

    prompt = ChatPromptTemplate.from_messages([("system", "You are a helpful assistant. The user's query will contain their user_id, which you must use when calling tools."), ("human", "{input}"), ("placeholder", "{agent_scratchpad}")])
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, return_intermediate_steps=True)
    fastapi_app.state.agent_executor = agent_executor

fastapi_app.state.limiter = limiter
fastapi_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
fastapi_app.add_middleware(CORSMiddleware, allow_origins=settings.ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
@fastapi_app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"message": "An unexpected server error occurred."})
@fastapi_app.get("/", tags=["Root"])
def read_root():
    return {"message": "Welcome to the FastAPI Manual Authentication App", "docs": "/docs"}
fastapi_app.include_router(auth_router)
fastapi_app.include_router(users_router)
fastapi_app.include_router(agent_router)

if __name__ == "__main__":
    uvicorn.run("main:fastapi_app", host="0.0.0.0", port=8000, reload=True, ssl_keyfile="localhost+2-key.pem", ssl_certfile="localhost+2.pem")


"""
uvicorn main:fastapi_app --reload --ssl-keyfile localhost+2-key.pem --ssl-certfile localhost+2.pem

PRE-REQUISITES FOR LOCAL DEVELOPMENT WITH HTTPS
brew install mkcert
mkcert localhost 127.0.0.1 ::1
mkcert -install


"""

"""
NOTES: Pydantic, the library Beanie uses for data validation, doesn't natively understand the Binary type from the bson library.

Why a Key Pair (RS256) Solves 🛡️
The key pair method (an asymmetric strategy) works like a personal signature and 
a public verification guide.


1. The Private Key (Your Signature ✍️)
This is your unique, physical signature that only you can produce. You keep it completely secret.

Its only job: To sign (create) new JWTs.

Where it lives: It should only exist on your authentication server—the single, secure service responsible for logging users in.

2. The Public Key (The Verification Guide ✅)
This is like a publicly available guide that shows everyone what your real signature looks like. You can share it freely because it can't be used to fake your signature.

Its only job: To verify that a JWT's signature is authentic.

Where it lives: You can give this key to any other service in your system (e.g., your profile service, order service, etc.) that needs to check if a user's token is valid.

# Command 1: Generate a 2048-bit RSA private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Command 2: Extract the public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem
"""

"""
---
### ## Why `Lax` Fails in THIS Setup

Think of `SameSite=Lax` as a bouncer at an exclusive club.
* **If you're already inside the club (same site):** You can go anywhere you want, and you can always show your membership card (the cookie).
* **If you arrive at the front door by clicking a direct link (top-level navigation):** The bouncer will let you in and accept your card.
* **If another club's staff (a script from another site) tries to send you over to make a request:** The bouncer says, "Nope, I don't trust requests that weren't initiated directly by the user."

In your setup:
* Your frontend (`localhost:8080`) is **"another club."**
* Your backend (`localhost:8000`) is the **"exclusive club."**
* Your JavaScript's `fetch()` call is the **"other club's staff"** trying to make a request.

`SameSite=Lax` is specifically designed to block this kind of cross-site JavaScript request to prevent a type of attack called Cross-Site Request Forgery (CSRF).

***
### ## Why `None` is the Solution

Think of `SameSite=None` as an international passport 🛂. It's explicitly designed to be shown at any border crossing (any site/origin).

By setting `samesite="none"`, you are telling the browser, "I have a modern application architecture. I fully intend for this cookie to be sent by scripts from other origins, and that's okay." This is the correct setting for APIs that are intentionally called from different frontends.

***
### ## Is `None` Less Secure? 🛡️

This is the crucial part. In the past, the default behavior was like `SameSite=None`, and it led to security holes. Modern browsers fixed this by adding a mandatory rule:

**You can only use `SameSite=None` if you also set `Secure=True`.**

This combination is the key.
* `SameSite=None`: Allows the cookie to be sent cross-site.
* `Secure=True`: **Forces** the cookie to only be sent over an encrypted **HTTPS** connection.

This pairing provides the necessary security. While the cookie is more widely sent, the `Secure` flag ensures it can't be intercepted and read by someone snooping on an insecure network (like public Wi-Fi). It's a trade-off: you're opting out of the `Lax` CSRF protection in favor of enabling cross-origin functionality, but you're enforcing transport-level security (HTTPS) to compensate.

### Summary

| Attribute | What it Does | Your Use Case | Security |
| :--- | :--- | :--- | :--- |
| **`SameSite=Lax`** | Blocks cookies on cross-site `fetch` requests. Great for traditional websites. | ❌ **Fails.** Your frontend (`:8080`) is cross-site from your backend (`:8000`). | The modern, secure default for most sites. |
| **`SameSite=None`** | Allows cookies on all cross-site requests, but **requires** the `Secure` flag. | ✅ **Works.** This is the correct setting for cross-origin APIs. | Secure, as long as it's paired with HTTPS to protect the cookie in transit. |
"""
