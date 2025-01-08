from fastapi import FastAPI, Depends, Request, Form, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, create_engine, Date, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, date as dt_date
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse

# 데이터베이스 설정
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()

# 사용자 모델 정의
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# 일정 모델 정의
class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    activity = Column(String)
    description = Column(String)
    date = Column(Date)
    completed = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# 세션 로컬 생성
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT 설정
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

templates = Jinja2Templates(directory="templates")

# 정적 파일 설정
app.mount("/static", StaticFiles(directory="static"), name="static")

# 데이터베이스 의존성
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 비밀번호 해싱 함수
def get_password_hash(password):
    return pwd_context.hash(password)

# 비밀번호 검증 함수
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# 사용자 인증 함수
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 로그인 엔드포인트
@app.post("/token")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "잘못된 아이디 또는 비밀번호입니다."})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/index", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

# 로그인 페이지 라우트
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# 메인 페이지 라우트
@app.get("/index", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 회원가입 페이지 라우트
@app.get("/register", response_class=HTMLResponse)
async def get_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def post_register(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # 사용자 이름 중복 확인
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "이미 존재하는 사용자 이름입니다."})
    
    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return RedirectResponse(url="/login", status_code=303)

# 로그아웃 엔드포인트
@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# 일정 관리 페이지 라우트
@app.get("/add_schedule", response_class=HTMLResponse)
async def get_add_schedule(request: Request, date: str = None, db: Session = Depends(get_db)):
    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    schedules = []
    if date:
        schedule_date = dt_date.fromisoformat(date)
        schedules = db.query(Schedule).filter(Schedule.date == schedule_date).all()
    return templates.TemplateResponse("add_schedule.html", {"request": request, "activities": activities, "schedules": schedules})

@app.post("/add_schedule")
async def post_add_schedule(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    date_str = form.get("schedule_date")
    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    if date_str:
        schedule_date = dt_date.fromisoformat(date_str)
        for i in range(1, 11):
            description = form.get(f"description{i}")
            completed = form.get(f"completed{i}") == "on"
            existing_schedule = db.query(Schedule).filter(Schedule.date == schedule_date, Schedule.activity == f"{i}: {activities[i-1]}").first()
            if existing_schedule:
                existing_schedule.description = description
                existing_schedule.completed = completed
            else:
                new_schedule = Schedule(
                    user_id=1,  # 예시로 사용자 ID를 1로 설정
                    activity=f"{i}: {activities[i-1]}",
                    description=description,
                    date=schedule_date,
                    completed=completed
                )
                db.add(new_schedule)
        db.commit()
    # 저장 후에도 현재 페이지에 머물도록 함
    schedules = db.query(Schedule).filter(Schedule.date == schedule_date).all()
    return templates.TemplateResponse("add_schedule.html", {"request": request, "activities": activities, "schedules": schedules})

# 다른 라우트 및 로직

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 