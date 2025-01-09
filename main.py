from fastapi import FastAPI, Depends, Request, Form, HTTPException, Response, status
from sqlalchemy import Column, Integer, String, create_engine, Date, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, date as dt_date
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError

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

# 토큰을 쿠키에서 추출
def get_current_user(request: Request, db: Session = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증되지 않았습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="인증되지 않았습니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증되지 않았습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증되지 않았습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# 로그인 엔드포인트
@app.post("/token")
async def login_for_access_token(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    user = authenticate_user(db, username, password)
    if not user:
        # 로그인 실패 시 login.html로 유지
        return templates.TemplateResponse("login.html", {"request": request, "error": "잘못된 아이디 또는 비밀번호입니다."})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # 로그인 성공 시 index.html로 리다이렉트 및 쿠키에 토큰 저장
    response = RedirectResponse(url="/index", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

# 로그인 페이지 라우트
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# 활동 데이터 정의
activities_data = [
    {
        "title": "운동",
        "description": """아무리 열심히 사업을 구축해도 건강을 잃으면 아무 도움이 없습니다.
            매일 매일 30분 이상 운동하는 습관을 기르세요.
            건강한 신체에 건강한 정신! 건강한 신체에 건강한 사업!!""",
        "image": "/static/images/exercise.jpg"
    },
    {
        "title": "책읽기",
        "description": """네트워크 마케팅에도 깊은 이해를 하고 있는 작가 버크 헤지는 [Read & Grow Rich]라는 책에서
            미국내 부부자의 비율과 독서를 제대로 하는 사람의 비율이 일치하고 있음을 증명합니다.
            이는 책을 통해서 자신의 내면과 이야기 할 수 있고, 책을 통해서 성장할 수 있기 때문입니다.
            오늘날 인터넷이라는 도구가 정보의 창고인 것은 사실이나, 인간을 성장시키는 도구는 아닙니다.
            또한 이 사업은 대인관계가 중요합니다. 스폰서/업라인과의 관계, 사업 파트너와의 관계,
            새로 후원할 프로스펙트와의 관계 등 대인 관계를 발전 시키려면 내 주장을 관철 시키기 위해
            남에게 강요하는 것이 아니라 ,내가 먼저 변화하고 성장하는 게 필요합니다.
            이는 부부관계, 자녀교육에도 적용됩니다. 부부간에도 내가 먼저 아내를 왕비로 대접해야,
            내가 왕으로 대접을 받을 수 있습니다.
            상대를 설득하는 가장 빠른 지름길은 자신의 변화입니다.
            책은 크게 두 종류로 구분 됩니다. 사업 자체를 이해하기 위한 서적과 자기 개발 서적입니다.
            이외에 건강 관련 책자등을 읽어 보는 것이 필요합니다.
            물론 책읽기가 쉽지는 않습니다. 첫 장을 넘기면서 졸리기도 하고, 앞의 내용이 기억나지 않기도
            합니다. 그래서 어떤 분은 직장 퇴근 후에 책 읽는 것이 피곤해서 책과 펜을 들고 선 채로 책에
            밑줄을 그으면서 읽었다고도 합니다.
            처음에 30분간 책 읽는 것이 어렵다면 첫째 주에는 5분, 둘째 주에는 10분 식으로 점차 읽는 시간을
            늘려가면 됩니다. 3주간 꾸준히 노력해 보십시오.
            미국 정치의 아버지라고 불리우는 프랭클린 루즈벨트는 눈을 감는 순간에도 머리맡에 책갈피가
            꽃힌 책이 있었다고 합니다. 끊임없이 자기 성장을 하려고 노력하였기에 영원한 미국 정치의 아버지로 자리 매김을 할 수가 있었던 것입니다.""",
        "image": "/static/images/reading.jpg"
    },
    {
        "title": "음원듣기",
        "description": """이미 성공한 사람의 사업 경험은 간접적으로 자신에게 큰 도움이 됩니다.
            푸에르토리코의 어떤 이발사는 다이아몬드가 얘기하는 테이프를 1,000번 듣고 자신이 다이아몬드 스피치를 할 수 있었다고 합니다. 테이프에는 다양 한 직업 배경의 성공자들이 다양한 성공 경험을 들려주는 데, 이것을 제대로 활용해야 합니다. 가령 자기가 후원할 사람이 직장인이라면 직장인 출신의 다이아몬드 스피치 테이프가 도움이 되고, 전업주부라면 전업 주부 출신의 사업자가가 얘기하는 테이프가 도움이 됩니다.
            우리가 뷔페 음식 전체의 맛을 안다면 한식, 중식, 일식의 취향에 맞게 추천해 줄 수가 있습니다. 그래서 미국의 모 수석 다이아몬드는"Eat the tape" 이라고 표현할 정도로 많이 들어서 성공자들의 경험을 자기 것으로 만들라 고 했습니다.
            그리고 성공담 테이프는 항상 우리에게 힘을 주는 도구입니다. 사업을 진행하면서 어려움을 겪고 힘을 잃었을 때, 성공담 테이프는 새로운 에너지를 제공합니다. 그래서 누구를 후원하기 전에 자기가 정말 좋아하는 테이프를 듣고 후원하는 것이 좋습니다.""",
        "image": "/static/images/music.jpg"
    },
    {
        "title": "미팅 참석",
        "description": """10Core 중에서 가장 중요한 것을 꼽는다면 미팅참석입니다. 암웨이 사업에서 성공 한 사람들의 스피치에서 자주 회자되는 내용이 자신은"모든 미팅에 참석했다"라 는 것입니다.
            초기에 사업을 진행하는 사람들이 가장 이해하지 못하는 부분이 미팅의 중요성입니다. 한번 듣고나서 두 번 째부터"같은 내용이다"라고 생각하기 쉽습니다. 그러나 미팅의 본래 목적은 자신의 비전과 확신을 강화시켜주는 자리입니다.
            암웨이 사업의 환경은 무지, 오해, 편견의 부정적인 환경입니다. 미팅에 참석하지 않고 홀로 사업을 진행한다면, 아무리 의지가 강한 사람일 지라도 계속 진행하기 어렵습니다.
            인간은 원래 나약한 존재입니다. 미팅은 사업에 긍정적인 사람들, 열정적 인 사람들의 모임입니다. 그 안에서 개인의 나약함을 이겨낼 수 있는 힘을 얻어야 부정적인 환경을 이겨낼 수 있습니다.
            사업 초기에 중요하다고 생각하는 것이 사업 설명회입니다. 많은 사람들을 초대해서 보여주고 싶은 욕심 때문입니다. 그러나 제대로 미팅을 이해한다면 큰 미팅의 순서대로 중요하다는 것을 알게 됩니다. 큰 미팅을 펑션 (Function)이라고 부릅니다.
            FED, OSR, Moving-Up Seminar와 같은 큰 미팅에 참석해서 팀웍으로 생기는 큰 힘을 얻어야 합니다.
            간혹 큰 미팅은 내 체질에 안 맞는다고 하는 경우가 있으나, 성공은 체질로 하는 것이 아니라, 필요한 성공 요소를 갖추었을 때 저절로 따라오는 것 입니다. 시스템은 그냥 만들어 진 것이 아닙니다. 오랜 경험과 지혜의 축적물입니다. 이를 안다면 자신을 중심으로 생각할 것이 아니라, 사업 파트너 들에게 무엇이 도움이 될 지를 생각해야 합니다.""",
        "image": "/static/images/meeting.jpg"
    },
    {
        "title": "제품이용",
        "description": """암웨이 사업은 단순 소비자에서 프로슈머로 인식을 전환하는 사업입니다.
            소비가 지출이 아니고, 소비가 사업이 되는 개념입니다. 소비가 사업이 되기 위해서는 내가 제대로 소비해야 합니다.
            만일 현대자동차그룹 회장이 벤츠차를 타거나, 삼성그룹 회장이 IBM 컴퓨터를 쓴다면 이상하게 생각되지 않겠습니까? 마찬가지입니다. 우리가 암웨이 사업을 하면서 타사의 제품을 사용한다면 소비자는 물론 사업 파트너 들에게 설득력이 없을 것입니다.
            소비자라면 굳이 그럴 필요가 없지만, 사업가라면 당연히 자기가 취급하는 제품에 대한 애정이 필수적일 것입니다.
            암웨이 사업은 단순 소비자에서 프로슈머로 인식을 전환하는 사업입니다.
            소비가 지출이 아니고, 소비가 사업이 되는 개념입니다. 소비가 사업이 되기 위해서는 내가 제대로 소비해야 합니다.
            만일 현대자동차그룹 회장이 벤츠차를 타거나, 삼성그룹 회장이 IBM 컴퓨터를 쓴다면 이상하게 생각되지 않겠습니까? 마찬가지입니다. 우리가 암웨이 사업을 하면서 타사의 제품을 사용한다면 소비자는 물론 사업 파트너 들에게 설득력이 없을 것입니다.
            소비자라면 굳이 그럴 필요가 없지만, 사업가라면 당연히 자기가 취급하는 제품에 대한 애정이 필수적일 것입니다.
            우리는 벤츠차를 타지 않으면서 벤츠차를 판매하는 세일즈맨이 아닙니다. 자신이 사용해 본 경험을 전달하는 사업입니다. 사업을 하기 때문에 제품을 사용하는 것이 아니라, 제품을 사용하다보니 제품이 좋아서 사업으로 발전하는 것입니다.
            제품에 대한 애정이 높을수록 이 사업은 쉬워집니다. 음식점에서 정말 맛난 음식을 먹었을 때, 남들에게 쉽게 그 음식점을 얘기할 수 있는 이치와 같습니다. 억지로 애용하는 것이 아니라, 제대로 애용해야 합니다.
            제대로 제품을 애용하려면 제품에 대해 제대로 알아야 합니다. 어떤 IBO는 사업 초기에 뛰어난 세탁 세제『프리워시』를 열 때 제품 뚜껑을 눌러서 돌려야 하는 것인 줄 모르고 불량품이라고 반품했다고 하는 웃지 못할 에피소드도 있습니다. 마우스 워시가 농축 제품인 줄 모르면 용량에 비해 엄청 나게 비싸 보입니다.
            최소한 구입가격(표시 가격)과 사용가격(사용 기간 환산 가격)을 구분할 줄 알아야 합니다
            제품에 대해 제대로 알기 위해서 제품 공부를 꼭 해야 합니다. 제품 강의나 테이프를 들어야 하는 이유가 여기에 있습니다.
            사업을 시작하였다면 집에 있는 생필품부터 바꾸어 써야 합니다. 비누, 세제 등 몇 푼 되지 않는 생필품이 아깝다고 해서 제품 사용을 미루는 것은 사업 자체를 미루는 격입니다. 간혹 자신은 제품을 쓰지 않으면서 다른 사람이 쓰기를 바라는 사람들이 있습니다. 이것은 이 사업을 그저 공짜 사업 정
            도로 이해한 것입니다. 피라미드 상술이 나쁘다고 욕하면서 정작 자신이 다른 사람을 이용해 사업을 하려는 격이 됩니다.
            또한 제품을 사용하는 것을 지출로 생각하는 사업자들이 간혹 있습니다만, 어차피 쓸 제품을 바꿔 쓰는 것이기 때문에 불필요한 지출이라 얘기할 수 없습니다.
            기존에 사용하고 있는 제품이 정말 아깝다면, 작은 박스에 그 제품을 넣어 봉하십시오. 그리고
            그날의 날짜를 기재해서 창고에 보관하면 부패하는 제품이 아니기 때문에 언제라도 다시 쓸 수가
            있습니다. 몇 년이 지나 이사를 하면서 그 제품을 발견하게 될 것입니다.
            암웨이 사업에서 성공한 사람들이 누구나 겪는 일이지만 그때의 기쁨은 말로 표현할 수가 없습니다
            또한 이왕이면 전제품을 사용하는 것이 좋습니다.
            초기에 사업을 알아보는 사람들이 다소 오해를 하는 사항이나, 이는 단순히 스폰서의 점수를
            올리기 위한 것이 아니라라, 자신의 사업을 크게하기 위함입니다.
            암웨이 회사가 제공한 기회를 구멍 가게 수준으로 할 것인가, 백화점 수준으로 할 것인가는 자신이 결정할 일입니다만, 자신의 제품사용규모가 자기 네트워크의 제품사용규모를 결정하는 것은 당연한 일입니다.
            """,
        "image": "/static/images/product.jpg"
    },
    {
        "title": "사업설명",
        "description": """결국 우리 사업은 여러분 자신의 사업입니다.
            따라서 여러분은 스스로 사업설명(SHOW THE PLAN)을 하실 줄 알아야 합니다.
            평균 주 3회 이상의 사업설명만이 여러분의 네트워크를 확장시킬 수 있습니다.
            절대로 과대과장된 사업설명을 사시면 안되고
            도입부에는 본인이 암웨이 사업을 하게된 배경과 현실점검을 통하여 상대방이
            OPEN MIND 하실 수 있게 하시기 바라며 상대방이 잊어버린 꿈을 TOUCH 해 주시고,
            중간부에는 경제적 현실점검 및 유통의 변화, 회사에 대한 소개와 수익 구조,
            종결부에는 앞으로 암웨이 사업의 비젼과 가치를 설명하시면 됩니다.""",
        "image": "/static/images/business.jpg"
    },
    {
        "title": "소비자 관리",
        "description": """이 분들이 회원일 수 도 있고 아닐 수 도 있습니다.
            몇 가지의 제품만 쓰는 회원 (회원 소비자) 이시거나 그냥 소비자 (비회원 소비자) 이시거나
            이 분들에게 꾸준히 전화 하시고, 제품을 전달해 드리고, 얼굴 보시고, 신 제품에 대해서 알려
            드리고, 그 제품을 제대로 쓰실 수 있도록 교육해 드리고..
            이런 고객 서비스를 꾸준히 하신다면 그 중 몇 분은 사업쪽으로 눈을 뜨시게 된다는 것입니다.
            최근들어 점점 제품의 가지수가 늘어나고 DIGITAL 시대에 발맞춘 제품들이 빠른 속도로 우리
            네트워크에 들어 오고 있습니다.
            즉 생활 자체가 사업인 개념을 통해 많은 고정고객을 확보 하시기 바랍니다.
            처음 부터 쉽지는 않겠지만 인내와 봉사로 꾸준히 고객서비스를 하시다보면 그 분들중에
            BIG BUSINESS로 받아들여 다이아몬드 이상의 PIN을 성취하는 경우가 많이 있습니다.""",
        "image": "/static/images/customer.jpg"
    },
    {
        "title": "상담",
        "description": """우리는 인생을 살면서 수 없이도 많은 경험을 합니다.
            그런데 경험 중에는 직접적인 경험과 간접적인 경험이 있습니다.
            직접적인 경험이란 말 그대로 자기가 직접 경험해 본 일들이고, 간접적인 경험은 대부분이
            책 이나 TV, 영화, 주변 사람들의 이야기 등을 통해서 간접 경험을 하게 되지요.
            우리가 TV, 영화, 책 등을 보면서 마치 나의 일인것처럼 눈물을 흘리듯이 말이지요.
            우리 사업에서는 여러분의 스폰서 업라인 께서는 이미 우리 사업을 시작 하셔서 수 많은 경경험을
            하신 분들 이십니다.
            제품에서 부터 여러사람들을 만나 우리사업에 JOIN 시키고 성장하시기 까지 말이지요.
            그런데 지금은 성장 하셨을 여러분의 스폰서, 업라인 분들도 처음부터 잘 하시지는 않으셨을 것
            입니다. 그 분들도 우리 사업을 전해듣고 도와주신 그분들의 스폰서, 업라인이 계셨기에
            성공 하셨을 것입니다.
            그렇다면 우리는 먼저 성장하신 여러분의 스폰서, 업라인의 직접경험이 무엇보다도 소중한
            사업의 KNOW-HOW 입니다.
            그런 분들과의 정기적인 상담을 통해 여러분의 스폰서, 업라인께서 초기에 범하셨을지도 모르는
            실수담도 들으시고, 반대로 성공담도 들으시고 여러가지 경험을 순복하는 자세로 들으셔야 합니다.
            여러분께서 성공하기를 가장 간절히 바라시는 분들이 바로 여러분의 스폰서, 업라인 분들입니다.
            그 분들과 정기적인 상담을 통해 신뢰도 쌓으시고 사업에 대한 많은 조언들을 겸손한 자세로
            받아들이셔야만 합니다.""",
        "image": "/static/images/consulting.jpg"
    },
    {
        "title": "신뢰 쌓기",
        "description": """상대방이 나를 생각할 때 "아 그사람이라면 믿을 수 있어" 라는 느낌이 가도록 우리가 모든 행동에
            모범이 되어야 합니다.
            아주 작은 약속이라도 잘 지키는 사람이 되어야 합니다.
            생활속에 있는 것들을 잘 지키지 않는 사람이 어떻게 큰 일을 할 수 있겠습니까?
            금전적으로 깨끗한 사람이 되어야 합니다.
            무리해서 돈을 꾸어 가면서 무슨 일을 한다면 친구, 형제 관계라도 깨어지기 일수죠.
            도덕적이라야 합니다.
            즉 남녀 관계, 옷차림 등이 얼굴을 찌푸리게 한다면 절대 사업의 동업자를 얻지 못할 것입니다.
            누구든지 나 보다는 더 나은 사람과 함께 하기를 원하니까요.
            우리는 이런 것을 잘 지키는 사람을 상식적인 사람이라고 부릅니다.
            우리 모두 상식이 통하는 사람이 됩시다.""",
        "image": "/static/images/trust.jpg"
    },
    {
        "title": "e-com",
        "description": """DIGITAL 시대, 지식 정보화 시대를 살고 있는 우리는 초 단위로 쏟아져 나오는
            수많은 지식정보가 세상을 바꾸어 놓고 있습니다.
            우리 사업은 정보전달과 프로모션을 잘 하시는 분들이 성공합니다.
            현재 WWDB-K GROUP 은 각 FAMILY 별로 홈페이지가 개설되어 운영되고 있습니다.
            FAMILY 별 홈페이지를 통하여 매일 매일 중요한 미팅, 제품에 대한 정보를 습득하고
            업라인과 파트너 간에 서로 격려하고 칭찬하면서 TEAM-WORK 을 다지시기 바랍니다.
            홈페이지 활용시에도 WWDB-K 의 분문율을 철저히 지켜 활용 합시다.""",
        "image": "/static/images/ecom.jpg"
    }
]

# 메인 페이지 라우트
@app.get("/index", response_class=HTMLResponse)
async def read_index(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": current_user.username,
            "activities": activities_data  # 활동 데이터 전달
        }
    )

# 회원가입 페이지 라우트
@app.get("/register", response_class=HTMLResponse)
async def get_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def post_register(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # 사용자 이름 중복 확인
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        # 회원가입 실패 시 register.html에 오류 메시지 표시
        return templates.TemplateResponse("register.html", {"request": request, "error": "이미 존재하는 사용자 이름입니다."})
    
    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    # 회원가입 성공 시 login.html로 리다이렉트
    return RedirectResponse(url="/", status_code=303)

# 로그아웃 엔드포인트
@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# 일정 관리 페이지 라우트
@app.get("/add_schedule", response_class=HTMLResponse)
async def get_add_schedule(request: Request, date: str = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    schedules = []
    if date:
        schedule_date = dt_date.fromisoformat(date)
        schedules = db.query(Schedule).filter(Schedule.date == schedule_date, Schedule.user_id == current_user.id).all()
    return templates.TemplateResponse("add_schedule.html", {"request": request, "activities": activities, "schedules": schedules})

@app.post("/add_schedule")
async def post_add_schedule(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    form = await request.form()
    date_str = form.get("schedule_date")
    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    if date_str:
        schedule_date = dt_date.fromisoformat(date_str)
        for i in range(1, 11):
            description = form.get(f"description{i}")
            completed = form.get(f"completed{i}") == "on"
            existing_schedule = db.query(Schedule).filter(Schedule.date == schedule_date, Schedule.activity == f"{i}: {activities[i-1]}", Schedule.user_id == current_user.id).first()
            if existing_schedule:
                existing_schedule.description = description
                existing_schedule.completed = completed
            else:
                new_schedule = Schedule(
                    user_id=current_user.id,
                    activity=f"{i}: {activities[i-1]}",
                    description=description,
                    date=schedule_date,
                    completed=completed
                )
                db.add(new_schedule)
        db.commit()
    schedules = db.query(Schedule).filter(Schedule.date == schedule_date, Schedule.user_id == current_user.id).all()
    return templates.TemplateResponse("add_schedule.html", {"request": request, "activities": activities, "schedules": schedules})

# 일정 검색 페이지 라우트
@app.get("/search_schedule", response_class=HTMLResponse)
async def get_search_schedule(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    return templates.TemplateResponse(
        "search_schedule.html",
        {
            "request": request,
            "username": current_user.username,
            "activities": activities
        }
    )

@app.post("/search_schedules")
async def search_schedules(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    form = await request.form()
    start_date = form.get("start_date")
    end_date = form.get("end_date")

    if not start_date or not end_date:
        raise HTTPException(status_code=400, detail="시작 날짜와 끝 날짜를 모두 선택해야 합니다.")

    start = dt_date.fromisoformat(start_date)
    end = dt_date.fromisoformat(end_date)

    if start > end:
        raise HTTPException(status_code=400, detail="시작 날짜는 끝 날짜보다 빠르거나 같아야 합니다.")

    activities = ["운동", "책읽기", "음원듣기", "미팅 참석", "제품이용", "사업설명", "소비자 관리", "상담", "신뢰 쌓기", "e-com"]
    counts = {activity: 0 for activity in activities}

    schedules = db.query(Schedule).filter(
        Schedule.user_id == current_user.id,
        Schedule.date >= start,
        Schedule.date <= end,
        Schedule.completed == True
    ).all()

    for schedule in schedules:
        activity = schedule.activity.split(": ")[1]  # "1: 운동" 형식에서 "운동동" 추출
        if activity in counts:
            counts[activity] += 1

    data = [counts[activity] for activity in activities]

    return {"activities": activities, "data": data}

# 예외 핸들러 추가
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return templates.TemplateResponse("login.html", {"request": request, "error": "인증되지 않았습니다."})
    raise exc

# 다른 라우트 및 로직

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 