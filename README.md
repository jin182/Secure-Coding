# Tiny Secondhand Shopping Platform

화이트햇 스쿨 3기 시큐어 코딩 과제

레포지토리 주소: [https://github.com/jin182/WHS3-Secure-Coding.git](https://github.com/jin182/WHS3-Secure-Coding.git)

---

## Requirements

Anaconda 또는 Miniconda를 설치해주세요:

- Miniconda 설치 (Linux 기준)

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh
cd ~/miniconda3/bin
./conda init
```

이후 터미널을 재시작 해주세요.

## 프로젝트 환경 설정

```bash
git clone https://github.com/jin182/WHS3-Secure-Coding.git
cd WHS3-Secure-Coding

conda create -n secure_coding python=3.11
conda activate secure_coding

# 필요한 패키지 설치
pip install flask flask_socketio flask_wtf bcrypt
```

## Usage

서버 실행:

```bash
python app.py
```

서버가 정상적으로 실행되면, `http://localhost:5000`에 접속하여 플랫폼을 이용할 수 있습니다.

### 외부 환경 테스트 (선택 사항)

외부 기기에서 접속하고 싶은 경우, ngrok을 사용하여 외부 URL을 설정할 수 있습니다:

```bash
ngrok http 5000
```

이후 표시된 Forwarding URL을 사용하여 외부에서 접근할 수 있습니다.

## 주요 기능

- 사용자 회원가입 및 로그인 (bcrypt를 사용한 비밀번호 해싱)
- 상품 등록 및 구매
- 포인트 송금 및 거래 내역 관리
- 관리자 페이지를 통한 사용자 관리, 상품 관리 및 신고 내역 관리
- 실시간 채팅 기능

---

보안 설정:
- CSRF 보호 적용 (Flask-WTF)
- XSS 방지(html.escape 사용)
- 비밀번호 안전 저장(bcrypt)
- 세션 및 쿠키 관리 강화

---

작성자: [jin182](https://github.com/jin182)
