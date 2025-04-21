# Tiny Secondhand Shopping Platform

화이트햇 스쿨 3기 시큐어 코딩 과제  
레포지토리: [https://github.com/jin182/WHS3-Secure-Coding.git](https://github.com/jin182/WHS3-Secure-Coding.git)

---

## 🛠️ Requirements

Anaconda 또는 Miniconda가 필요합니다.

### Miniconda 설치 (Linux 기준)

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh
~/miniconda3/bin/conda init
```

설치 중 프롬프트가 나오면 'yes'를 입력해 `.bashrc`를 초기화하세요.  
설치 후, 셸을 재시작하거나 아래 명령어를 실행합니다.

```bash
source ~/.bashrc
```

---

## ⚙️ 프로젝트 환경 설정

```bash
git clone https://github.com/jin182/Secure-Coding.git
cd Secure-Coding

conda create -n secure_coding python=3.11
conda activate secure_coding

pip install flask flask_socketio flask_wtf bcrypt
```

---

## 🚀 Usage

서버 실행:

```bash
python app.py
```

실행 후 [http://localhost:5000](http://localhost:5000)에서 플랫폼을 이용할 수 있습니다.

### 외부 환경 테스트 (선택 사항)

외부 기기에서 접속하려면 **ngrok**을 사용하세요.

```bash
ngrok http 5000
```

표시된 Forwarding URL을 이용해 외부에서 접근할 수 있습니다.

---

## ✨ 주요 기능

- 사용자 회원가입 및 로그인 (bcrypt 기반 비밀번호 해싱)
- 상품 등록 및 구매
- 포인트 송금 및 거래 내역 관리
- 관리자 페이지(사용자/상품/신고 내역 관리)
- 실시간 채팅 기능

---

## 🔒 보안 설정

- CSRF 보호 (Flask-WTF)
- XSS 방지 (`html.escape` 사용)
- 안전한 비밀번호 저장 (bcrypt)
- 세션 및 쿠키 관리 강화

---

## 👤 작성자

[jin182](https://github.com/jin182)

---

**참고:**  
설치 및 실행 과정에서 문제가 발생하면 [Miniconda 공식 문서](https://docs.conda.io/en/latest/miniconda.html)를 참고하세요.
