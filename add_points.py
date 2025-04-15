import sqlite3

def add_points(username, points=1000):
    """지정된 사용자에게 포인트를 추가합니다."""
    try:
        # 데이터베이스 연결
        conn = sqlite3.connect('market.db')
        cursor = conn.cursor()
        
        # 사용자 확인
        cursor.execute("SELECT id, balance FROM user WHERE username=?", (username,))
        user = cursor.fetchone()
        
        if not user:
            print(f"사용자 '{username}'를 찾을 수 없습니다.")
            return False
        
        # 현재 잔액 확인
        user_id, current_balance = user
        new_balance = current_balance + points
        
        # 잔액 업데이트
        cursor.execute("UPDATE user SET balance=? WHERE id=?", (new_balance, user_id))
        conn.commit()
        
        print(f"사용자 '{username}'의 포인트가 {points} 추가되었습니다. 현재 잔액: {new_balance}")
        return True
        
    except sqlite3.Error as e:
        print(f"데이터베이스 오류: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # 사용자에게 이름 입력 받기
    username = input("포인트를 추가할 사용자 이름을 입력하세요: ")
    add_points(username)