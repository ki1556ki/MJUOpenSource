import os
# 루트를 파일의 절대경로로 설정
_ROOT = os.path.abspath(os.path.dirname(__file__))
# 경로의 데어터 반환
def get_data(path):
    return os.path.join(_ROOT, 'signatures', path)
