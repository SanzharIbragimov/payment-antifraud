@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist .venv (
  echo Создаю виртуальное окружение...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
echo Запуск тестов...
python -m pytest -q
echo.
echo Панель: http://127.0.0.1:8000   API: http://127.0.0.1:8000/docs
start "" http://127.0.0.1:8000
python -m uvicorn app.api:app --port 8000
