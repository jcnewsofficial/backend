```bash
sudo service postgresql start
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
/usr/bin/docker-compose up -d --build
```
