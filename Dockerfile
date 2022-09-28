FROM python:3.6-buster
RUN useradd -ms /bin/bash htmlfetcher

USER htmlfetcher
WORKDIR /home/htmlfetcher

COPY src ./CTF-werkzeug_pin_crack
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY challenge/note.txt ../

EXPOSE 5000
CMD ["python", "./CTF-werkzeug_pin_crack/main.py"]