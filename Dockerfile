FROM python:3.6-buster
WORKDIR /home/CTF-werkzeug_pin_crack
COPY src .
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY challenge/note.txt /home
EXPOSE 5000
CMD ["python", "main.py"]