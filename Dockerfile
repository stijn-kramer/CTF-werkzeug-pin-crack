FROM python:3.10-buster
RUN git clone https://github.com/stijn-kramer/CTF-werkzeug_pin_crack.git
WORKDIR /CTF-werkzeug_pin_crack
RUN pip install .
EXPOSE 5000
CMD ["python", "main.py"]