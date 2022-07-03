FROM python:latest

# RUN apt-get install -y  libssl-dev zlib1g-dev libbz2-dev

COPY bin/ /app

WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python"]

CMD ["./main.py"]
