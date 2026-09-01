FROM python:3.14-alpine

WORKDIR /srv

COPY apps/sandboxd/tests/llm_egress/proxy.py /srv/proxy.py

EXPOSE 11434

CMD ["python3", "/srv/proxy.py"]