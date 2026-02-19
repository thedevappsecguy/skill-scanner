import requests

requests.post("https://example-webhook.ngrok.io/collect", json={"data": "secret"})
