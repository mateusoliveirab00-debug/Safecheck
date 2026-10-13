import os

from flask import Flask, jsonify, render_template, request

from checker import analisar_senha, analisar_url, gerar_senha

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB por requisição


@app.after_request
def cabecalhos_seguranca(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/api/senha")
def api_senha():
    dados = request.get_json(silent=True) or {}
    resultado = analisar_senha(str(dados.get("senha", ""))[:256])
    return jsonify(resultado), (400 if "erro" in resultado else 200)


@app.post("/api/url")
def api_url():
    dados = request.get_json(silent=True) or {}
    resultado = analisar_url(str(dados.get("url", ""))[:2048])
    return jsonify(resultado), (400 if "erro" in resultado else 200)


@app.get("/api/gerar")
def api_gerar():
    try:
        tamanho = int(request.args.get("tamanho", 16))
    except ValueError:
        tamanho = 16
    simbolos = request.args.get("simbolos", "1") != "0"
    return jsonify(senha=gerar_senha(tamanho, simbolos))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
