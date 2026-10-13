# 🛡️ SafeCheck

Aplicação web em Python (Flask) com três ferramentas de segurança:

- **Força da senha**: entropia, tempo estimado para quebrar e dicas.
- **Verificador de link**: sinais de phishing (sem HTTPS, IP no lugar de domínio, `@`, punycode, encurtadores, palavras suspeitas).
- **Gerador de senhas**: usa o módulo `secrets` (criptograficamente seguro).

Nenhuma senha ou URL é salva ou registrada.

## Estrutura

```
safecheck/
├── app.py              # rotas Flask
├── checker.py          # lógica de segurança
├── templates/index.html
├── static/style.css
├── static/app.js
├── tests/test_app.py
├── requirements.txt
├── Procfile            # Railway / Heroku
└── render.yaml         # Render
```

## Rodar no VS Code

1. Instale o **Python 3.10+** e a extensão **Python** do VS Code.
2. Abra a pasta: `File > Open Folder > safecheck`.
3. Abra o terminal (`Ctrl+'`) e rode:

   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   pip install -r requirements-dev.txt
   python app.py
   ```
4. Acesse http://localhost:5000.
5. Testes: `pytest -v`.

Dica: `Ctrl+Shift+P > Python: Select Interpreter` e escolha o `.venv`. Com `F5` o app roda em modo debug (config em `.vscode/launch.json`).

## Hospedar (grátis): Render

1. Crie uma conta no GitHub e suba o projeto:

   ```bash
   git init
   git add .
   git commit -m "SafeCheck"
   git branch -M main
   git remote add origin https://github.com/SEU_USUARIO/safecheck.git
   git push -u origin main
   ```
2. Em https://render.com, clique em **New + > Web Service** e conecte o repositório.
3. O Render lê o `render.yaml`. Se preferir manual:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
4. Clique em **Deploy**. Em alguns minutos você recebe uma URL `https://safecheck-xxxx.onrender.com`.

No plano grátis o app "dorme" após inatividade e a primeira visita pode levar ~30 s.

## Alternativas

- **Railway:** `New Project > Deploy from GitHub`. O `Procfile` já resolve.
- **PythonAnywhere:** envie os arquivos, crie um *Web app > Flask* e aponte o WSGI para `app.app`.

## Ideias para evoluir

- Checar a senha no serviço *Have I Been Pwned* (k-anonymity).
- Consultar a API do Google Safe Browsing para URLs.
- Salvar histórico de verificações com SQLite (sem guardar senhas).
- Limitar requisições com `Flask-Limiter`.
