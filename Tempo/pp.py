from flask import Flask, request, jsonify
from flask_cors import CORS  # Para permitir requisições do frontend

app = Flask(__name__)
CORS(app)  # Habilita requisições do JavaScript no navegador

# Função para analisar ameaças no texto (exemplo simples)
def analisar_ameaca(texto):
    palavras_suspeitas = ["ataque", "hack", "exploit", "malware", "phishing"]
    
    for palavra in palavras_suspeitas:
        if palavra in texto.lower():
            return "⚠️ Ameaça detectada! O texto contém possíveis riscos."
    
    return "✅ Nenhuma ameaça detectada."

# Criar uma rota para receber textos e analisar
@app.route('/analisar', methods=['POST'])
def analisar():
    dados = request.json  # Recebe os dados do frontend (JSON)
    texto = dados.get("texto", "")

    resultado = analisar_ameaca(texto)  # Chama a função de análise

    return jsonify({"mensagem": resultado})  # Retorna a resposta em JSON

# Rodar o servidor Flask
if __name__ == '__main__':
    app.run(debug=True)
