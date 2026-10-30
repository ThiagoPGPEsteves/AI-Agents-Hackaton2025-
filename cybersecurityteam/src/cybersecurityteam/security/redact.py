import re

# Padrões para higienização e prevenção de vazamento de dados sensíveis (LGPD / PCI-DSS)
RE_PASSWORD = re.compile(r'(?i)(password|passwd|pwd|senha|secret)\s*[:=]\s*([^\s,;&"\']+)', re.IGNORECASE)
RE_BEARER = re.compile(r'(?i)(bearer|token|apikey|api_key)\s*[:=]?\s*([a-zA-Z0-9_\-\.]{10,})', re.IGNORECASE)
RE_AUTH_HEADER = re.compile(r'(?i)authorization:\s*(basic|bearer)\s+[a-zA-Z0-9+/=_\-\.]+', re.IGNORECASE)
RE_CPF = re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b')
RE_CREDIT_CARD = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b')
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')

def redact_sensitive_data(text: str, max_length: int = 200) -> str:
    """
    Remove ou mascara credenciais, tokens, CPFs, cartões e e-mails de strings de log.
    Também trunca o texto para evitar estouro de tokens e mitigar prompt injection.
    """
    if not text:
        return ""
    
    # Mascara senhas
    text = RE_PASSWORD.sub(r'\1=[REDACTED]', text)
    # Mascara headers de autorização
    text = RE_AUTH_HEADER.sub('Authorization: [REDACTED]', text)
    # Mascara tokens
    text = RE_BEARER.sub(r'\1=[REDACTED]', text)
    # Mascara cartões de crédito
    text = RE_CREDIT_CARD.sub('[CARD_REDACTED]', text)
    # Mascara CPFs
    text = RE_CPF.sub('[CPF_REDACTED]', text)
    # Mascara e-mails
    text = RE_EMAIL.sub('[EMAIL_REDACTED]', text)
    
    # Trunca texto para limite seguro
    if len(text) > max_length:
        text = text[:max_length] + " [TRUNCATED...]"
        
    return text
