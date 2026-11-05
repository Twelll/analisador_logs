"""LogSentinel - analisador de logs SSH e web (esqueleto da Sprint 2).

Aqui ficam apenas as assinaturas e o contrato de cada função, que os testes
de test_logsentinel.py usam como especificação. A implementação é a Sprint 3.
"""

DEFAULT_CONFIG = {
    "ssh_falhas_limite": 5,
    "ssh_janela_segundos": 60,
    "web_404_limite": 10,
    "web_404_janela_segundos": 60,
}


def parse_ssh_line(linha, year=2026):
    """Lê uma linha de log SSH (syslog).

    Retorna dict {"tipo": "ssh_falha" | "ssh_sucesso", "ip", "usuario",
    "horario": datetime} ou None se a linha não for de login SSH.
    """
    raise NotImplementedError


def parse_web_line(linha):
    """Lê uma linha de acesso web em Combined (Apache).

    Retorna dict {"tipo": "web", "ip", "horario", "metodo", "caminho",
    "status": int} ou None se a linha não estiver no formato.
    """
    raise NotImplementedError


def detect_ssh_bruteforce(eventos, config):
    """Gera um alerta por IP com falhas SSH >= limite dentro da janela."""
    raise NotImplementedError


def detect_web_404(eventos, config):
    """Gera um alerta por IP com respostas 404 >= limite dentro da janela."""
    raise NotImplementedError


def calcular_nivel(ocorrencias, limite):
    """Nível de suspeita: inteiro de 1 a 10, que não diminui com mais ocorrências."""
    raise NotImplementedError


def analyze_lines(linhas, config=None, year=2026):
    """Analisa as linhas de um log.

    Retorna {"alertas": [...], "linhas_ignoradas": int}. Cada alerta é um dict
    com: ip, fonte ("ssh" | "web"), inicio, fim, ocorrencias, motivo, nivel,
    evidencias (lista de str).
    """
    raise NotImplementedError


def format_report(resultado):
    """Monta o texto do relatório a partir do resultado de analyze_lines."""
    raise NotImplementedError


def main(argv=None):
    """Ponto de entrada de linha de comando (argparse).

    Uso: python main.py [--ssh ARQUIVO] [--web ARQUIVO] [--ano ANO]
    Exige ao menos uma das opções --ssh ou --web e aceita ambas juntas.
    Lê os arquivos informados, analisa e imprime o relatório no terminal.
    --ano informa o ano dos registros SSH (padrão: 2026).
    Retorna 0 em caso de sucesso e um código diferente de 0 se algum arquivo
    não existir (com mensagem clara no stderr). Sem argumentos, o argparse
    mostra o modo de uso e encerra com SystemExit diferente de 0.
    """
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit(main())
