"""LogSentinel - analisador de logs SSH e web (Sprint 3).

Lê logs de autenticação SSH (syslog) e de acesso web (Common/Combined),
procura IPs com comportamento suspeito e imprime um relatório no terminal.

Fluxo de dados:
    arquivo -> linhas -> eventos (parsers) -> alertas (detectores)
            -> resultado (analyze_lines) -> texto (format_report)

Uso:
    python logsentinel.py --ssh auth.log --web access.log [--ano 2026]
"""
import argparse
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

ANO_PADRAO = 2026  # o log SSH (syslog) não traz o ano

DEFAULT_CONFIG = {
    "ssh_falhas_limite": 5,
    "ssh_janela_segundos": 60,
    "web_404_limite": 10,
    "web_404_janela_segundos": 60,
}

MAX_EVIDENCIAS_NO_RELATORIO = 5

MESES = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# ---------------------------------------------------------------------------
# Leitura: de linha de texto para evento
# ---------------------------------------------------------------------------

# Ex.: Oct 27 20:16:26 ubuntu sshd-session[2853967]: Failed password for user from 192.0.2.10 port 19405 ssh2
_RE_SSH = re.compile(
    r"^(?P<mes>[A-Z][a-z]{2})\s+(?P<dia>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+\S+\s+"
    r"sshd(?:-session)?\[\d+\]:\s+(?P<resultado>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)"
)

# Ex.: 203.0.113.5 - - [27/Oct/2026:20:16:02 -0300] "GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"
_RE_WEB = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<dia>\d{2})/(?P<mes>[A-Za-z]{3})/(?P<ano>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) [+-]\d{4}\] "
    r'"(?P<metodo>[A-Z]+) (?P<caminho>\S+)(?: [^"]*)?" '
    r"(?P<status>\d{3}) (?:\d+|-)"
)


def parse_ssh_line(linha, year=ANO_PADRAO):
    """Lê uma linha de log SSH (syslog).

    Retorna dict {"tipo": "ssh_falha" | "ssh_sucesso", "ip", "usuario",
    "horario": datetime} ou None se a linha não for de login SSH.
    """
    m = _RE_SSH.match(linha.strip())
    if m is None or m["mes"] not in MESES:
        return None
    try:
        horario = datetime(
            year, MESES[m["mes"]], int(m["dia"]),
            int(m["h"]), int(m["m"]), int(m["s"]),
        )
    except ValueError:  # data impossível, como 30/02 
        return None
    tipo = "ssh_falha" if m["resultado"] == "Failed" else "ssh_sucesso"
    return {
        "tipo": tipo,
        "ip": m["ip"],
        "usuario": m["usuario"],
        "horario": horario
    }


def parse_web_line(linha):
    """Lê uma linha de acesso web (Common ou Combined, Apache/Nginx).

    Retorna dict {"tipo": "web", "ip", "horario", "metodo", "caminho",
    "status": int} ou None se a linha não estiver no formato.
    O fuso horário do log é ignorado: o horário é o que está escrito na linha.
    """
    m = _RE_WEB.match(linha.strip())
    if m is None or m["mes"] not in MESES:
        return None
    try:
        horario = datetime(
            int(m["ano"]), MESES[m["mes"]], int(m["dia"]),
            int(m["h"]), int(m["m"]), int(m["s"]),
        )
    except ValueError:
        return None
    return {
        "tipo": "web",
        "ip": m["ip"],
        "horario": horario,
        "metodo": m["metodo"],
        "caminho": m["caminho"],
        "status": int(m["status"]),
    }


# ---------------------------------------------------------------------------
# Detecção: de eventos para alertas
# ---------------------------------------------------------------------------

def _agrupar_por_ip(eventos):
    """Agrupa os eventos por IP, cada grupo em ordem de horário."""
    grupos = {}
    for evento in eventos:
        grupos.setdefault(evento["ip"], []).append(evento)
    for lista in grupos.values():
        lista.sort(key=lambda e: e["horario"])
    return grupos


def _janela_mais_cheia(eventos, janela_segundos):
    """Acha a sequência de eventos (ordenados) com mais itens dentro da janela.

    Retorna (inicio, fim): índices, inclusivos, do primeiro e do último evento.
    """
    melhor = (0, 0)
    inicio = 0
    for fim in range(len(eventos)):
        while (eventos[fim]["horario"] - eventos[inicio]["horario"]).total_seconds() > janela_segundos:
            inicio += 1
        if fim - inicio > melhor[1] - melhor[0]:
            melhor = (inicio, fim)
    return melhor


def calcular_nivel(ocorrencias, limite):
    """Nível de suspeita: inteiro de 1 a 10, que não diminui com mais ocorrências.

    Regra: 10 x ocorrências / (3 x limite), arredondado para baixo.
    Com 3 vezes o limite (ou mais) o nível chega a 10.
    Ex.: limite 5 e 12 falhas -> 8.
    """
    nivel = ocorrencias * 10 // (max(limite, 1) * 3)
    return max(1, min(10, nivel))


def detect_ssh_bruteforce(eventos, config):
    """Gera um alerta por IP com falhas SSH >= limite dentro da janela.

    O alerta descreve a janela mais cheia daquele IP.
    """
    limite = config["ssh_falhas_limite"]
    janela = config["ssh_janela_segundos"]
    falhas = [e for e in eventos if e["tipo"] == "ssh_falha"]

    alertas = []
    for ip, lista in _agrupar_por_ip(falhas).items():
        i, j = _janela_mais_cheia(lista, janela)
        na_janela = lista[i:j + 1]
        if len(na_janela) < limite:
            continue
        alertas.append({
            "ip": ip,
            "fonte": "ssh",
            "inicio": na_janela[0]["horario"],
            "fim": na_janela[-1]["horario"],
            "ocorrencias": len(na_janela),
            "motivo": "Falhas repetidas de autenticação SSH",
            "nivel": calcular_nivel(len(na_janela), limite),
            "evidencias": [
                f"{e['horario']:%d/%m %H:%M:%S} senha incorreta (usuário: {e['usuario']})"
                for e in na_janela
            ],
        })
    return alertas


def detect_web_404(eventos, config):
    """Gera um alerta por IP com respostas 404 >= limite dentro da janela.

    O alerta descreve a janela mais cheia daquele IP.
    """
    limite = config["web_404_limite"]
    janela = config["web_404_janela_segundos"]
    respostas_404 = [e for e in eventos if e["tipo"] == "web" and e["status"] == 404]

    alertas = []
    for ip, lista in _agrupar_por_ip(respostas_404).items():
        i, j = _janela_mais_cheia(lista, janela)
        na_janela = lista[i:j + 1]
        if len(na_janela) < limite:
            continue
        alertas.append({
            "ip": ip,
            "fonte": "web",
            "inicio": na_janela[0]["horario"],
            "fim": na_janela[-1]["horario"],
            "ocorrencias": len(na_janela),
            "motivo": "Excesso de respostas 404 (busca por páginas escondidas)",
            "nivel": calcular_nivel(len(na_janela), limite),
            "evidencias": [
                f"{e['horario']:%d/%m %H:%M:%S} {e['metodo']} {e['caminho']} -> 404"
                for e in na_janela
            ],
        })
    return alertas


# ---------------------------------------------------------------------------
# Análise e relatório
# ---------------------------------------------------------------------------

def _ordenar(alertas):
    """Do mais suspeito para o menos: nível, depois ocorrências, depois IP."""
    return sorted(alertas, key=lambda a: (-a["nivel"], -a["ocorrencias"], a["ip"]))


def analyze_lines(linhas, config=None, year=ANO_PADRAO):
    """Analisa as linhas de um log (SSH, web ou os dois misturados).

    Retorna {"alertas": [...], "linhas_ignoradas": int}. Cada alerta é um dict
    com: ip, fonte ("ssh" | "web"), inicio, fim, ocorrencias, motivo, nivel,
    evidencias (lista de str). Linhas em branco não contam como ignoradas.
    """
    cfg = dict(DEFAULT_CONFIG)
    if config:
        cfg.update(config)

    eventos = []
    ignoradas = 0
    for linha in linhas:
        linha = linha.strip()
        if not linha:
            continue
        evento = parse_ssh_line(linha, year) or parse_web_line(linha)
        if evento is None:
            ignoradas += 1
        else:
            eventos.append(evento)

    alertas = detect_ssh_bruteforce(eventos, cfg) + detect_web_404(eventos, cfg)
    return {"alertas": _ordenar(alertas), "linhas_ignoradas": ignoradas}


def _formatar_periodo(inicio, fim):
    if inicio.date() == fim.date():
        return f"{inicio:%d/%m}, das {inicio:%H:%M:%S} às {fim:%H:%M:%S}"
    return f"{inicio:%d/%m %H:%M} a {fim:%d/%m %H:%M}"


def format_report(resultado):
    """Monta o texto do relatório a partir do resultado de analyze_lines."""
    alertas = _ordenar(resultado["alertas"])
    texto = ["=== LogSentinel - Relatório de análise ==="]

    if not alertas:
        texto.append("Nenhuma atividade suspeita encontrada.")
    else:
        texto.append(f"{len(alertas)} alerta(s), do mais para o menos suspeito.")
        for alerta in alertas:
            fonte = "SSH" if alerta["fonte"] == "ssh" else "Web"
            texto.append("")
            texto.append(f"IP analisado: {alerta['ip']}")
            texto.append(f"Fonte: {fonte}")
            texto.append(f"Período: {_formatar_periodo(alerta['inicio'], alerta['fim'])}")
            texto.append(f"Ocorrências: {alerta['ocorrencias']}")
            texto.append(f"Motivo: {alerta['motivo']}")
            texto.append(f"Nível de suspeita: {alerta['nivel']}/10")
            evidencias = alerta["evidencias"]
            if evidencias:
                texto.append("Evidências:")
                for e in evidencias[:MAX_EVIDENCIAS_NO_RELATORIO]:
                    texto.append(f"  - {e}")
                restantes = len(evidencias) - MAX_EVIDENCIAS_NO_RELATORIO
                if restantes > 0:
                    texto.append(f"  (e mais {restantes})")

    texto.append("")
    texto.append(f"Linhas ignoradas: {resultado['linhas_ignoradas']}")
    return "\n".join(texto)


# ---------------------------------------------------------------------------
# Linha de comando
# ---------------------------------------------------------------------------

def _ler_linhas(caminho):
    # newline="" mantém o \r\n do fim das linhas; o parser faz strip()
    with open(caminho, encoding="utf-8", errors="replace", newline="") as arquivo:
        return arquivo.readlines()


def main(argv=None):
    """Ponto de entrada de linha de comando.

    Uso: python logsentinel.py [--ssh ARQUIVO] [--web ARQUIVO] [--ano ANO]
    Exige ao menos --ssh ou --web e aceita os dois juntos. Imprime o relatório
    no terminal e retorna 0; se um arquivo não puder ser lido, escreve a
    mensagem no stderr e retorna 1. Sem arquivo, o argparse mostra o modo de
    uso e encerra com SystemExit diferente de 0.
    """
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Analisa logs SSH e web e aponta IPs com atividade suspeita.",
    )
    parser.add_argument("--ssh", metavar="ARQUIVO", help="log de autenticação SSH (syslog)")
    parser.add_argument("--web", metavar="ARQUIVO", help="log de acesso web (Common ou Combined)")
    parser.add_argument(
        "--ano", type=int, default=ANO_PADRAO,
        help=f"ano dos registros SSH, que não trazem o ano (padrão: {ANO_PADRAO})",
    )
    args = parser.parse_args(argv)

    if not args.ssh and not args.web:
        parser.error("informe ao menos um arquivo com --ssh ou --web")

    linhas = []
    for caminho in (args.ssh, args.web):
        if caminho is None:
            continue
        try:
            linhas += _ler_linhas(caminho)
        except FileNotFoundError:
            print(f"Erro: arquivo não encontrado: {caminho}", file=sys.stderr)
            return 1
        except OSError as erro:
            print(f"Erro ao ler {caminho}: {erro.strerror}", file=sys.stderr)
            return 1

    resultado = analyze_lines(linhas, year=args.ano)
    print(format_report(resultado))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
