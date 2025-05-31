import subprocess
import re
import os
from datetime import datetime

class CyberSecTerminal:
    """
    Terminal de segurança cibernética leve para PCs antigos.
    Uso exclusivo em ambientes autorizados e controlados.
    """

    def __init__(self):
        self.session_logs = []
        self.vulnerabilities_db = {
            "OpenSSH 7.6p1": {"cve": "CVE-2018-15473", "cvss": 5.3, "desc": "Username Enumeration"},
            "Apache/2.4.41": {"cve": "CVE-2021-41773", "cvss": 7.5, "desc": "Path Traversal"},
            "vsftpd 3.0.3": {"cve": "CVE-2011-2523", "cvss": 9.8, "desc": "Backdoor Command Execution"},
            "Microsoft Windows SMB": {"cve": "CVE-2017-0144", "cvss": 8.8, "desc": "EternalBlue Exploit"}
        }

    def _log_session(self, event):
        """Registra eventos em um arquivo de texto simples."""
        log_entry = f"[{datetime.now().isoformat()}] {event}\n"
        self.session_logs.append(log_entry)
        with open("session_logs.txt", "a") as f:
            f.write(log_entry)

    def _validate_ip_range(self, ip_range):
        """Valida o intervalo de IP de forma simples."""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-2]?[0-9]|3[0-2]))?$"
        return bool(re.match(pattern, ip_range))

    def network_scan(self, ip_range):
        """Executa varredura leve com nmap."""
        if not self._validate_ip_range(ip_range):
            return {"error": "Intervalo de IP inválido"}

        self._log_session(f"[*] Iniciando varredura em {ip_range}")
        try:
            # Varredura leve: apenas portas comuns, modo não agressivo
            cmd = f"nmap -sV --open -T3 -p 21,22,80,443,445 {ip_range}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = result.stdout

            hosts = []
            current_host = None
            for line in output.splitlines():
                if "Nmap scan report for" in line:
                    ip = line.split()[-1].strip("()")
                    current_host = {"ip": ip, "services": []}
                    hosts.append(current_host)
                elif "/tcp" in line and "open" in line and current_host:
                    parts = line.split()
                    port = parts[0].split("/")[0]
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    current_host["services"].append({
                        "port": port,
                        "service": service,
                        "version": version
                    })

            self._log_session(f"[+] Varredura concluída: {len(hosts)} hosts encontrados")
            return {
                "scan_range": ip_range,
                "hosts_encontrados": len(hosts),
                "detalhes": hosts
            }

        except Exception as e:
            self._log_session(f"[!] Erro na varredura: {str(e)}")
            return {"error": f"Falha na varredura: {str(e)}"}

    def vulnerability_check(self, scan_results):
        """Verifica vulnerabilidades nos serviços encontrados."""
        self._log_session("[*] Iniciando verificação de vulnerabilidades")
        vulnerabilities = []

        for host in scan_results.get("detalhes", []):
            for service in host["services"]:
                service_key = service["version"].strip()
                if service_key in self.vulnerabilities_db:
                    vuln = self.vulnerabilities_db[service_key]
                    vulnerabilities.append({
                        "ip": host["ip"],
                        "port": service["port"],
                        "service": service["service"],
                        "cve": vuln["cve"],
                        "cvss": vuln["cvss"],
                        "description": vuln["desc"]
                    })

        self._log_session(f"[+] {len(vulnerabilities)} vulnerabilidades identificadas")
        return vulnerabilities

    def generate_report(self, simulation_id, scan_results, vulnerabilities):
        """Gera relatório simples em texto."""
        self._log_session(f"[*] Gerando relatório {simulation_id}")

        report = f"""
=== RELATÓRIO DE SEGURANÇA ===
ID: {simulation_id}
Data: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Intervalo Escaneado: {scan_results.get("scan_range", "unknown")}
Hosts Encontrados: {scan_results.get("hosts_encontrados", 0)}

Vulnerabilidades:
"""
        for vuln in vulnerabilities:
            report += f"- IP: {vuln['ip']} | Porta: {vuln['port']} | Serviço: {vuln['service']}\n"
            report += f"  CVE: {vuln['cve']} | CVSS: {vuln['cvss']} | {vuln['description']}\n"

        report += """
Recomendações:
- Aplicar patches de segurança.
- Configurar firewall para portas desnecessárias.
- Usar autenticação forte.
- Monitorar logs regularmente.

Evidências:
"""
        for host in scan_results.get("detalhes", []):
            report += f"IP: {host['ip']}\n"
            for svc in host["services"]:
                report += f"  Porta {svc['port']}: {svc['service']} ({svc['version']})\n"

        # Salvar relatório
        report_file = f"report_{simulation_id}.txt"
        with open(report_file, "w") as f:
            f.write(report)

        self._log_session(f"[+] Relatório salvo em {report_file}")
        return report

class CyberSecTraining:
    """
    Módulo de treinamento em segurança cibernética.
    """

    def __init__(self):
        self.courses = {
            "beginner": [
                {"name": "Introdução à Segurança", "cert": "CompTIA Security+", "hours": 40, "desc": "Noções básicas de segurança"},
                {"name": "Redes Básicas", "cert": "Network+", "hours": 30, "desc": "Protocolos de rede"}
            ],
            "intermediate": [
                {"name": "Teste de Invasão Web", "cert": "CEH", "hours": 60, "desc": "Ataques SQLi e XSS"},
                {"name": "Análise de Malware", "cert": "GREM", "hours": 50, "desc": "Técnicas de análise"}
            ]
        }

    def start_course(self, level):
        if level not in self.courses:
            return {"error": f"Nível {level} não encontrado"}

        selected_course = self.courses[level][0]  # Escolha fixa para simplicidade
        modules = [
            {"name": "Teoria", "hours": 10},
            {"name": "Prática", "hours": 15}
        ]

        return {
            "curso": selected_course["name"],
            "nivel": level,
            "certificacao": selected_course["cert"],
            "duracao": f"{selected_course['hours'] // 4} semanas",
            "horas_totais": selected_course["hours"],
            "modulos": modules
        }

# Exemplo de uso
def main():
    simulator = CyberSecTerminal()
    training = CyberSecTraining()

    # Varredura de rede
    ip_range = "192.168.1.0/24"  # Ajuste para sua rede local
    print("\n=== [VARREDURA DE REDE] ===")
    scan_results = simulator.network_scan(ip_range)
    if "error" not in scan_results:
        print(f"Hosts encontrados: {scan_results['hosts_encontrados']}")
        for host in scan_results["detalhes"]:
            print(f"\nIP: {host['ip']}")
            for svc in host["services"]:
                print(f"  Porta {svc['port']}: {svc['service']} ({svc['version']})")

    # Verificação de vulnerabilidades
    print("\n=== [VERIFICAÇÃO DE VULNERABILIDADES] ===")
    vulnerabilities = simulator.vulnerability_check(scan_results)
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"IP: {vuln['ip']} | Porta: {vuln['port']} | CVE: {vuln['cve']}")
    else:
        print("Nenhuma vulnerabilidade encontrada.")

    # Relatório
    print("\n=== [RELATÓRIO DE SEGURANÇA] ===")
    report = simulator.generate_report("SEC-2025-001", scan_results, vulnerabilities)
    print(report)

    # Treinamento
    print("\n=== [TREINAMENTO] ===")
    course = training.start_course("beginner")
    if "error" not in course:
        print(f"Curso: {course['curso']} ({course['certificacao']})")
        print(f"Duração: {course['duracao']} ({course['horas_totais']} horas)")
        print("Módulos:")
        for module in course["modulos"]:
            print(f"- {module['name']} ({module['hours']} horas)")

if __name__ == "__main__":
    main()
