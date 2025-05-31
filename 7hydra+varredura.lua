-- netsentry.lua
-- NetSentry: Ferramenta educacional de cibersegurança para celulares
-- Uso exclusivo em ambientes autorizados!

local NetSentry = {}

-- Banco de vulnerabilidades estático
NetSentry.vulns_db = {
    ["OpenSSH 7.6p1"] = { cve = "CVE-2018-15473", cvss = 5.3, desc = "Username Enumeration" },
    ["Apache/2.4.41"] = { cve = "CVE-2021-41773", cvss = 7.5, desc = "Path Traversal" },
    ["vsftpd 3.0.3"] = { cve = "CVE-2011-2523", cvss = 9.8, desc = "Backdoor Command Execution" }
}

-- Simulação de varredura de rede
function NetSentry:network_scan(ip_range)
    self:log_session("[*] Iniciando varredura simulada em " .. ip_range)
    
    -- Dados fictícios para simular hosts
    local hosts = {
        { ip = "192.168.1.100", services = {
            { port = 21, service = "ftp", version = "vsftpd 3.0.3" },
            { port = 80, service = "http", version = "Apache/2.4.41" }
        }},
        { ip = "192.168.1.101", services = {
            { port = 22, service = "ssh", version = "OpenSSH 7.6p1" }
        }}
    }
    
    self:log_session("[+] Varredura concluída: " .. #hosts .. " hosts encontrados")
    return {
        scan_range = ip_range,
        hosts_encontrados = #hosts,
        detalhes = hosts
    }
end

-- Verificação de vulnerabilidades
function NetSentry:vulnerability_check(scan_results)
    self:log_session("[*] Iniciando verificação de vulnerabilidades")
    local vulnerabilities = {}
    
    for _, host in ipairs(scan_results.detalhes) do
        for _, service in ipairs(host.services) do
            local version = service.version
            if self.vulns_db[version] then
                table.insert(vulnerabilities, {
                    ip = host.ip,
                    port = service.port,
                    service = service.service,
                    cve = self.vulns_db[version].cve,
                    cvss = self.vulns_db[version].cvss,
                    description = self.vulns_db[version].desc
                })
            end
        end
    end
    
    self:log_session("[+] " .. #vulnerabilities .. " vulnerabilidades identificadas")
    return vulnerabilities
end

-- Geração de relatório
function NetSentry:generate_report(simulation_id, scan_results, vulnerabilities)
    self:log_session("[*] Gerando relatório " .. simulation_id)
    
    local report = "=== RELATÓRIO DE SEGURANÇA ===\n"
    report = report .. "ID: " .. simulation_id .. "\n"
    report = report .. "Data: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n"
    report = report .. "Intervalo Escaneado: " .. scan_results.scan_range .. "\n"
    report = report .. "Hosts Encontrados: " .. scan_results.hosts_encontrados .. "\n\n"
    report = report .. "Vulnerabilidades:\n"
    
    for _, vuln in ipairs(vulnerabilities) do
        report = report .. "- IP: " .. vuln.ip .. " | Porta: " .. vuln.port .. " | Serviço: " .. vuln.service .. "\n"
        report = report .. "  CVE: " .. vuln.cve .. " | CVSS: " .. vuln.cvss .. " | " .. vuln.description .. "\n"
    end
    
    report = report .. "\nRecomendações:\n"
    report = report .. "- Aplicar patches de segurança.\n"
    report = report .. "- Configurar firewall.\n"
    report = report .. "- Usar autenticação forte.\n\n"
    report = report .. "Evidências:\n"
    for _, host in ipairs(scan_results.detalhes) do
        report = report .. "IP: " .. host.ip .. "\n"
        for _, svc in ipairs(host.services) do
            report = report .. "  Porta " .. svc.port .. ": " .. svc.service .. " (" .. svc.version .. ")\n"
        end
    end
    
    -- Salvar relatório em arquivo
    local file = io.open("report_" .. simulation_id .. ".txt", "w")
    if file then
        file:write(report)
        file:close()
        self:log_session("[+] Relatório salvo em report_" .. simulation_id .. ".txt")
    end
    
    return report
end

-- Registro de logs
function NetSentry:log_session(event)
    local log_entry = "[" .. os.date("%Y-%m-%dT%H:%M:%S") .. "] " .. event .. "\n"
    table.insert(self.session_logs or {}, log_entry)
    local file = io.open("session_logs.txt", "a")
    if file then
        file:write(log_entry)
        file:close()
    end
end

-- Módulo de treinamento
local CyberSecTraining = {}

function CyberSecTraining:new()
    local o = {
        courses = {
            beginner = {
                { name = "Introdução à Segurança", cert = "CompTIA Security+", hours = 40, desc = "Noções básicas de segurança" },
                { name = "Redes Básicas", cert = "Network+", hours = 30, desc = "Protocolos de rede" }
            },
            intermediate = {
                { name = "Teste de Invasão Web", cert = "CEH", hours = 60, desc = "Ataques SQLi e XSS" }
            }
        }
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

function CyberSecTraining:start_course(level)
    if not self.courses[level] then
        return { error = "Nível " .. level .. " não encontrado" }
    end
    local course = self.courses[level][1]
    return {
        curso = course.name,
        nivel = level,
        certificacao = course.cert,
        duracao = tostring(math.floor(course.hours / 4)) .. " semanas",
        horas_totais = course.hours,
        modulos = { { name = "Teoria", hours = 10 }, { name = "Prática", hours = 15 } }
    }
end

-- Função principal
function main()
    local simulator = NetSentry
    local training = CyberSecTraining:new()
    
    print("\n=== [VARREDURA DE REDE] ===")
    local scan_results = simulator:network_scan("192.168.1.0/24")
    print("Hosts encontrados: " .. scan_results.hosts_encontrados)
    for _, host in ipairs(scan_results.detalhes) do
        print("\nIP: " .. host.ip)
        for _, svc in ipairs(host.services) do
            print("  Porta " .. svc.port .. ": " .. svc.service .. " (" .. svc.version .. ")")
        end
    end
    
    print("\n=== [VERIFICAÇÃO DE VULNERABILIDADES] ===")
    local vulnerabilities = simulator:vulnerability_check(scan_results)
    if #vulnerabilities > 0 then
        for _, vuln in ipairs(vulnerabilities) do
            print("IP: " .. vuln.ip .. " | Porta: " .. vuln.port .. " | CVE: " .. vuln.cve)
        end
    else
        print("Nenhuma vulnerabilidade encontrada.")
    end
    
    print("\n=== [RELATÓRIO DE SEGURANÇA] ===")
    local report = simulator:generate_report("SEC-2025-001", scan_results, vulnerabilities)
    print(report)
    
    print("\n=== [TREINAMENTO] ===")
    local course = training:start_course("beginner")
    if not course.error then
        print("Curso: " .. course.curso .. " (" .. course.certificacao .. ")")
        print("Duração: " .. course.duracao .. " (" .. course.horas_totais .. " horas)")
        print("Módulos:")
        for _, module in ipairs(course.modulos) do
            print("- " .. module.name .. " (" .. module.hours .. " horas)")
        end
    end
end

-- Executar
main()
