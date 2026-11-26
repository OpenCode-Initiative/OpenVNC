# Configuracao pos-instalacao do OpenVNC Server no Windows (roda elevado).
#
#   setup.ps1 -Install   -Dir <pasta de instalacao>
#   setup.ps1 -Uninstall
#
# Na instalacao: gera a config base (so se nao existir, sem senha: quem define
# e o assistente "OpenVNC Configuracoes"), restringe a pasta de dados a
# Administradores e SYSTEM, gera o certificado TLS, libera as portas no
# firewall e cria a tarefa agendada que inicia o servidor no logon. O servidor roda na sessao do usuario (nao como servico),
# porque um servico fica na sessao 0, que nao tem acesso a tela.
param(
    [switch]$Install,
    [switch]$Uninstall,
    [string]$Dir = "$env:ProgramFiles\OpenVNC",
    [int]$Port = 5900
)
$ErrorActionPreference = 'Stop'
$Data = Join-Path $env:ProgramData 'OpenVNC'
$State = Join-Path $Data 'state'
$Config = Join-Path $Data 'openvnc.toml'
$Cred = Join-Path $Data 'credenciais.txt'
$Task = 'OpenVNC Server'
$Rule = 'OpenVNC Server'

# UTF-8 sem BOM (o Windows PowerShell 5.1 grava BOM, que o TOML rejeita)
function Write-Utf8([string]$Path, [Parameter(ValueFromPipeline)][string]$Text) {
    process { [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false)) }
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process openvnc-server -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-NetFirewallRule -DisplayName "$Rule*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    exit 0
}
if (-not $Install) { throw 'use -Install ou -Uninstall' }

New-Item -ItemType Directory -Force $State | Out-Null
# so Administradores e SYSTEM leem a pasta de dados (senha, chave TLS, tokens)
icacls $Data /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null

$server = Join-Path $Dir 'openvnc-server.exe'
$Native = $Port + 1
# versoes anteriores gravavam a senha em texto num arquivo a parte
Remove-Item $Cred -Force -ErrorAction SilentlyContinue
if (-not (Test-Path $Config)) {
    @"
# OpenVNC Server. Use "OpenVNC Configuracoes" para ajustar.
listen = "0.0.0.0:$Port"
native_listen = "0.0.0.0:$Native"
capture = "native"
require_tls = true
pairing = true
view_only = false
lan_only = true
state_dir = '$State'
name = "$env:COMPUTERNAME"
# o servidor so e iniciado depois do assistente
setup_done = false
"@ | Write-Utf8 $Config
}

# configs de versoes anteriores nao tinham view_only (padrao: so visualizacao)
if (-not (Select-String -Path $Config -Pattern '^\s*view_only\s*=' -Quiet)) {
    Add-Content -Path $Config -Encoding ascii -Value "`n# Permite controlar mouse e teclado.`nview_only = false"
}

# certificado TLS ja na instalacao (o assistente mostra a impressao digital)
$env:OPENVNC_SERVER_DIR = $State
& $server --config $Config fingerprint | Out-Null

# regras iniciais (so rede local) enquanto o assistente nao rodou; depois
# dele, as regras escolhidas sao mantidas
$SetupDone = Select-String -Path $Config -Pattern '^\s*setup_done\s*=\s*true' -Quiet
if (-not $SetupDone) {
    Get-NetFirewallRule -DisplayName "$Rule*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $Rule -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort $Port, $Native -Program $server -Profile Private, Domain `
        -RemoteAddress LocalSubnet | Out-Null
    New-NetFirewallRule -DisplayName "$Rule (QUIC)" -Direction Inbound -Action Allow -Protocol UDP `
        -LocalPort $Native -Program $server -Profile Private, Domain `
        -RemoteAddress LocalSubnet | Out-Null
}

# conhost --headless: console sem janela, na sessao interativa do usuario
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
    -Argument "--headless `"$server`" --config `"$Config`" --tray" -WorkingDirectory $Data
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-544' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Get-Process openvnc-server -ErrorAction SilentlyContinue | Stop-Process -Force
if ($SetupDone) {
    Start-ScheduledTask -TaskName $Task
}
