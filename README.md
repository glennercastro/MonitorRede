# MonitorRede
Monitoramento Profissional de Rede em Pythom Sem a necessidade de um servidor DNS, ele capta as requisições e as exibe em uma interface web.

# OBS: Fique à vontade para copiar, usar ou modificar o código conforme necessário. Só peço que me mandem as alterações para eu também poder aprender e aproveitá-las.

0 - Acesse o código e insira o nome da sua interface de rede, que está na linha 19.
Exemplo: INTERFACE = "enp0s3"

1 - Requisitos
Antes de rodar o sistema, instale os pacotes necessarios executando o seguinte comando:
```sh
sudo apt update && sudo apt install -y python3 python3-pip python3-venv libpcap-dev
```
```sh
pip install dash dash-bootstrap-components scapy pandas plotly scikit-learn requests

```
2 - Criando um Ambiente Virtual (Opcional, mas Recomendado)
```sh
python3 -m venv monitor_env
```
 Linux/macOS
```sh
source monitor_env/bin/activate 
```
 Windows
```sh
monitor_env\Scripts\activate
```
```sh
pip install dash plotly pandas scapy
```
Acesse a interface web atraves do navegador em:
http://127.0.0.1:5000 ou http://192.168.X.X:5000

3 - Capturando Trafego de Toda a Rede
 Linux
```sh
sudo ip link set enp0s3 promisc on
```
 Windows
```sh
Set-NetAdapter -Name 'Ethernet' -PromiscuousMode On
```
4 - Executando o Monitor de Rede
```sh
sudo python Monitor.py
```
5 - Como Parar o Monitoramento?
CTRL + C # Para interromper no terminal
deactivate # Se estiver em ambiente virtual

6 - Possiveis Problemas e Solucoes
Se encontrar erros ao rodar o monitor, veja estas solucoes:
ModuleNotFoundError -> Execute pip install dash plotly pandas scapy
Permission Denied -> Rode com sudo: sudo python Monitor.py
Nao captura rede toda -> Ative o modo promiscuo no adaptador de rede
