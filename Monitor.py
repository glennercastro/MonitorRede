from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP
import datetime
import socket
import threading
import dash
from dash import dcc, html, dash_table
import plotly.graph_objs as go
import pandas as pd
from functools import lru_cache

# Configurações
INTERFACE = "enp0s3"
LOG_FILE = "trafego_rede.log"

# Dicionários para armazenar estatísticas
trafego_por_site = {}
trafego_por_ip = {}
trafego_por_protocolo = {"TCP": 0, "UDP": 0, "OUTROS": 0}
ip_resolvidos = {}
logs = []
ips_excluidos = set()

# Função para resolver hostname com cache
@lru_cache(maxsize=1024)
def resolver_host(ip):
    """Resolve o nome do host a partir do IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

# Criando a aplicação Dash
app = dash.Dash(__name__)
app.title = "Monitoramento Profissional de Rede"

# Layout da aplicação Dash
app.layout = html.Div([
    html.H1("Monitoramento Profissional de Rede", style={'textAlign': 'center', 'color': '#007BFF'}),
    
    # Filtros
    html.Div([
        html.Label("Filtrar por IP:", style={'marginRight': '10px'}),
        dcc.Dropdown(id='filtro-ip', options=[], multi=True, placeholder="Selecione IPs...", style={'width': '300px'}),
    ], style={'display': 'inline-block'}),
    
    html.Div([
        html.Label("Filtrar por Domínio:", style={'marginLeft': '20px', 'marginRight': '10px'}),
        dcc.Dropdown(id='filtro-dominio', options=[], multi=True, placeholder="Selecione Domínios...", style={'width': '300px'}),
    ], style={'display': 'inline-block'}),
    
    # Gráficos
    dcc.Graph(id='grafico-trafego', style={'height': '50vh', 'marginBottom': '20px'}),
    dcc.Graph(id='grafico-protocolo', style={'height': '50vh', 'marginBottom': '20px'}),
    
    # Tabela de requisições
    html.H3("Requisições Capturadas"),
    html.Div([
        html.Label("Filtrar por IP de Origem:", style={'marginBottom': '10px'}),
        dcc.Dropdown(id='filtro-requisicoes-ip', options=[], multi=True, placeholder="Selecione IPs de origem...", style={'width': '400px'}),
    ]),
    dash_table.DataTable(
        id='tabela-requisicoes',
        columns=[
            {"name": "Timestamp", "id": "timestamp"},
            {"name": "IP de Origem", "id": "src_ip"},
            {"name": "Host de Origem", "id": "src_host"},
            {"name": "IP de Destino", "id": "dst_ip"},
            {"name": "Host de Destino", "id": "dst_host"},
            {"name": "Protocolo", "id": "protocolo"},
            {"name": "Domínio Consultado", "id": "site"}
        ],
        data=[],
        style_table={'overflowX': 'auto', 'margin-bottom': '20px'},
        style_header={'backgroundColor': '#007BFF', 'color': 'white', 'fontWeight': 'bold'},
        style_data={'backgroundColor': '#F8F9FA', 'color': '#000'}
    ),
    
    # Intervalo de atualização
    dcc.Interval(id='intervalo-atualizacao', interval=5000, n_intervals=0)
])

# Callback para processar pacotes
def packet_callback(packet):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            src_host = resolver_host(src_ip)
            dst_ip = packet[IP].dst
            dst_host = resolver_host(dst_ip)
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OUTROS"
            
            site = ""
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                site = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                trafego_por_site[site] = trafego_por_site.get(site, 0) + 1
            
            trafego_por_ip[src_ip] = trafego_por_ip.get(src_ip, 0) + 1
            trafego_por_protocolo[proto] += 1
            
            logs.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_host": src_host,
                "dst_ip": dst_ip,
                "dst_host": dst_host,
                "protocolo": proto,
                "site": site
            })
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")

# Callback para atualizar filtros e tabela de requisições
@app.callback(
    [dash.dependencies.Output('filtro-requisicoes-ip', 'options'),
     dash.dependencies.Output('tabela-requisicoes', 'data')],
    [dash.dependencies.Input('intervalo-atualizacao', 'n_intervals'),
     dash.dependencies.Input('filtro-requisicoes-ip', 'value')]
)
def atualizar_filtros_e_requisicoes(n, filtro_ip):
    ip_options = [{'label': ip, 'value': ip} for ip in trafego_por_ip.keys()]
    df = pd.DataFrame(logs)
    if not df.empty and filtro_ip:
        df = df[df['src_ip'].isin(filtro_ip)]
    return ip_options, df.to_dict('records')

# Callback para atualizar gráficos
@app.callback(
    [dash.dependencies.Output('grafico-trafego', 'figure'),
     dash.dependencies.Output('grafico-protocolo', 'figure')],
    [dash.dependencies.Input('intervalo-atualizacao', 'n_intervals')]
)
def atualizar_graficos(n):
    fig_trafego = go.Figure()
    if trafego_por_site:
        fig_trafego.add_trace(go.Bar(x=list(trafego_por_site.keys()), y=list(trafego_por_site.values()), marker_color='blue'))
        fig_trafego.update_layout(title='Tráfego de Rede por Domínio', xaxis_title='Domínios', yaxis_title='Número de Requisições')
    else:
        fig_trafego.update_layout(title='Nenhum dado disponível')
    
    fig_protocolo = go.Figure()
    if trafego_por_protocolo:
        fig_protocolo.add_trace(go.Pie(labels=list(trafego_por_protocolo.keys()), values=list(trafego_por_protocolo.values())))
        fig_protocolo.update_layout(title='Distribuição de Protocolos')
    else:
        fig_protocolo.update_layout(title='Nenhum dado disponível')
    
    return fig_trafego, fig_protocolo

# Iniciar thread para rodar o Dash
threading.Thread(target=lambda: app.run_server(host='0.0.0.0', port=5000, debug=False), daemon=True).start()

# Captura de pacotes na interface especificada
if __name__ == "__main__":
    print("Iniciando monitoramento de tráfego...")
    sniff(iface=INTERFACE, prn=packet_callback, store=False, promisc=True)
