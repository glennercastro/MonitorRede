import logging
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP
import datetime
import socket
import threading
import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, dash_table
import plotly.graph_objs as go
import pandas as pd
from functools import lru_cache
from sklearn.ensemble import IsolationForest

# Configurações
INTERFACE = "enp0s3"

# Estruturas para armazenar dados capturados
trafego_por_site = {}
trafego_por_ip = {}
trafego_por_protocolo = {"TCP": 0, "UDP": 0, "OUTROS": 0}
logs_data = []

# Lock para sincronização entre threads
data_lock = threading.Lock()

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Função para resolver hostnames com cache
@lru_cache(maxsize=1024)
def resolver_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

# Função para processar pacotes capturados
def packet_callback(packet):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            with data_lock:
                src_host = resolver_host(src_ip)
                dst_host = resolver_host(dst_ip)
                # Determina o protocolo
                if packet.haslayer(TCP):
                    proto = "TCP"
                elif packet.haslayer(UDP):
                    proto = "UDP"
                else:
                    proto = "OUTROS"
                site = ""
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    try:
                        site = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    except Exception as decode_error:
                        logging.error(f"Erro ao decodificar domínio: {decode_error}")
                        site = ""
                    trafego_por_site[site] = trafego_por_site.get(site, 0) + 1
                trafego_por_ip[src_ip] = trafego_por_ip.get(src_ip, 0) + 1
                trafego_por_protocolo[proto] = trafego_por_protocolo.get(proto, 0) + 1

                logs_data.append({
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "src_host": src_host,
                    "dst_ip": dst_ip,
                    "dst_host": dst_host,
                    "protocolo": proto,
                    "site": site
                })
    except Exception as e:
        logging.error(f"Erro ao processar pacote: {e}")

# Configuração do Dash com tema dark (DARKLY)
external_stylesheets = [dbc.themes.DARKLY]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "Monitoramento Profissional de Rede"

# Layout geral com abas (Dashboard, Logs, Configurações e Anomalias)
app.layout = dbc.Container([
    dbc.Row(
        dbc.Col(html.H1("Monitoramento Profissional de Rede", className="text-center mb-4"), width=12)
    ),
    dbc.Tabs(
        id="tabs", active_tab="tab-dashboard",
        children=[
            dbc.Tab(label="Dashboard", tab_id="tab-dashboard"),
            dbc.Tab(label="Logs", tab_id="tab-logs"),
            dbc.Tab(label="Configurações", tab_id="tab-config"),
            dbc.Tab(label="Anomalias", tab_id="tab-anomalias")
        ]
    ),
    html.Div(id="tab-content", className="p-4"),
    # Intervalo para atualização dos dados (a cada 5 segundos)
    dcc.Interval(id="intervalo-atualizacao", interval=5000, n_intervals=0)
], fluid=True)

# Callback para renderizar o conteúdo de cada aba
@app.callback(
    dash.dependencies.Output("tab-content", "children"),
    [dash.dependencies.Input("tabs", "active_tab")]
)
def render_content(active_tab):
    if active_tab == "tab-dashboard":
        return dbc.Container([
            dbc.Row([
                dbc.Col(dcc.Graph(id="grafico-trafego"), md=6),
                dbc.Col(dcc.Graph(id="grafico-protocolo"), md=6)
            ])
        ])
    elif active_tab == "tab-logs":
        return dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.Label("Filtrar por IP:"),
                    dcc.Dropdown(id="filtro-logs-ip", multi=True, placeholder="Selecione IP(s)")
                ], md=4),
                dbc.Col([
                    html.Label("Filtrar por Protocolo:"),
                    dcc.Dropdown(
                        id="filtro-logs-protocolo",
                        options=[
                            {"label": "TCP", "value": "TCP"},
                            {"label": "UDP", "value": "UDP"},
                            {"label": "OUTROS", "value": "OUTROS"}
                        ],
                        multi=True,
                        placeholder="Selecione protocolo(s)"
                    )
                ], md=4),
                dbc.Col([
                    html.Label("Filtrar por Domínio:"),
                    dcc.Dropdown(id="filtro-logs-dominio", multi=True, placeholder="Selecione domínio(s)")
                ], md=4)
            ], className="mb-4"),
            dash_table.DataTable(
                id="tabela-logs",
                columns=[
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "IP de Origem", "id": "src_ip"},
                    {"name": "Host de Origem", "id": "src_host"},
                    {"name": "IP de Destino", "id": "dst_ip"},
                    {"name": "Host de Destino", "id": "dst_host"},
                    {"name": "Protocolo", "id": "protocolo"},
                    {"name": "Domínio", "id": "site"}
                ],
                data=[],
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#343a40", "color": "white", "fontWeight": "bold"},
                style_data={"backgroundColor": "#212529", "color": "white"}
            )
        ])
    elif active_tab == "tab-config":
        return dbc.Container([
            html.H3("Configurações"),
            html.P("Defina as configurações desejadas para o monitoramento."),
            html.Div([
                dbc.Label("Exemplo de Configuração:"),
                dbc.Input(id="input-config", type="text", placeholder="Digite um valor...")
            ], className="mb-3"),
            dbc.Button("Salvar Configurações", id="btn-salvar", color="primary", className="mt-2"),
            html.Div(id="config-output", className="mt-3")
        ])
    elif active_tab == "tab-anomalias":
        return dbc.Container([
            html.H3("Anomalias Detectadas"),
            dash_table.DataTable(
                id="tabela-anomalias",
                columns=[
                    {"name": "IP", "id": "IP"},
                    {"name": "Requisições", "id": "Requisições"},
                    {"name": "Anomalia", "id": "Anomalia"}
                ],
                data=[],
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#343a40", "color": "white", "fontWeight": "bold"},
                style_data={"backgroundColor": "#212529", "color": "white"}
            )
        ])
    return html.Div("Selecione uma aba para visualizar o conteúdo.")

# Callback para atualizar os gráficos da aba Dashboard
@app.callback(
    [dash.dependencies.Output("grafico-trafego", "figure"),
     dash.dependencies.Output("grafico-protocolo", "figure")],
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_dashboard(n_intervals):
    with data_lock:
        trafego_site = trafego_por_site.copy()
        trafego_protocol = trafego_por_protocolo.copy()
    fig_trafego = go.Figure(data=[
        go.Bar(x=list(trafego_site.keys()), y=list(trafego_site.values()), marker_color='blue')
    ])
    fig_trafego.update_layout(title="Tráfego de Rede por Domínio", xaxis_title="Domínios", yaxis_title="Número de Requisições")
    
    fig_protocol = go.Figure(data=[
        go.Pie(labels=list(trafego_protocol.keys()), values=list(trafego_protocol.values()))
    ])
    fig_protocol.update_layout(title="Distribuição de Protocolos")
    
    return fig_trafego, fig_protocol

# Callback para atualizar a tabela de logs e os filtros na aba Logs
@app.callback(
    [dash.dependencies.Output("tabela-logs", "data"),
     dash.dependencies.Output("filtro-logs-ip", "options"),
     dash.dependencies.Output("filtro-logs-dominio", "options")],
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals"),
     dash.dependencies.Input("filtro-logs-ip", "value"),
     dash.dependencies.Input("filtro-logs-protocolo", "value"),
     dash.dependencies.Input("filtro-logs-dominio", "value")]
)
def update_logs(n_intervals, selected_ips, selected_protocols, selected_domains):
    with data_lock:
        logs_copy = logs_data.copy()
    df = pd.DataFrame(logs_copy)
    if df.empty:
        df = pd.DataFrame(columns=["timestamp", "src_ip", "src_host", "dst_ip", "dst_host", "protocolo", "site"])
    if selected_ips:
        df = df[df["src_ip"].isin(selected_ips)]
    if selected_protocols:
        df = df[df["protocolo"].isin(selected_protocols)]
    if selected_domains:
        df = df[df["site"].isin(selected_domains)]
    ip_options = [{"label": ip, "value": ip} for ip in df["src_ip"].unique()]
    domain_options = [{"label": domain, "value": domain} for domain in df["site"].unique() if pd.notna(domain) and domain != ""]
    return df.to_dict("records"), ip_options, domain_options

# Callback para processar as configurações da aba "Configurações"
@app.callback(
    dash.dependencies.Output("config-output", "children"),
    [dash.dependencies.Input("btn-salvar", "n_clicks")],
    [dash.dependencies.State("input-config", "value")]
)
def salvar_configuracoes(n_clicks, valor_config):
    if n_clicks:
        return dbc.Alert(f"Configurações salvas! Valor: {valor_config}.", color="success")
    return ""

# Callback para atualizar a tabela de anomalias na aba "Anomalias"
@app.callback(
    dash.dependencies.Output("tabela-anomalias", "data"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_anomalias(n_intervals):
    with data_lock:
        ip_data = trafego_por_ip.copy()
    if not ip_data:
        df = pd.DataFrame(columns=["IP", "Requisições", "Anomalia"])
        return df.to_dict("records")
    # Cria um DataFrame com os dados de tráfego por IP
    df = pd.DataFrame(list(ip_data.items()), columns=["IP", "Requisições"])
    # Se houver poucos dados, não há como detectar anomalias
    if len(df) < 2:
        df["Anomalia"] = "Não"
        return df.to_dict("records")
    # Aplica o IsolationForest para detectar anomalias
    model = IsolationForest(contamination=0.1, random_state=42)
    df["Pred"] = model.fit_predict(df[["Requisições"]])
    df["Anomalia"] = df["Pred"].apply(lambda x: "Sim" if x == -1 else "Não")
    df.drop("Pred", axis=1, inplace=True)
    return df.to_dict("records")

# Função para iniciar o servidor Dash em uma thread separada
def run_dash():
    app.run_server(host="0.0.0.0", port=5000, debug=False)

dash_thread = threading.Thread(target=run_dash, daemon=True)
dash_thread.start()

# Inicia a captura de pacotes na interface especificada
if __name__ == "__main__":
    logging.info("Iniciando monitoramento de tráfego...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False, promisc=True)
    except Exception as e:
        logging.error(f"Erro na captura de pacotes: {e}")
