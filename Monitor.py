import logging
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP
import datetime
import socket
import threading
import requests
import random
import dash
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
from dash import dcc, html, dash_table
import plotly.graph_objs as go
import pandas as pd
from functools import lru_cache
from sklearn.ensemble import IsolationForest

# --- CONFIGURAÇÕES GLOBAIS ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
INTERFACE = "enp0s3"  # Ajuste conforme necessário

# Estruturas para armazenar os dados capturados
logs_data = []
packet_sizes_data = []  # Caso utilize para outro recurso
trafego_por_site = {}
trafego_por_ip = {}
trafego_por_protocolo = {"TCP": 0, "UDP": 0, "OUTROS": 0}
data_lock = threading.Lock()

# --- FUNÇÕES AUXILIARES ---
@lru_cache(maxsize=1024)
def resolver_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

@lru_cache(maxsize=1024)
def get_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Geolocation for {ip}: {data}")
            if data.get("status") == "success":
                return {"lat": data.get("lat"), "lon": data.get("lon"), "country": data.get("country")}
            else:
                logging.warning(f"Geolocation failed for {ip}: {data.get('message')}")
        else:
            logging.error(f"HTTP error {response.status_code} for {ip}")
    except Exception as e:
        logging.error(f"Error getting geolocation for {ip}: {e}")
    return None

def dummy_threat_intel(ip):
    return random.randint(0, 100)

# --- FUNÇÃO DE CAPTURA DE PACOTES ---
def packet_callback(packet):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)  # Tamanho do pacote em bytes
            with data_lock:
                src_host = resolver_host(src_ip)
                dst_host = resolver_host(dst_ip)
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
                    except Exception as e:
                        logging.error(f"Error decoding domain: {e}")
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
                packet_sizes_data.append({
                    "timestamp": timestamp,
                    "size": packet_size
                })
    except Exception as e:
        logging.error(f"Packet processing error: {e}")

# --- DASH APP ---
external_stylesheets = [dbc.themes.DARKLY]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "Network Monitoring Dashboard"

# Navbar
navbar = dbc.NavbarSimple(
    brand="Network Monitoring Dashboard",
    brand_href="/",
    color="primary",
    dark=True,
)

# Layout do aplicativo principal com a nova aba "Host Monitor"
main_layout = dbc.Container([
    navbar,
    dbc.Row(
        dbc.Col(html.H1("Network Monitoring Dashboard", className="text-center mb-4"), width=12)
    ),
    dbc.Tabs(
        id="tabs", active_tab="tab-dashboard",
        children=[
            dbc.Tab(label="Dashboard", tab_id="tab-dashboard"),
            dbc.Tab(label="Logs", tab_id="tab-logs"),
            dbc.Tab(label="Configurações", tab_id="tab-config"),
            dbc.Tab(label="Anomalias", tab_id="tab-anomalias"),
            dbc.Tab(label="Geolocalização", tab_id="tab-geolocalizacao"),
            dbc.Tab(label="Threat Intelligence", tab_id="tab-threat"),
            dbc.Tab(label="Time Series", tab_id="tab-timeseries"),
            dbc.Tab(label="Topologia", tab_id="tab-topologia"),
            dbc.Tab(label="Export", tab_id="tab-export"),
            dbc.Tab(label="Host Monitor", tab_id="tab-host-monitor")
        ]
    ),
    html.Div(id="tab-content", className="p-4"),
    dcc.Interval(id="intervalo-atualizacao", interval=5000, n_intervals=0)
], fluid=True)

app.layout = main_layout

# --- CALLBACK PARA RENDERIZAR CONTEÚDO POR ABA ---
@app.callback(
    dash.dependencies.Output("tab-content", "children"),
    [dash.dependencies.Input("tabs", "active_tab")]
)
def render_tab_content(active_tab):
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
                columns=[{"name": col, "id": col} for col in ["timestamp", "src_ip", "src_host", "dst_ip", "dst_host", "protocolo", "site"]],
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
                columns=[{"name": col, "id": col} for col in ["IP", "Requisições", "Anomalia"]],
                data=[],
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#343a40", "color": "white", "fontWeight": "bold"},
                style_data={"backgroundColor": "#212529", "color": "white"}
            )
        ])
    elif active_tab == "tab-geolocalizacao":
        return dbc.Container([
            html.H3("Geolocalização dos IPs Capturados"),
            dcc.Graph(id="mapa-geolocalizacao")
        ])
    elif active_tab == "tab-threat":
        return dbc.Container([
            html.H3("Threat Intelligence"),
            dash_table.DataTable(
                id="tabela-threat",
                columns=[{"name": col, "id": col} for col in ["IP", "Requisições", "Threat Score"]],
                data=[],
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#343a40", "color": "white", "fontWeight": "bold"},
                style_data={"backgroundColor": "#212529", "color": "white"}
            )
        ])
    elif active_tab == "tab-timeseries":
        return dbc.Container([
            html.H3("Time Series Analysis"),
            dcc.Graph(id="grafico-timeseries")
        ])
    elif active_tab == "tab-topologia":
        return dbc.Container([
            html.H3("Network Topology"),
            cyto.Cytoscape(
                id="cytoscape-topologia",
                layout={'name': 'cose'},
                style={'width': '100%', 'height': '500px'},
                elements=[]
            )
        ])
    elif active_tab == "tab-export":
        return dbc.Container([
            html.H3("Export Data"),
            dbc.Button("Download Logs CSV", id="btn-export", color="secondary"),
            dcc.Download(id="download-logs")
        ])
    elif active_tab == "tab-host-monitor":
        return dbc.Container([
            html.H3("Monitoramento de Host"),
            html.Label("Selecione um Host:"),
            dcc.Dropdown(id="host-monitor-dropdown", multi=False, placeholder="Selecione um host"),
            dash_table.DataTable(
                id="host-monitor-table",
                columns=[{"name": col, "id": col} for col in ["timestamp", "src_ip", "src_host", "dst_ip", "dst_host", "protocolo", "site"]],
                data=[],
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#343a40", "color": "white", "fontWeight": "bold"},
                style_data={"backgroundColor": "#212529", "color": "white"}
            )
        ])
    return html.Div("Selecione uma aba para visualizar o conteúdo.")

# --- CALLBACKS DOS GRÁFICOS E TABELAS ---
@app.callback(
    [dash.dependencies.Output("grafico-trafego", "figure"),
     dash.dependencies.Output("grafico-protocolo", "figure")],
    [dash.dependencies.Input("intervalo-atualizacao", "n_clicks"),
     dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_dashboard_graphs(n_clicks, n_intervals):
    with data_lock:
        trafego_site = trafego_por_site.copy()
        trafego_protocol = trafego_por_protocolo.copy()
    fig_trafego = go.Figure(data=[go.Bar(x=list(trafego_site.keys()), y=list(trafego_site.values()), marker_color='blue')])
    fig_trafego.update_layout(title="Tráfego de Rede por Domínio", xaxis_title="Domínios", yaxis_title="Número de Requisições")
    fig_protocol = go.Figure(data=[go.Pie(labels=list(trafego_protocol.keys()), values=list(trafego_protocol.values()))])
    fig_protocol.update_layout(title="Distribuição de Protocolos")
    return fig_trafego, fig_protocol

@app.callback(
    [dash.dependencies.Output("tabela-logs", "data"),
     dash.dependencies.Output("filtro-logs-ip", "options"),
     dash.dependencies.Output("filtro-logs-dominio", "options")],
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals"),
     dash.dependencies.Input("filtro-logs-ip", "value"),
     dash.dependencies.Input("filtro-logs-protocolo", "value"),
     dash.dependencies.Input("filtro-logs-dominio", "value")]
)
def update_logs_table(n_intervals, selected_ips, selected_protocols, selected_domains):
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

@app.callback(
    dash.dependencies.Output("config-output", "children"),
    [dash.dependencies.Input("btn-salvar", "n_clicks")],
    [dash.dependencies.State("input-config", "value")]
)
def save_config(n_clicks, value):
    if n_clicks:
        return dbc.Alert(f"Configurações salvas! Valor: {value}.", color="success")
    return ""

@app.callback(
    dash.dependencies.Output("tabela-anomalias", "data"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_anomalies(n_intervals):
    with data_lock:
        ip_data = trafego_por_ip.copy()
    if not ip_data:
        df = pd.DataFrame(columns=["IP", "Requisições", "Anomalia"])
        return df.to_dict("records")
    df = pd.DataFrame(list(ip_data.items()), columns=["IP", "Requisições"])
    if len(df) < 2:
        df["Anomalia"] = "Não"
        return df.to_dict("records")
    model = IsolationForest(contamination=0.1, random_state=42)
    df["Pred"] = model.fit_predict(df[["Requisições"]])
    df["Anomalia"] = df["Pred"].apply(lambda x: "Sim" if x == -1 else "Não")
    df.drop("Pred", axis=1, inplace=True)
    return df.to_dict("records")

@app.callback(
    dash.dependencies.Output("tabela-threat", "data"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_threat_intelligence(n_intervals):
    with data_lock:
        ip_data = trafego_por_ip.copy()
    data_list = []
    for ip, count in ip_data.items():
        threat_score = dummy_threat_intel(ip)
        data_list.append({"IP": ip, "Requisições": count, "Threat Score": threat_score})
    df = pd.DataFrame(data_list)
    return df.to_dict("records")

@app.callback(
    dash.dependencies.Output("grafico-timeseries", "figure"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_timeseries(n_intervals):
    with data_lock:
        logs_copy = logs_data.copy()
    if not logs_copy:
        return go.Figure()
    df = pd.DataFrame(logs_copy)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.set_index("timestamp")
    ts = df.resample("1Min").size()
    fig = go.Figure(data=[go.Scatter(x=ts.index, y=ts.values, mode='lines+markers')])
    fig.update_layout(title="Tráfego ao Longo do Tempo", xaxis_title="Tempo", yaxis_title="Número de Requisições")
    return fig

@app.callback(
    dash.dependencies.Output("cytoscape-topologia", "elements"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_topology(n_intervals):
    with data_lock:
        logs_copy = logs_data.copy()
    if not logs_copy:
        return []
    df = pd.DataFrame(logs_copy)
    nodes = set(df["src_ip"].unique()).union(set(df["dst_ip"].unique()))
    elements = [{"data": {"id": ip, "label": ip}} for ip in nodes]
    edges = []
    for _, row in df.iterrows():
        edges.append({"data": {"source": row["src_ip"], "target": row["dst_ip"]}})
    elements.extend(edges)
    return elements

@app.callback(
    dash.dependencies.Output("mapa-geolocalizacao", "figure"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_geolocalizacao(n_intervals):
    with data_lock:
        ips = list(trafego_por_ip.keys())
    latitudes, longitudes, texts = [], [], []
    for ip in ips:
        geo = get_geolocation(ip)
        if geo and geo["lat"] is not None and geo["lon"] is not None:
            latitudes.append(geo["lat"])
            longitudes.append(geo["lon"])
            texts.append(f"{ip} ({geo['country']}) - {trafego_por_ip.get(ip, 0)} req")
    if not latitudes or not longitudes:
        return go.Figure()
    fig = go.Figure(go.Scattermapbox(
        lat=latitudes,
        lon=longitudes,
        mode='markers',
        marker=go.scattermapbox.Marker(size=9, color='red'),
        text=texts
    ))
    fig.update_layout(mapbox_style="open-street-map", mapbox_zoom=1, margin={"r":0, "t":0, "l":0, "b":0})
    return fig

@app.callback(
    dash.dependencies.Output("download-logs", "data"),
    [dash.dependencies.Input("btn-export", "n_clicks")],
    prevent_initial_call=True
)
def export_logs(n_clicks):
    with data_lock:
        logs_copy = logs_data.copy()
    df = pd.DataFrame(logs_copy)
    return dcc.send_data_frame(df.to_csv, "logs.csv", index=False)

# --- NOVO CALLBACK: HOST MONITOR ---
@app.callback(
    [dash.dependencies.Output("host-monitor-dropdown", "options"),
     dash.dependencies.Output("host-monitor-table", "data")],
    [dash.dependencies.Input("host-monitor-dropdown", "value"),
     dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_host_monitor(selected_host, n_intervals):
    with data_lock:
        logs_copy = logs_data.copy()
    df = pd.DataFrame(logs_copy)
    # Atualiza as opções do dropdown com os IPs únicos
    host_options = [{"label": ip, "value": ip} for ip in df["src_ip"].unique()] if not df.empty else []
    if selected_host:
        df = df[df["src_ip"] == selected_host]
    return host_options, df.to_dict("records")

# --- NOVO RECURSO: PACKET SIZES (já integrado anteriormente) ---
@app.callback(
    dash.dependencies.Output("grafico-packet-sizes", "figure"),
    [dash.dependencies.Input("intervalo-atualizacao", "n_intervals")]
)
def update_packet_sizes(n_intervals):
    with data_lock:
        sizes_copy = packet_sizes_data.copy()
    if not sizes_copy:
        return go.Figure()
    df = pd.DataFrame(sizes_copy)
    fig = go.Figure(data=[go.Histogram(x=df['size'], nbinsx=20)])
    fig.update_layout(
        title="Distribuição de Tamanho dos Pacotes",
        xaxis_title="Tamanho (bytes)",
        yaxis_title="Frequência"
    )
    return fig

# --- INÍCIO DO SERVIDOR DASH EM UMA THREAD ---
def run_dash():
    app.run_server(host="0.0.0.0", port=5000, debug=False)

dash_thread = threading.Thread(target=run_dash, daemon=True)
dash_thread.start()

# --- INÍCIO DA CAPTURA DE PACOTES ---
if __name__ == "__main__":
    logging.info("Iniciando monitoramento de tráfego...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False, promisc=True)
    except Exception as e:
        logging.error(f"Erro na captura de pacotes: {e}")
