import requests
import json
import re

# Configura las credenciales y URL de la API
url_base = 'https://api.xdr.trendmicro.com'
url_path = '/v3.0/response/suspiciousObjects'
url_path_ioc_delete = '/v3.0/response/suspiciousObjects/delete'
url_path_isolate = '/v3.0/response/endpoints/isolate'
url_path_restore = '/v3.0/response/endpoints/restore'
url_path_malware_scan = '/v3.0/response/endpoints/startMalwareScan'
url_path_custom_script = '/v3.0/response/customScripts'
url_path_run_script = '/v3.0/response/endpoints/runScript'
url_path_disable_account = '/v3.0/response/domainAccounts/disable'
url_path_enable_account = '/v3.0/response/domainAccounts/enable'
url_path_logout_account = '/v3.0/response/domainAccounts/signOut'
url_path_reset_account_password = '/v3.0/response/domainAccounts/resetPassword'
url_path_delete_email = '/v3.0/response/emails/delete'
url_path_quarantine_email = '/v3.0/response/emails/quarantine'
url_path_restore_email = '/v3.0/response/emails/restore'
url_path_email_activities = '/v3.0/search/emailActivities'
url_path_workbenc_alerts = '/v3.0/workbench/alerts'
url_path_task = '/v3.0/response/tasks'
token = 'tu_token_aqui'  # Sustituye con tu token real

headers = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json;charset=utf-8'
}

def get_chiste():
    joke = requests.get('https://api.chucknorris.io/jokes/random')
    data = joke.json()
    return data["value"]

def get_ips(content):
    # Función simplificada para extraer IPs
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, content)

def get_hashes(content):
    # Función simplificada para extraer hashes SHA-256
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b'
    return re.findall(hash_pattern, content)

def upload_iocs(hashes):
    iocs = [{'fileSha256': h, 'description': 'HASH TelegramBot', 'scanAction': 'log', 'riskLevel': 'low', 'daysToExpiration': '30'} for h in hashes]
    response = requests.post(url_base + url_path, headers=headers, json=iocs)
    if response.status_code == 200:
        print("Data uploaded successfully.")
        return json.dumps(response.json(), indent=4)
    else:
        print(f"Failed to upload data. Status code: {response.status_code}")
        return response.text

def get_endpoints(content):
    # Función simplificada para extraer nombres de endpoints (simulando la funcionalidad)
    # Ajusta esta función según tus necesidades
    return content.splitlines()

def isolate_endpoints(endpoints):
    isolate = [{'endpointName': e, 'description': 'Aislado TelegramBot'} for e in endpoints]
    response = requests.post(url_base + url_path_isolate, headers=headers, json=isolate)
    if response.status_code == 200:
        print("Equipo aislado correctamente")
        return json.dumps(response.json(), indent=4)
    else:
        print(f"Equipo no aislado. Status code: {response.status_code}")
        return response.text

def restore_endpoints(lista_equipos):
    body = []
    for equipo in lista_equipos:
        body.append({
            'description': f'Restore {equipo}',
            'endpointName': equipo
        })
    # Realizar la solicitud HTTP POST
    r = requests.post(url_base + url_path_restore, headers=headers, json=body)
    # Manejar la respuesta
    if r.status_code == 200:
        if 'application/json' in r.headers.get('Content-Type', ''):
            return r.json()
        else:
            return r.text
    else:
        return f'Error: {r.status_code} - {r.text}'
    
def start_malware_scan(lista_equipos):
 # Construir el cuerpo de la solicitud
    body = {
        'endpoints': []
    }
    for equipo in lista_equipos:
        body['endpoints'].append({
            'description': f'Malware scan for {equipo}',
            'endpointName': equipo
        })
    # Realizar la solicitud HTTP POST
    r = requests.post(url_base + url_path_malware_scan, headers=headers, json=body)
    # Manejar la respuesta
    if r.status_code == 200:
        if 'application/json' in r.headers.get('Content-Type', ''):
            return r.json()
        else:
            return r.text
    else:
        return f'Error: {r.status_code} - {r.text}'
    


def procesar_sha256(hashes: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'SHA256 hash {i+1}',
            'fileSha256': hash_value
        }
        for i, hash_value in enumerate(hashes)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "Hashes cargados correctamente."
        else:
            return f"Error al cargar hashes. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def procesar_sha1(hashes: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'SHA1 hash {i+1}',
            'fileSha1': hash_value
        }
        for i, hash_value in enumerate(hashes)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "Hashes SHA1 cargados correctamente."
        else:
            return f"Error al cargar hashes SHA1. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"
    
def procesar_ip(ips: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'IP {i+1}',
            'ip': ip_value
        }
        for i, ip_value in enumerate(ips)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "IPs cargadas correctamente."
        else:
            return f"Error al cargar IPs. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"
    
def procesar_url(urls: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'URL {i+1}',
            'url': url_value
        }
        for i, url_value in enumerate(urls)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "URLs cargadas correctamente."
        else:
            return f"Error al cargar URLs. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"
    
def procesar_domain(domains: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'Dominio {i+1}',
            'domain': domain_value
        }
        for i, domain_value in enumerate(domains)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "Dominios cargados correctamente."
        else:
            return f"Error al cargar dominios. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"
    
def procesar_sender(senders: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'Remitente {i+1}',
            'senderMailAddress': sender_value
        }
        for i, sender_value in enumerate(senders)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        if r.status_code == 200:
            return "Remitentes cargados correctamente."
        else:
            return f"Error al cargar remitentes. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"


def eliminar_suspicious_objects_sha256(lista_sha256):
    # Validar que la lista no esté vacía
    if not lista_sha256:
        return "No se proporcionaron hashes SHA256 para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for sha256 in lista_sha256:
        # Añadir hashes SHA256 sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {sha256}',
            'fileSha256': sha256  # Específico para hashes SHA256 sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_sha1(lista_sha1):
    # Validar que la lista no esté vacía
    if not lista_sha1:
        return "No se proporcionaron hashes SHA1 para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for sha1 in lista_sha1:
        # Añadir hashes SHA1 sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {sha1}',
            'fileSha1': sha1  # Específico para hashes SHA1 sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_ip(lista_ips):
    # Validar que la lista no esté vacía
    if not lista_ips:
        return "No se proporcionaron IPs para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for ip in lista_ips:
        # Añadir IPs sospechosas al cuerpo
        body.append({
            'description': f'Eliminando {ip}',
            'ip': ip  # Específico para IPs sospechosas
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_url(lista_urls):
    # Validar que la lista no esté vacía
    if not lista_urls:
        return "No se proporcionaron URLs para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for url in lista_urls:
        # Añadir objetos sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {url}',
            'url': url  # Específico para URLs sospechosas
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_domain(lista_dominios):
    # Validar que la lista no esté vacía
    if not lista_dominios:
        return "No se proporcionaron dominios para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for dominio in lista_dominios:
        # Añadir dominios sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {dominio}',
            'domain': dominio  # Específico para dominios sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_sender(lista_objetos):
    # Validar que la lista no esté vacía
    if not lista_objetos:
        return "No se proporcionaron objetos para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for objeto in lista_objetos:
        # Añadir objetos sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {objeto}',
            'senderMailAddress': objeto  # Específico para remitentes sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

# Listar Script personalizadas:

def listar_scripts_personalizados():
    # Configurar encabezados (asumiendo que ya tienes el token en headers como variable global)
    try:
        # Realizar la solicitud HTTP GET
        r = requests.get(url_base + url_path_custom_script, headers=headers)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'
    
def ejecutar_script_customizado(nombre_script, lista_endpoints, parametros=None):
    # Construir el cuerpo de la solicitud
    body = []
    for endpoint in lista_endpoints:
        # Construir el diccionario de cada endpoint
        script_info = {
            'description': f'Ejecutando script {nombre_script} en {endpoint}',
            'endpointName': endpoint,
            'fileName': nombre_script  # Nombre del script a ejecutar
        }
        
        # Agregar los parámetros si están presentes
        if parametros:
            script_info['parameter'] = ' '.join(parametros)
        
        body.append(script_info)

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_run_script, headers=headers, json=body)
        
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'
    
#Funcion para deshabilitar cuentas

def deshabilitar_cuentas(lista_cuentas):
    # Validar que la lista no esté vacía
    if not lista_cuentas:
        return "No se proporcionaron cuentas para deshabilitar."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Deshabilitando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_disable_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'
    
#Funcion para habilitar cuentas deshabilitadas

def habilitar_cuentas(lista_cuentas):
    # Validar que la lista no esté vacía
    if not lista_cuentas:
        return "No se proporcionaron cuentas para habilitar."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Habilitando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_enable_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'
    
#Funcion para forzar deslogueo de cuentas

def desloguear_cuentas(lista_cuentas):
    # Validar que la lista no esté vacía
    if not lista_cuentas:
        return "No se proporcionaron cuentas para desloguear."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Deslogueando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_logout_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'
    
#Funcion para resetear el password de la cuenta

def resetear_password(lista_cuentas):
    # Validar que la lista no esté vacía
    if not lista_cuentas:
        return "No se proporcionaron cuentas para restablecer las contraseñas."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Reseteando contraseña de la cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_reset_account_password, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funciones referentes a correo


def eliminar_mensajes_por_uuid(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Eliminando mensaje {i+1}',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_delete_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes eliminados correctamente."
        else:
            return f"Error al eliminar mensajes. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def mandar_mensajes_a_cuarentena(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Enviando mensaje {i+1} a cuarentena',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_quarantine_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes enviados a cuarentena correctamente."
        else:
            return f"Error al enviar mensajes a cuarentena. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def restaurar_mensajes(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Restaurando mensaje {i+1}',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]
    
    # Envía la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_restore_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes restaurados correctamente."
        else:
            return f"Error al restaurar mensajes. Código de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"
        
def buscar_correos_por_asunto(asunto: str) -> dict:
    headersCorreo = {
        'Authorization': 'Bearer ' + token, # Asegúrate de reemplazar 'YOUR_TOKEN' por el token correcto
        'Content-Type': 'application/json;charset=utf-8',
        'TMV1-Query': f'mailMsgSubject:{asunto}'  # Asunto ya viene con comillas
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_email_activities, headers=headersCorreo)
        
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

# Funciones Referentes a Workbench

def obtener_alertas_workbench() -> dict:
    query_params = {
        'orderBy': 'createdDateTime desc'  # Ordena por createdDateTime en orden descendente
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_workbenc_alerts, params=query_params, headers=headers)    
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def obtener_detalle_alerta_workbench(alerta_id: str) -> dict:
    url_path_workbench_id = f'/v3.0/workbench/alerts/{alerta_id}'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_workbench_id, headers=headers)
        
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}


def cambiar_estado_alerta_workbench(alerta_id: str, nuevo_estado: str, findings: str = None) -> dict:
    url_path_workbench_id_status = f'/v3.0/workbench/alerts/{alerta_id}'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8',
        'If-Match': '*'
    }
    # Cuerpo de la solicitud que contiene el nuevo estado y opcionalmente los findings
    body = {
        'status': nuevo_estado
    }
    if findings:
        body['investigationResult'] = findings
    try:
        # Realiza la solicitud PATCH a la API
        r = requests.patch(url_base + url_path_workbench_id_status, headers=headers, json=body)
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def obtener_notas_workbench(alerta_id: str) -> dict:
    url_path_workbench_get_notes = f'/v3.0/workbench/alerts/{alerta_id}/notes'
    query_params = {
        'orderBy': 'lastUpdatedDateTime desc,creatorName asc,id asc',  # Ordena por lastUpdatedDateTime, luego por creatorName, luego por id
        'top': 100  # Obtiene las primeras 100 notas
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_workbench_get_notes, params=query_params, headers=headers)     
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def borrar_nota_workbench_api(alerta_id: str, nota_id: str) -> dict:
    url_path_workbench_note_delete = f'/v3.0/workbench/alerts/{alerta_id}/notes/delete'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    body = [
        {
            'id': int(nota_id)  # Asegúrate de convertir el ID de la nota a entero
        }
    ]
    try:
        # Realiza la solicitud POST a la API para borrar la nota
        r = requests.post(url_base + url_path_workbench_note_delete, headers=headers, json=body)   
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def agregar_nota_workbench_api(alerta_id: str, contenido: str) -> dict:
    url_path_workbench_note_add = f'/v3.0/workbench/alerts/{alerta_id}/notes'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    body = {
        'content': contenido  # El contenido de la nota
    }
    try:
        # Realiza la solicitud POST a la API para agregar la nota
        r = requests.post(url_base + url_path_workbench_note_add, headers=headers, json=body)
        
        # Verifica si la solicitud fue exitosa
        if r.status_code == 201:  # Código 201 para creación exitosa
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def obtener_tareas_top_50() -> dict:
    query_params = {
        'top': 50  # Limita los resultados a las primeras 50 tareas
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_task, params=query_params, headers=headers)
        
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def buscar_guid_endpoint(endpoint_name: str) -> dict:
    url_path_endpoint_get = '/v3.0/endpointSecurity/endpoints'
    query_params = {
        'orderBy': 'endpointName',
        'top': 1,  # Solo necesitamos el primer resultado coincidente
        'select': 'endpointName,agentGuid'
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8',
        'TMV1-Filter': f'endpointName eq "{endpoint_name}"'
    }
    try:
        # Realiza la solicitud GET a la API para obtener el GUID del endpoint
        r = requests.get(url_base + url_path_endpoint_get, params=query_params, headers=headers)  
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            results = r.json().get('items', [])
            if results:
                return {'agentGuid': results[0]['agentGuid']}
            else:
                return {'error': f"No se encontró ningún endpoint con el nombre '{endpoint_name}'"}
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

import requests

def obtener_detalles_endpoint(agent_guid: str) -> dict:
    url_path_endpoint_details = f'/v3.0/endpointSecurity/endpoints/{agent_guid}'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json;charset=utf-8'
    }
    try:
        # Realiza la solicitud GET a la API para obtener los detalles del endpoint
        r = requests.get(url_base + url_path, headers=headers)
        
        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"Código de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}
