from telegram.ext import Updater, CommandHandler, ConversationHandler, MessageHandler, Filters, CallbackContext
from telegram import Update
from engine import *
import logging, os

# Variables para los estados en la conversación
TEXTO_ENDPOINTS = 0
INPUT_TEXT = 0

# Funciones
def start(update, context):
    logger.info('He recibido un comando start')
    update.message.reply_text(f'¡Bienvenido al Actualizador de Compromisos {update.message.from_user.name}!')

def chiste(update, context):
    logger.info('Consultando API Chiste')
    update.message.reply_text(get_chiste())


# Funcion para cargar SHA256 separado por coma

def cargar_sha256(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /sha256
    hashes = update.message.text[len('/sha256 '):]
    
    # Divide los hashes por coma y limpia espacios
    lista_hashes = [hash.strip() for hash in hashes.split(',')]
    
    # Llama a la función que maneja la carga de los hashes
    response = procesar_sha256(lista_hashes)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de hashes: {response}')

# Función que se ejecuta al recibir el comando /sha1
def cargar_sha1(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /sha1
    hashes = update.message.text[len('/sha1 '):]
    
    # Divide los hashes por coma y limpia espacios
    lista_hashes = [hash.strip() for hash in hashes.split(',')]
    
    # Llama a la función que maneja la carga de los hashes
    response = procesar_sha1(lista_hashes)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de hashes: {response}')

# Función que se ejecuta al recibir el comando /ip
def cargar_ip(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /ip
    ips = update.message.text[len('/ip '):]
    
    # Divide las IPs por coma y limpia espacios
    lista_ips = [ip.strip() for ip in ips.split(',')]
    
    # Llama a la función que maneja la carga de las IPs
    response = procesar_ip(lista_ips)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de IPs: {response}')

# Función que se ejecuta al recibir el comando /url
def cargar_url(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /url
    urls = update.message.text[len('/url '):]
    
    # Divide las URLs por coma y limpia espacios
    lista_urls = [url.strip() for url in urls.split(',')]
    
    # Llama a la función que maneja la carga de las URLs
    response = procesar_url(lista_urls)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de URLs: {response}')

# Función que se ejecuta al recibir el comando /domain
def cargar_domain(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /domain
    domains = update.message.text[len('/domain '):]
    
    # Divide los dominios por coma y limpia espacios
    lista_domains = [domain.strip() for domain in domains.split(',')]
    
    # Llama a la función que maneja la carga de los dominios
    response = procesar_domain(lista_domains)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de dominios: {response}')

# Función que se ejecuta al recibir el comando /sender
def cargar_sender(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /sender
    senders = update.message.text[len('/sender '):]
    
    # Divide las direcciones de correo por coma y limpia espacios
    lista_senders = [sender.strip() for sender in senders.split(',')]
    
    # Llama a la función que maneja la carga de los senders
    response = procesar_sender(lista_senders)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la carga de remitentes: {response}')

# Funciones para eliminar indicadores de compromiso cargados

def eliminar_objeto_sospechoso_sha256(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminarsha256
    objetos = update.message.text[len('/eliminarsha256 '):]
    
    # Divide los hashes SHA256 sospechosos por coma y limpia espacios
    lista_sha256 = [sha256.strip() for sha256 in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de los hashes SHA256 sospechosos
    response = eliminar_suspicious_objects_sha256(lista_sha256)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de hashes SHA256 sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_sha1(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminarsha1
    objetos = update.message.text[len('/eliminarsha1 '):]
    
    # Divide los hashes SHA1 sospechosos por coma y limpia espacios
    lista_sha1 = [sha1.strip() for sha1 in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de los hashes SHA1 sospechosos
    response = eliminar_suspicious_objects_sha1(lista_sha1)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de hashes SHA1 sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_ip(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminarip
    objetos = update.message.text[len('/eliminarip '):]
    
    # Divide las IPs sospechosas por coma y limpia espacios
    lista_ips = [ip.strip() for ip in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de las IPs sospechosas
    response = eliminar_suspicious_objects_ip(lista_ips)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de IPs sospechosas: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_url(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminarurl
    objetos = update.message.text[len('/eliminarurl '):]
    
    # Divide las URLs sospechosas por coma y limpia espacios
    lista_urls = [url.strip() for url in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de las URLs sospechosas
    response = eliminar_suspicious_objects_url(lista_urls)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de URLs sospechosas: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_domain(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminardomain
    objetos = update.message.text[len('/eliminardomain '):]
    
    # Divide los dominios sospechosos por coma y limpia espacios
    lista_dominios = [dominio.strip() for dominio in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de los dominios sospechosos
    response = eliminar_suspicious_objects_domain(lista_dominios)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de dominios sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_sender(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /eliminar
    objetos = update.message.text[len('/eliminarsender '):]
    
    # Divide los objetos sospechosos por coma y limpia espacios
    lista_objetos = [objeto.strip() for objeto in objetos.split(',')]
    
    # Llama a la función que maneja la eliminación de los objetos sospechosos
    response = eliminar_suspicious_objects_sender(lista_objetos)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la eliminación de senders sospechosos: {json.dumps(response, indent=4)}')

# Funcion para Aislar Equipos separado por coma

def aislar(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /aislar
    equipos = update.message.text[len('/aislar '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la función para aislar los equipos
    resultado = isolate_endpoints(lista_equipos)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del aislamiento: {resultado}')

def restaurar(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /aislar
    equipos = update.message.text[len('/restaurar '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la función para aislar los equipos
    resultado = restore_endpoints(lista_equipos)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del restore: {resultado}')

def escanear_malware(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /escanear
    equipos = update.message.text[len('/escanear '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la función para iniciar el escaneo de malware
    resultado = start_malware_scan(lista_equipos)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del escaneo: {json.dumps(resultado, indent=4)}')

# Funcion para listar script personalizados cargados en Vision One

def listar_script(update: Update, context: CallbackContext) -> None:
    # Llama a la función que maneja la lista de scripts personalizados
    response = listar_scripts_personalizados()
    
    # Si la respuesta es JSON, formatear adecuadamente
    if isinstance(response, dict):
        response_text = json.dumps(response, indent=4)
    else:
        response_text = response

    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la lista de scripts personalizados: {response_text}')

# Funcion para ejecutar una script personalizada sobre una lista de equipos
def ejecutar_script(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /script
    mensaje = update.message.text[len('/script '):].strip()

    try:
        # Verifica si el mensaje contiene "/target" y opcionalmente "/parametro"
        if '/target' not in mensaje:
            update.message.reply_text("Formato incorrecto. Usa: /script nombre_script /parametro parametro1,parametro2 /target equipo1,equipo2, equipo3")
            return
        
        # Extraer la parte del script y los targets (endpoints)
        script_part, targets_part = mensaje.split('/target')

        # Limpiar y extraer el nombre del script
        nombre_script = script_part.split('/parametro')[0].strip() if '/parametro' in script_part else script_part.strip()

        # Verificar si hay parámetros opcionales
        parametros = []
        if '/parametro' in script_part:
            parametros = script_part.split('/parametro')[1].strip().split()

        # Separar los targets por comas y limpiar espacios
        lista_endpoints = [target.strip() for target in targets_part.split(',') if target.strip()]

        # Verifica que tanto el nombre del script como la lista de endpoints no estén vacíos
        if not nombre_script or not lista_endpoints:
            update.message.reply_text("Formato incorrecto. Usa: /script nombre_script /parametro parametro1,parametro2 /target equipo1,equipo2, equipo3")
            return

        # Llama a la función que ejecuta la script personalizada en los endpoints
        response = ejecutar_script_customizado(nombre_script, lista_endpoints, parametros)

        # Envía el resultado al chat
        update.message.reply_text(f'Resultado de la ejecución del script {nombre_script}: {json.dumps(response, indent=4)}')

    except Exception as e:
        # Captura cualquier otra excepción inesperada
        update.message.reply_text(f"Se produjo un error: {str(e)}")

#ejemplo: /script nombre_script /target endpoint1, endpoint2, endpoint3

#Funciones relacionadas a cuentas de usuarios

    #Función para deshabilitar cuentas

def deshabilitar_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /disable
    cuentas = update.message.text[len('/disable '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la función que maneja la deshabilitación de cuentas
    response = deshabilitar_cuentas(lista_cuentas)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la deshabilitación de cuentas: {json.dumps(response, indent=4)}')

    #Funcion para habilitar cuentas
def habilitar_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /enable
    cuentas = update.message.text[len('/enable '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la función que maneja la habilitación de cuentas
    response = habilitar_cuentas(lista_cuentas)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la habilitación de cuentas: {json.dumps(response, indent=4)}')

    #Funcion para desloguear cuentas
def desloguear_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /logout
    cuentas = update.message.text[len('/logout '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la función que maneja el deslogueo de cuentas
    response = desloguear_cuentas(lista_cuentas)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del deslogueo de cuentas: {json.dumps(response, indent=4)}')

    #Función para resetear el password de una cuenta

def resetear_password_comando(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /resetpassword
    cuentas = update.message.text[len('/resetpassword '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la función que maneja el reseteo de contraseñas
    response = resetear_password(lista_cuentas)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del reseteo de contraseñas: {json.dumps(response, indent=4)}')

#Funciones relacionadas a emails

def borrar_mensaje(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /borrarmail
    uuids = update.message.text[len('/borrarmail '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la función que maneja el borrado de los mensajes
    response = eliminar_mensajes_por_uuid(lista_uuids)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del borrado de mensajes: {response}')

def enviar_a_cuarentena(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /cuarentena
    uuids = update.message.text[len('/cuarentena '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la función que maneja el envío a cuarentena
    response = mandar_mensajes_a_cuarentena(lista_uuids)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado del envío a cuarentena: {response}')

def restaurar_email(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /restauraremail
    uuids = update.message.text[len('/restauraremail '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la función que maneja la restauración de los mensajes
    response = restaurar_mensajes(lista_uuids)
    
    # Envía el resultado al chat
    update.message.reply_text(f'Resultado de la restauración de mensajes: {response}')

def buscar_mail(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /buscarmail
    asunto = update.message.text[len('/buscarmail '):].strip()

    # Pasa el asunto a la función con comillas dobles estándar
    asunto = asunto.replace('“', '"').replace('”', '"')
    response = buscar_correos_por_asunto(f'"{asunto}"')
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # Obtén el número de mensajes y los UUIDs
    num_mensajes = len(response.get('items', []))
    uuids = [item['uniqueId'] for item in response.get('items', [])]
    
    # Prepara el mensaje de respuesta
    uuids_text = ','.join(uuids)
    update.message.reply_text(f"Se detectaron {num_mensajes} mensajes con el asunto '{asunto}'. UUIDs: {uuids_text}")

# Funciones referentes a Workbench

def listar_workbench(update: Update, context: CallbackContext) -> None:
    # Llama a la función que realiza la solicitud para obtener las alertas
    response = obtener_alertas_workbench()
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # Obtén la lista de alertas
    alertas = response.get('items', [])
    
    if not alertas:
        update.message.reply_text("No se encontraron alertas en el Workbench.")
        return
    
    # Prepara la lista de alertas para el mensaje
    lista_alertas = [f"ID: {alerta['id']}, Nombre: {alerta['name']}, Fecha: {alerta['createdDateTime']}" for alerta in alertas]
    alertas_text = "\n".join(lista_alertas)
    
    # Envía la lista de alertas al chat
    update.message.reply_text(f"Alertas en Workbench:\n{alertas_text}")

def detalle_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /detalleworkbench
    ids = update.message.text[len('/detalleworkbench '):].strip()
    
    # Divide los IDs por coma y limpia espacios
    lista_ids = [id.strip() for id in ids.split(',')]
    
    # Para cada ID, obtener los detalles de la alerta
    detalles_alertas = []
    for id in lista_ids:
        response = obtener_detalle_alerta_workbench(id)
        
        if response.get('error'):
            detalles_alertas.append(f"Error con la alerta {id}: {response['error']}")
        else:
            # Extraer detalles relevantes de la alerta
            detalles = f"ID: {response.get('id')}\nNombre: {response.get('name')}\nDescripción: {response.get('description')}\nFecha de creación: {response.get('createdDateTime')}\nScore: {response.get('score')}\n"
            detalles_alertas.append(detalles)
    
    # Unir todos los detalles y enviarlos como un solo mensaje
    detalles_text = "\n".join(detalles_alertas)
    update.message.reply_text(f"Detalles de las alertas en Workbench:\n\n{detalles_text}")

#Funcion para cambiar estado de workbench:

def cambiar_estado_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /workbenchstatus
    mensaje = update.message.text[len('/workbenchstatus '):].strip()
    
    # Separa los IDs, el estado, y opcionalmente los findings
    try:
        partes = mensaje.split(' /')
        ids_part = partes[0]
        status_part = partes[1]
        findings_part = partes[2] if len(partes) > 2 else None
    except ValueError:
        update.message.reply_text("Formato incorrecto. Usa: /workbenchstatus workbench1,workbench2 /Estado [/findings Resultado]")
        return
    
    # Divide los IDs por coma y limpia espacios
    lista_ids = [id.strip() for id in ids_part.split(',')]
    
    # Llama a la función que maneja el cambio de estado para cada ID
    resultados = []
    for alerta_id in lista_ids:
        response = cambiar_estado_alerta_workbench(alerta_id, status_part, findings_part)
        
        if response.get('error'):
            resultados.append(f"Error con la alerta {alerta_id}: {response['error']}")
        else:
            result = f"Alerta {alerta_id}: Estado cambiado a {status_part}"
            if findings_part:
                result += f" con findings: {findings_part}"
            resultados.append(result)
    
    # Unir todos los resultados y enviarlos como un solo mensaje
    resultado_text = "\n".join(resultados)
    update.message.reply_text(f"Resultados del cambio de estado:\n{resultado_text}")

    #Funciones notas workbench

    def listar_notas_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /listarworkbenchnotes
    alerta_id = update.message.text[len('/listarworkbenchnotes '):].strip()
    
    # Llama a la función que obtiene las notas de la alerta
    response = obtener_notas_workbench(alerta_id)
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # Obtén las notas
    notas = response.get('items', [])
    
    if not notas:
        update.message.reply_text(f"No se encontraron notas para la alerta {alerta_id}.")
        return
    
    # Prepara la lista de notas para el mensaje
    lista_notas = [f"ID: {nota['id']}\nCreador: {nota['creatorName']}\nÚltima actualización: {nota['lastUpdatedDateTime']}\nContenido: {nota['noteContent']}" for nota in notas]
    notas_text = "\n\n".join(lista_notas)
    
    # Envía la lista de notas al chat
    update.message.reply_text(f"Notas de la alerta {alerta_id}:\n\n{notas_text}")


def listar_notas_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /listarworkbenchnotes
    alerta_id = update.message.text[len('/listarworkbenchnotes '):].strip()
    
    # Llama a la función que obtiene las notas de la alerta
    response = obtener_notas_workbench(alerta_id)
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # Obtén las notas
    notas = response.get('items', [])
    
    if not notas:
        update.message.reply_text(f"No se encontraron notas para la alerta {alerta_id}.")
        return
    
    # Prepara la lista de notas para el mensaje
    lista_notas = [f"ID: {nota['id']}\nCreador: {nota['creatorName']}\nÚltima actualización: {nota['lastUpdatedDateTime']}\nContenido: {nota['noteContent']}" for nota in notas]
    notas_text = "\n\n".join(lista_notas)
    
    # Envía la lista de notas al chat
    update.message.reply_text(f"Notas de la alerta {alerta_id}:\n\n{notas_text}")

def borrar_nota_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /borrarnotaworkbench
    mensaje = update.message.text[len('/borrarnotaworkbench '):].strip()
    
    # Separa el ID de la alerta del ID de la nota
    try:
        alerta_id, nota_id = mensaje.split(' /nota ')
    except ValueError:
        update.message.reply_text("Formato incorrecto. Usa: /borrarnotaworkbench workbench /nota iddenota")
        return
    
    # Llama a la función que borra la nota
    response = borrar_nota_workbench_api(alerta_id.strip(), nota_id.strip())
    
    if response.get('error'):
        update.message.reply_text(f"Error al borrar la nota: {response['error']}")
    else:
        update.message.reply_text(f"Nota con ID {nota_id} de la alerta {alerta_id} borrada correctamente.")

def agregar_nota_workbench(update: Update, context: CallbackContext) -> None:
    # Obtén el texto después del comando /agregarnotaworkbench
    mensaje = update.message.text[len('/agregarnotaworkbench '):].strip()
    
    # Separa el ID de la alerta del contenido de la nota
    try:
        alerta_id, contenido_nota = mensaje.split(' /contenido ', 1)
    except ValueError:
        update.message.reply_text("Formato incorrecto. Usa: /agregarnotaworkbench workbench /contenido \"texto\"")
        return
    
    # Llama a la función que agrega la nota
    response = agregar_nota_workbench_api(alerta_id.strip(), contenido_nota.strip())
    
    if response.get('error'):
        update.message.reply_text(f"Error al agregar la nota: {response['error']}")
    else:
        update.message.reply_text(f"Nota agregada a la alerta {alerta_id} correctamente.")

def listar_tareas(update: Update, context: CallbackContext) -> None:
    # Llama a la función que obtiene las tareas
    response = obtener_tareas_top_50()
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # Obtén la lista de tareas
    tareas = response.get('items', [])
    
    if not tareas:
        update.message.reply_text("No se encontraron tareas.")
        return
    
    # Prepara la lista de tareas para el mensaje
    lista_tareas = [f"ID: {tarea['id']}\nNombre: {tarea.get('name', 'Sin nombre')}\nEstado: {tarea.get('status', 'Desconocido')}" for tarea in tareas]
    tareas_text = "\n\n".join(lista_tareas)
    
    # Envía la lista de tareas al chat
    update.message.reply_text(f"Tareas (Top 50):\n\n{tareas_text}")

def detalle_endpoint(update: Update, context: CallbackContext) -> None:
    # Obtén el nombre del endpoint después del comando /detalleendpoints
    endpoint_name = update.message.text[len('/detalleendpoints '):].strip()
    
    if not endpoint_name:
        update.message.reply_text("Por favor, proporciona el nombre del endpoint. Ejemplo: /detalleendpoints nombre_endpoint")
        return
    
    # Buscar el agentGuid del endpoint
    guid = buscar_guid_endpoint(endpoint_name)
    
    if guid.get('error'):
        update.message.reply_text(f"Error al buscar el GUID del endpoint: {guid['error']}")
        return
    
    # Obtener los detalles del endpoint usando el GUID
    response = obtener_detalles_endpoint(guid['agentGuid'])
    
    if response.get('error'):
        update.message.reply_text(f"Error al obtener los detalles del endpoint: {response['error']}")
    else:
        # Extraer detalles relevantes del endpoint y enviar al usuario
        detalles = f"Nombre: {response.get('endpointName')}\nGUID: {response.get('agentGuid')}\nOS: {response.get('os')}\nÚltimo estado: {response.get('lastStatus')}\n"
        update.message.reply_text(f"Detalles del endpoint:\n{detalles}")


# Funcion para iniciar el comando /endpoints y pedir nombres de equipos
def endpoint(update: Update, context: CallbackContext) -> int:
    logger.info('Dialogo ENDPOINT')
    update.message.reply_text('Es necesario que me pases el nombre del equipo que deseas aislar.')
    return TEXTO_ENDPOINTS

# Funcion que recibe el nombre del equipo y lo aisla
def isolate_endpoints_handler(update: Update, context: CallbackContext) -> int:
    logger.info('Se recibio el nombre del equipo para aislar')
    team_name = update.message.text
    lista_de_endpoints = [team_name]  # Asumiendo que el mensaje contiene el nombre del equipo directamente

    if lista_de_endpoints:
        response = isolate_endpoints(lista_de_endpoints)
        update.message.reply_text(f'Se solicito el aislamiento del equipo. Respuesta de la API: {response}')
    else:
        update.message.reply_text('No se especifico ningun equipo para aislar.')

    # Finaliza la conversacion y resetea el estado
    return ConversationHandler.END

# Funcion para cargar indicadores de compromiso mediante conversacion, soporta SHA256 e IP
    # Comienza la conversacion con /ioc y nos pide que escribamos los indicadores
def ioc(update, context):
    logger.info('Dialogo IOC')
    update.message.reply_text('Es necesario que me pases el mensaje para parsearlo.')
    return INPUT_TEXT

    # Parsea el texto y determina cual es SHA256 y cual es IP
def update_ioc(update, context):
    logger.info('Se recibió el texto a parsear')
    text = update.message.text
    direcciones_ip = get_ips(text)
    hashes = get_hashes(text)
    if direcciones_ip:
        logger.info(f'Las Direcciones IP: {direcciones_ip}')
        update.message.reply_text(f'Se recibió el IoC, procederemos a aplicar los siguientes cambios. Direcciones IPs: {direcciones_ip}')
    if hashes:
        logger.info(f'Los Hash: {hashes}')
        update.message.reply_text(f'Se recibió el IoC, procederemos a aplicar los siguientes cambios. Hashes: {hashes}')
    return ConversationHandler.END

# Funcion que cancela la conversacion
def cancel(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('Comando cancelado.', reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

# Main del Programa
if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger('AutomaticBot')

    # Llave API para conectarse a Telegram
    updater = Updater(token=os.getenv("TOKEN_TELEGRAM"), use_context=True)
    dp = updater.dispatcher

    # Handlers de los comandos
    dp.add_handler(CommandHandler('start', start))
    dp.add_handler(CommandHandler('chiste', chiste))
    dp.add_handler(CommandHandler("aislar", aislar))
    dp.add_handler(CommandHandler('restaurar', restaurar))
    dp.add_handler(CommandHandler('escanear', escanear_malware))
    dp.add_handler(CommandHandler('listarscript', listar_script))
    dp.add_handler(CommandHandler('script', ejecutar_script))
    dp.add_handler(CommandHandler('disable', deshabilitar_cuentas_comando))
    dp.add_handler(CommandHandler('enable', habilitar_cuentas_comando))
    dp.add_handler(CommandHandler('logout', desloguear_cuentas_comando))
    dp.add_handler(CommandHandler('resetpassword', resetear_password_comando))
    dp.add_handler(CommandHandler("sha256", cargar_sha256))
    dp.add_handler(CommandHandler("sha1", cargar_sha1))
    dp.add_handler(CommandHandler("ip", cargar_ip))
    dp.add_handler(CommandHandler("url", cargar_url))
    dp.add_handler(CommandHandler("domain", cargar_domain))
    dp.add_handler(CommandHandler("sender", cargar_sender))
    dp.add_handler(CommandHandler('eliminarsha256', eliminar_objeto_sospechoso_sha256))
    dp.add_handler(CommandHandler('eliminarsha1', eliminar_objeto_sospechoso_sha1))
    dp.add_handler(CommandHandler('eliminarip', eliminar_objeto_sospechoso_ip))
    dp.add_handler(CommandHandler('eliminarurl', eliminar_objeto_sospechoso_url))
    dp.add_handler(CommandHandler('eliminardomain', eliminar_objeto_sospechoso_domain))
    dp.add_handler(CommandHandler('eliminarsender', eliminar_objeto_sospechoso_sender))
    dp.add_handler(CommandHandler('borrarmail', borrar_mensaje))
    dp.add_handler(CommandHandler('cuarentena', enviar_a_cuarentena))
    dp.add_handler(CommandHandler('restauraremail', restaurar_email))
    dp.add_handler(CommandHandler('buscarmail', buscar_mail))
    dp.add_handler(CommandHandler('listarworkbench', listar_workbench))
    dp.add_handler(CommandHandler('detalleworkbench', detalle_workbench))
    dp.add_handler(CommandHandler('workbenchstatus', cambiar_estado_workbench))
    dp.add_handler(CommandHandler('listarworkbenchnotes', listar_notas_workbench))
    dp.add_handler(CommandHandler('borrarnotaworkbench', borrar_nota_workbench))
    dp.add_handler(CommandHandler('agregarnotaworkbench', agregar_nota_workbench))
    dp.add_handler(CommandHandler('listartareas', listar_tareas))
    dp.add_handler(CommandHandler('detalleendpoints', detalle_endpoint))
    dp.add_handler(ConversationHandler(
        entry_points=[
            CommandHandler('ioc', ioc),
        ],
        states={
            INPUT_TEXT: [MessageHandler(Filters.text & ~Filters.command, update_ioc)],
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    ))
    dp.add_handler(ConversationHandler(
        entry_points=[
            CommandHandler('endpoint', endpoint)
        ],
        states={
            TEXTO_ENDPOINTS: [MessageHandler(Filters.text & ~Filters.command, isolate_endpoints_handler)]
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    ))

#lineas que arrancan el bot
    updater.start_polling()
    updater.idle()
