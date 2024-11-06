from telegram.ext import Updater, CommandHandler, ConversationHandler, MessageHandler, Filters, CallbackContext
from telegram import Update
from engine import *
import logging, os

# Variables para los estados en la conversaciÃ³n
TEXTO_ENDPOINTS = 0
INPUT_TEXT = 0

# Lista de user_ids autorizados
authorized_users = [5688659524]  # Reemplaza con los user_ids autorizados

# Funcion de start con control de acceso basado en user_id
def start(update, context):
    user_id = update.message.from_user.id  # Obtiene el user_id del usuario
    full_name = update.message.from_user.full_name  # Nombre completo del usuario

    # Verifica si el user_id esta en la lista de autorizados
    if user_id in authorized_users:
        logger.info(f'He recibido un comando start de {full_name} (user_id: {user_id})')
        update.message.reply_text(f'Bienvenido al Bot de Vision One, {full_name}! Para conocer los comandos disponibles, escribe /help')
    else:
        logger.warning(f'Intento de acceso no autorizado de {full_name} (user_id: {user_id})')
        update.message.reply_text('Acceso denegado. No tienes permiso para utilizar este bot.')

#Funcion        
def chiste(update, context):
    logger.info('Consultando API Chiste')
    update.message.reply_text(get_chiste())


# Funcion para cargar SHA256 separado por coma

def cargar_sha256(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /sha256
    hashes = update.message.text[len('/sha256 '):]
    
    # Divide los hashes por coma y limpia espacios
    lista_hashes = [hash.strip() for hash in hashes.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de los hashes
    response = procesar_sha256(lista_hashes)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de hashes: {response}')

# FunciÃ³n que se ejecuta al recibir el comando /sha1
def cargar_sha1(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /sha1
    hashes = update.message.text[len('/sha1 '):]
    
    # Divide los hashes por coma y limpia espacios
    lista_hashes = [hash.strip() for hash in hashes.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de los hashes
    response = procesar_sha1(lista_hashes)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de hashes: {response}')

# FunciÃ³n que se ejecuta al recibir el comando /ip
def cargar_ip(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /ip
    ips = update.message.text[len('/ip '):]
    
    # Divide las IPs por coma y limpia espacios
    lista_ips = [ip.strip() for ip in ips.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de las IPs
    response = procesar_ip(lista_ips)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de IPs: {response}')

# FunciÃ³n que se ejecuta al recibir el comando /url
def cargar_url(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /url
    urls = update.message.text[len('/url '):]
    
    # Divide las URLs por coma y limpia espacios
    lista_urls = [url.strip() for url in urls.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de las URLs
    response = procesar_url(lista_urls)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de URLs: {response}')

# FunciÃ³n que se ejecuta al recibir el comando /domain
def cargar_domain(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /domain
    domains = update.message.text[len('/domain '):]
    
    # Divide los dominios por coma y limpia espacios
    lista_domains = [domain.strip() for domain in domains.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de los dominios
    response = procesar_domain(lista_domains)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de dominios: {response}')

# FunciÃ³n que se ejecuta al recibir el comando /sender
def cargar_sender(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /sender
    senders = update.message.text[len('/sender '):]
    
    # Divide las direcciones de correo por coma y limpia espacios
    lista_senders = [sender.strip() for sender in senders.split(',')]
    
    # Llama a la funciÃ³n que maneja la carga de los senders
    response = procesar_sender(lista_senders)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la carga de remitentes: {response}')

# Funciones para eliminar indicadores de compromiso cargados

def eliminar_objeto_sospechoso_sha256(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminarsha256
    objetos = update.message.text[len('/eliminarsha256 '):]
    
    # Divide los hashes SHA256 sospechosos por coma y limpia espacios
    lista_sha256 = [sha256.strip() for sha256 in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de los hashes SHA256 sospechosos
    response = eliminar_suspicious_objects_sha256(lista_sha256)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de hashes SHA256 sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_sha1(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminarsha1
    objetos = update.message.text[len('/eliminarsha1 '):]
    
    # Divide los hashes SHA1 sospechosos por coma y limpia espacios
    lista_sha1 = [sha1.strip() for sha1 in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de los hashes SHA1 sospechosos
    response = eliminar_suspicious_objects_sha1(lista_sha1)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de hashes SHA1 sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_ip(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminarip
    objetos = update.message.text[len('/eliminarip '):]
    
    # Divide las IPs sospechosas por coma y limpia espacios
    lista_ips = [ip.strip() for ip in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de las IPs sospechosas
    response = eliminar_suspicious_objects_ip(lista_ips)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de IPs sospechosas: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_url(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminarurl
    objetos = update.message.text[len('/eliminarurl '):]
    
    # Divide las URLs sospechosas por coma y limpia espacios
    lista_urls = [url.strip() for url in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de las URLs sospechosas
    response = eliminar_suspicious_objects_url(lista_urls)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de URLs sospechosas: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_domain(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminardomain
    objetos = update.message.text[len('/eliminardomain '):]
    
    # Divide los dominios sospechosos por coma y limpia espacios
    lista_dominios = [dominio.strip() for dominio in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de los dominios sospechosos
    response = eliminar_suspicious_objects_domain(lista_dominios)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de dominios sospechosos: {json.dumps(response, indent=4)}')

def eliminar_objeto_sospechoso_sender(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /eliminar
    objetos = update.message.text[len('/eliminarsender '):]
    
    # Divide los objetos sospechosos por coma y limpia espacios
    lista_objetos = [objeto.strip() for objeto in objetos.split(',')]
    
    # Llama a la funciÃ³n que maneja la eliminaciÃ³n de los objetos sospechosos
    response = eliminar_suspicious_objects_sender(lista_objetos)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la eliminaciÃ³n de senders sospechosos: {json.dumps(response, indent=4)}')

# Funcion para Aislar Equipos separado por coma

def aislar(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /aislar
    equipos = update.message.text[len('/aislar '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la funciÃ³n para aislar los equipos
    resultado = isolate_endpoints(lista_equipos)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del aislamiento: {resultado}')

def restaurar(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /aislar
    equipos = update.message.text[len('/restaurar '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la funciÃ³n para aislar los equipos
    resultado = restore_endpoints(lista_equipos)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del restore: {resultado}')

def escanear_malware(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /escanear
    equipos = update.message.text[len('/escanear '):]
    
    # Divide los nombres de equipos por coma y limpia espacios
    lista_equipos = [equipo.strip() for equipo in equipos.split(',')]
    
    # Llama a la funciÃ³n para iniciar el escaneo de malware
    resultado = start_malware_scan(lista_equipos)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del escaneo: {json.dumps(resultado, indent=4)}')

# Funcion para listar script personalizados cargados en Vision One

def listar_script(update: Update, context: CallbackContext) -> None:
    # Llama a la funciÃ³n que maneja la lista de scripts personalizados
    response = listar_scripts_personalizados()
    
    # Si la respuesta es JSON, formatear adecuadamente
    if isinstance(response, dict):
        response_text = json.dumps(response, indent=4)
    else:
        response_text = response

    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la lista de scripts personalizados: {response_text}')

# Funcion para ejecutar una script personalizada sobre una lista de equipos
def ejecutar_script(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /script
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

        # Verificar si hay parÃ¡metros opcionales
        parametros = []
        if '/parametro' in script_part:
            parametros = script_part.split('/parametro')[1].strip().split()

        # Separar los targets por comas y limpiar espacios
        lista_endpoints = [target.strip() for target in targets_part.split(',') if target.strip()]

        # Verifica que tanto el nombre del script como la lista de endpoints no estÃ©n vacÃ­os
        if not nombre_script or not lista_endpoints:
            update.message.reply_text("Formato incorrecto. Usa: /script nombre_script /parametro parametro1,parametro2 /target equipo1,equipo2, equipo3")
            return

        # Llama a la funciÃ³n que ejecuta la script personalizada en los endpoints
        response = ejecutar_script_customizado(nombre_script, lista_endpoints, parametros)

        # EnvÃ­a el resultado al chat
        update.message.reply_text(f'Resultado de la ejecuciÃ³n del script {nombre_script}: {json.dumps(response, indent=4)}')

    except Exception as e:
        # Captura cualquier otra excepciÃ³n inesperada
        update.message.reply_text(f"Se produjo un error: {str(e)}")

#ejemplo: /script nombre_script /target endpoint1, endpoint2, endpoint3

#Funciones relacionadas a cuentas de usuarios

    #FunciÃ³n para deshabilitar cuentas

def deshabilitar_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /disable
    cuentas = update.message.text[len('/disable '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la funciÃ³n que maneja la deshabilitaciÃ³n de cuentas
    response = deshabilitar_cuentas(lista_cuentas)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la deshabilitaciÃ³n de cuentas: {json.dumps(response, indent=4)}')

    #Funcion para habilitar cuentas
def habilitar_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /enable
    cuentas = update.message.text[len('/enable '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la funciÃ³n que maneja la habilitaciÃ³n de cuentas
    response = habilitar_cuentas(lista_cuentas)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la habilitaciÃ³n de cuentas: {json.dumps(response, indent=4)}')

    #Funcion para desloguear cuentas
def desloguear_cuentas_comando(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /logout
    cuentas = update.message.text[len('/logout '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la funciÃ³n que maneja el deslogueo de cuentas
    response = desloguear_cuentas(lista_cuentas)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del deslogueo de cuentas: {json.dumps(response, indent=4)}')

    #FunciÃ³n para resetear el password de una cuenta

def resetear_password_comando(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /resetpassword
    cuentas = update.message.text[len('/resetpassword '):]
    
    # Divide las cuentas por comas y limpia espacios
    lista_cuentas = [cuenta.strip() for cuenta in cuentas.split(',')]
    
    # Llama a la funciÃ³n que maneja el reseteo de contraseÃ±as
    response = resetear_password(lista_cuentas)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del reseteo de contraseÃ±as: {json.dumps(response, indent=4)}')

#Funciones relacionadas a emails

def borrar_mensaje(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /borrarmail
    uuids = update.message.text[len('/borrarmail '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la funciÃ³n que maneja el borrado de los mensajes
    response = eliminar_mensajes_por_uuid(lista_uuids)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del borrado de mensajes: {response}')

def enviar_a_cuarentena(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /cuarentena
    uuids = update.message.text[len('/cuarentena '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la funciÃ³n que maneja el envÃ­o a cuarentena
    response = mandar_mensajes_a_cuarentena(lista_uuids)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado del envÃ­o a cuarentena: {response}')

def restaurar_email(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /restauraremail
    uuids = update.message.text[len('/restauraremail '):]
    
    # Divide los UUIDs por coma y limpia espacios
    lista_uuids = [uuid.strip() for uuid in uuids.split(',')]
    
    # Llama a la funciÃ³n que maneja la restauraciÃ³n de los mensajes
    response = restaurar_mensajes(lista_uuids)
    
    # EnvÃ­a el resultado al chat
    update.message.reply_text(f'Resultado de la restauraciÃ³n de mensajes: {response}')

def buscar_mail(update: Update, context: CallbackContext) -> None:
    # ObtÃ©n el texto despuÃ©s del comando /buscarmail
    asunto = update.message.text[len('/buscarmail '):].strip()

    # Pasa el asunto a la funciÃ³n con comillas dobles estÃ¡ndar
    asunto = asunto.replace('â€œ', '"').replace('â€', '"')
    response = buscar_correos_por_asunto(f'"{asunto}"')
    
    if response.get('error'):
        update.message.reply_text(f"Error: {response['error']}")
        return
    
    # ObtÃ©n el nÃºmero de mensajes y los UUIDs
    num_mensajes = len(response.get('items', []))
    uuids = [item['uniqueId'] for item in response.get('items', [])]
    
    # Prepara el mensaje de respuesta
    uuids_text = ','.join(uuids)
    update.message.reply_text(f"Se detectaron {num_mensajes} mensajes con el asunto '{asunto}'. UUIDs: {uuids_text}")



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
    logger.info('Se recibiÃ³ el texto a parsear')
    text = update.message.text
    direcciones_ip = get_ips(text)
    hashes = get_hashes(text)
    if direcciones_ip:
        logger.info(f'Las Direcciones IP: {direcciones_ip}')
        update.message.reply_text(f'Se recibiÃ³ el IoC, procederemos a aplicar los siguientes cambios. Direcciones IPs: {direcciones_ip}')
    if hashes:
        logger.info(f'Los Hash: {hashes}')
        update.message.reply_text(f'Se recibiÃ³ el IoC, procederemos a aplicar los siguientes cambios. Hashes: {hashes}')
    return ConversationHandler.END

# Funcion que cancela la conversacion
def cancel(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('Comando cancelado.', reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

# FunciÃ³n para el comando /help
def help_command(update: Update, context: CallbackContext):
    help_text = (
        "Estos son los comandos que puede utilizar:\n"
        "/start - Comando para iniciar el bot.\n"
        "/help - Lista los comandos disponibles con el bot.\n"
        "/aislar <EndpointName> - Con este comando aislaremos un equipo en concreto.\n"
        "/restaurar <EndpointName> - Haremos un restore del equipo aislado previamente\n"
        "/sha1 <SHA1> - Con este comando agregaremos un HASH en el formato indicado a la lista de indicadores de compromiso.\n"
        "/sha256 <SHA256> - Con este comando agregaremos un HASH en el formato indicado a la lista de indicadores de compromiso.\n"
        "/ip <Direccion IP> - Con este comando agregaremos una direccion IP a la lista de indicadores de compromiso.\n"
        "/url <URL> - Con este comando agregaremos una URL a la lista de indicadores de compromiso.\n"
        "/domain <Dominio> - Con este comando agregaremos un Dominio a la lista de indicadores de compromiso.\n"
        "/sender <Remitente> - Con este comando agregaremos un Remitente a la lista de indicadores de compromiso.\n"
        "/eliminarsha256 <Hash SHA256> - Con este comando eliminaremos un HASH en el formato indicado de la lista de IOC.\n"
        "/eliminarsha1 <Hash SHA1> - Con este comando eliminaremos un HASH en el formato indicado de la lista de IOC.\n"
        "/eliminarip <Direccion IP> - Con este comando eliminaremos una direccion IP de la lista de IOC.\n"
        "/eliminarurl <Protocolo://URL> - Eliminaremo la URL de la lista de IOC.\n"
        "/eliminardomain <Dominio> - Con este comando eliminaremos el Dominio de la lista de IOC.\n"
        "/eliminarsender <Sender> - Con este comando eliminaremos el Sender de la lista de IOC.\n"
#       "/borrarmail <MessageID> - Con este comando eliminaremos el correo utilizando el ID del mensaje.\n"
#       "/cuarentena <MessageID> - Con este comando enviaremos a cuarentena el correo utilizando el ID del mensaje.\n"
#       "/restauraremail <MessageID> - Con este comando podemos restaurar el correo utilizando el ID del mensaje.\n"
#       "/buscarmail <Asunto> - Con este comando podemos buscar un mail agregando el asunto del correo.\n"
        "/escanear - Ejecutaremos un Scan Now en el equipo que le indiquemos.\n"
        "/listarscript - Listaremos los scripts personalizados cargados en Vision One.\n"
        "/script - Ejecutaremos un script, es recomendable listarlo anteriormente para poner el nombre exacto.\n"
        "/disable <Cuenta> - Deshabilitaremos una cuenta.\n"
        "/enable <Cuenta> - Habilitaremos una cuenta.\n"
        "/logout <Cuenta> - Forzaremos un deslogueo en la cuenta.\n"
        "/resetpassword <Cuenta> - Forzaremos un reinicio de la clave en la cuenta mencionada.\n"

        # Agregar los demas comandos
    )
    update.message.reply_text(help_text)

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
#   dp.add_handler(CommandHandler('borrarmail', borrar_mensaje))
#   dp.add_handler(CommandHandler('cuarentena', enviar_a_cuarentena))
#   dp.add_handler(CommandHandler('restauraremail', restaurar_email))
#   dp.add_handler(CommandHandler('buscarmail', buscar_mail))
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
    dp.add_handler(CommandHandler ('help', help_command))

#lineas que arrancan el bot
    updater.start_polling()
    updater.idle()

