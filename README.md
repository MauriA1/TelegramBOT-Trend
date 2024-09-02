<p align="center">
<img src="screenshots/BannerBTTMV1.png" width="1024" >
</p>

# Telegram Vision One Bot :robot:

Toma acciones en tu consola de Vision One por mensaje. El Bot se encargará de realizar el trabajo.

### Crea tu BOT de Telegram con BotFather y genera tu Token

[How To](https://core.telegram.org/bots)
<p align="center">
<img src="screenshots/BotTelegram2.png" width="400" >
</p>

### Pasos

#### Descarga el Proyecto

```bash
git clone git@github.com:Gig-Jag/Telegram
```

#### Construir la imagen

```bash
docker build -t bot .
```

#### Ejecutar el contenedor

```bash
docker run -e TOKEN_TELEGRAM="YOUR_TELEGRAM_TOKEN" bot
```

Diálogo entre el BOT y el Administrador, donde se le informa las instrucciones para realizar e impactar en su consola de Vision One. Utilizando el comando /help le proporcionara las posibiles acciones que pueda realizar.

<p align="center">
<img src="screenshots/TelegramDialogoAdministrador.png" width="400" >
</p>
<p align="center">
<img src="screenshots/TelegramBot2.jpg" width="800" >
</p>

## Proceso :robot:

Dentro de la consola Trend Micro Vision One, debemos generar un API Key la cual va a ser utilizada por el BOT.
Debemos editar el archivo engine.py, modificando el parametro token y agregaremos el valor de la API Key que nos otorga la consola de Vision One.

### Envío IoC al Bot

<p align="center">
<img src="screenshots/Carga2.png" width="400" >
</p>

### Impacto del IoC en Trend Micro Vision One

<p align="center">
<img src="screenshots/IoCTMV1.png" width="800" >
</p>

### Indicarle al Bot que aisle un Endpoint

<p align="center">
<img src="screenshots/Aislar.png" width="400" >
</p>

### Indicarle al Bot que restablezca un Endpoint

<p align="center">
<img src="screenshots/Restore.png" width="400" >
</p>

### Tareas realizadas Trend Micro Vision One

<p align="center">
<img src="screenshots/ResponseManagement.png" width="800" >
</p>
