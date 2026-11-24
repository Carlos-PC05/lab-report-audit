"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente. En producción desde hace 18 meses; nadie lo ha
revisado desde entonces.

Punto de partida del Laboratorio 1 de Calidad de Software: este módulo
contiene problemas reales de seguridad, sembrados a propósito, que el
estudiante debe encontrar (primero a mano y luego con herramientas) y
corregir. No uses este código como ejemplo de cómo hacer las cosas.
"""

import hashlib
import os
import sqlite3
import subprocess
from contextlib import closing

import yaml

NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    with closing(sqlite3.connect(ruta_db)) as conexion:
        cursor = conexion.execute(
            "SELECT * FROM reportes WHERE cliente = ?", (nombre_cliente,)
        )
        return cursor.fetchall()


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    nombre, separador, extension = nombre_archivo.rpartition(".")
    if (
        not separador
        or extension != "html"
        or not nombre
        or not nombre.isascii()
        or not (nombre[0].isalnum() or nombre[0] == "_")
        or any(not (caracter.isalnum() or caracter in "_.-") for caracter in nombre)
    ):
        raise ValueError("Nombre de archivo no válido")
    salida = nombre_archivo + ".pdf"
    try:
        subprocess.run(["wkhtmltopdf", nombre_archivo, salida], check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return salida


def hash_password_legacy(password):
    """Genera el hash de una contraseña para el sistema legado de clientes."""
    sal = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), sal, 600_000)
    return f"{sal.hex()}:{derivado.hex()}"


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    estado = "configurada" if NOTIFICATION_API_KEY else "sin configurar"
    print(f"[NotifyAPI: clave {estado}] -> {email}: {mensaje}")
    return True
