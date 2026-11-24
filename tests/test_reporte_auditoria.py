import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from reporte_auditoria import (
    buscar_reportes_cliente,
    convertir_a_pdf,
    hash_password_legacy,
    notificar_cliente,
)
from servicio import app


class ReporteAuditoriaTest(unittest.TestCase):
    def test_cliente_con_apostrofo(self):
        with TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / "reportes.db"
            conexion = sqlite3.connect(ruta)
            with conexion:
                conexion.execute("CREATE TABLE reportes (cliente TEXT)")
                conexion.executemany(
                    "INSERT INTO reportes VALUES (?)", [("acme",), ("o'brien",)]
                )
            conexion.close()
            self.assertEqual(buscar_reportes_cliente("o'brien", ruta), [("o'brien",)])

    def test_conversion_acepta_solo_nombres_html_simples(self):
        with (
            TemporaryDirectory() as carpeta,
            patch("reporte_auditoria.subprocess.run") as conversor,
            patch("reporte_auditoria.Path.cwd", return_value=Path(carpeta)),
        ):
            cliente = app.test_client()
            for nombre in ("../informe.html", "informe final.html", "-opcion.html"):
                with self.subTest(nombre=nombre):
                    respuesta = cliente.get("/convertir", query_string={"archivo": nombre})
                    self.assertEqual(respuesta.status_code, 400)
            conversor.assert_not_called()
            self.assertEqual(convertir_a_pdf("ausente.html"), "ausente.html.pdf")
            conversor.assert_not_called()
            entrada = Path(carpeta) / "informe-1.html"
            entrada.touch()
            self.assertEqual(convertir_a_pdf("informe-1.html"), "informe-1.html.pdf")
            conversor.assert_called_once_with(
                ["wkhtmltopdf", entrada, entrada.with_suffix(".html.pdf")], check=False
            )

    def test_misma_contrasena_recibe_sales_distintas(self):
        primero = hash_password_legacy("clave de prueba")
        segundo = hash_password_legacy("clave de prueba")
        self.assertNotEqual(primero.split(":")[0], segundo.split(":")[0])

    def test_notificacion_no_registra_la_clave(self):
        with (
            patch("reporte_auditoria.NOTIFICATION_API_KEY", "valor-de-prueba"),
            patch("builtins.print") as registro,
        ):
            self.assertTrue(notificar_cliente("cliente@example.test", "Reporte listo"))
            salida = registro.call_args.args[0]
            self.assertIn("clave configurada", salida)
            self.assertNotIn("valor-de-prueba", salida)
