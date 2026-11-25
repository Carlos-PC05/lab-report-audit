# Laboratorio 1. Bitácora de la cadena de suministro

- **Autor:** Carlos Parra Camacho
- **Repositorio:** [Carlos-PC05/lab-report-audit](https://github.com/Carlos-PC05/lab-report-audit)
- **Entorno:** Omarchy (Linux). Python 3.15.2 para el servicio y Python 3.12 para el hook de Semgrep.
- **Punto de partida de las mediciones:** `main` en `3be9487`, 24 de noviembre de 2026.

## Parte C. Lectura del código

Esta tabla es una revisión del código antiguo. No es una captura de la auditoría inicial.

| Hallazgo | Entrada | Operación a la que llega | Impacto |
| --- | --- | --- | --- |
| H1. SQL | Parámetro `cliente` en `/reportes` | `buscar_reportes_cliente` construía la consulta como texto | Podía devolver reportes de otro cliente. |
| H2. Comandos | Parámetro `archivo` en `/convertir` | `convertir_a_pdf` pasaba el nombre a `os.system` | La entrada podía modificar la orden que ejecutaba el servicio. |
| H3. YAML | Contenido de `app/config.yaml` | `cargar_configuracion` usaba `yaml.Loader` | Una configuración manipulada podía provocar efectos al cargarla. |
| H4. Hash débil | Contraseña que recibe `hash_password_legacy` | MD5 sin sal | Si se filtran los hashes, resulta más fácil probar contraseñas. |
| H5. Clave de notificaciones | Valor fijo en el código | `notificar_cliente` imprimía una parte en el registro | El repositorio y los registros podían exponer la clave. |
| H6. Contraseña SMTP | Valor fijo en el código | Constante incluida en el repositorio | Quien accede al historial puede recuperar el valor antiguo. |

## Partes G y H. Detección antes de corregir

SonarQube Cloud tenía [seis vulnerabilidades abiertas](evidencias/sonar-antes.json) y cero hotspots en `main`. CodeQL tenía [cuatro alertas abiertas](evidencias/codeql-antes.json): SQL, comandos, hash débil y registro de datos sensibles. Semgrep [terminó con código 1](evidencias/semgrep-antes.txt) y tres hallazgos bloqueantes. El código 1 sirve como evidencia de que el hook detectó problemas. El código 2 que apareció antes era un fallo del motor, que dejó de ocurrir al usar Python 3.12 para el hook. No se ha recuperado la captura original del commit bloqueado.

| Hallazgo | SonarQube Cloud | CodeQL | Semgrep | Trivy |
| --- | --- | --- | --- | --- |
| H1. SQL | Sí, S3649 | Sí, `py/sql-injection` | No | N/A |
| H2. Comandos | Sí, S2076 | Sí, `py/command-line-injection` | No | N/A |
| H3. YAML inseguro | No | No | Sí, `avoid-pyyaml-load` | N/A |
| H4. MD5 | Sí, S4790 | Sí, `py/weak-sensitive-data-hashing` | Sí, dos reglas de MD5 | N/A |
| H5. Clave de notificaciones | No | Detectó su registro parcial | No | No observado |
| H6. Contraseña SMTP | Sí, S2068 y S7552 | No | No | No observado |

Los IDs de Semgrep salen de una [segunda ejecución sobre los mismos archivos de partida](evidencias/semgrep-reglas-antes.json). Las pruebas de SonarQube for IDE en modo local y conectado quedan sin verificar.

## Parte I. Dependabot

Hay [12 alertas abiertas](evidencias/dependabot-antes.json) y GitHub abrió PR agrupados de seguridad ([#21](https://github.com/Carlos-PC05/lab-report-audit/pull/21) y [#22](https://github.com/Carlos-PC05/lab-report-audit/pull/22)). La configuración ya está en `main` y el [issue #5](https://github.com/Carlos-PC05/lab-report-audit/issues/5) figura cerrado.

La alerta [GHSA-2g68-c3qc-8985](https://github.com/advisories/GHSA-2g68-c3qc-8985) señala a Werkzeug 3.0.1 en `requirements.txt`. Es alta y se corrigió por primera vez en la versión 3.0.3. Werkzeug y Jinja2 llegan con Flask. Flask sí es una dependencia directa. El [PR #21](https://github.com/Carlos-PC05/lab-report-audit/pull/21) toca tanto `requirements.in` como el lockfile porque también actualiza una dependencia directa. Los checks de CodeQL pasaron. Los de SonarQube fallaron en la ejecución antigua, que todavía no tenía el archivo de configuración en su rama.

## Parte J. Herramientas

El instalador del repositorio verificó SHA-256 para Syft 1.52.0, Grype 0.119.0 y Trivy 0.74.0 antes de extraer los binarios.

## Parte K. SBOM y triage

El [SBOM](evidencias/sbom.cyclonedx.json) es CycloneDX 1.7. Hay 2 dependencias directas, 9 paquetes Python en el inventario, 4 entradas de acciones de GitHub y 2 archivos que Syft incluye como metadatos. Syft leyó el lockfile, por eso incluye Colorama aunque esa dependencia solo se instala en Windows.

[Grype](evidencias/grype-antes.txt) marcó 13 avisos. Dependabot mostraba 12. La diferencia en esta medición fue `GHSA-g6x2-hccm-hh4m`, que Grype encontró para Werkzeug y no estaba en la lista de alertas abiertas de GitHub.

| Paquete y versión | Tipo | Aviso | Severidad | Corregida en | Uso en ReportAudit y decisión |
| --- | --- | --- | --- | --- | --- |
| Werkzeug 3.0.1 | Transitiva | GHSA-2g68-c3qc-8985 | Alta | 3.0.3 | El depurador está apagado en el arranque de la app. Documentar y actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-q34m-jh98-gwm2 | Media | 3.0.6 | La app no recibe archivos en formularios. Actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-f9vj-2wh5-fj8j | Media | 3.0.6 | Afecta a la unión de rutas en Windows. Los endpoints no sirven rutas de usuario con esa utilidad. Actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-hgf8-39gv-g3f2 | Media | 3.1.4 | Afecta a nombres especiales de Windows en rutas. Actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-87hc-h4r5-73f7 | Media | 3.1.5 | Variante para nombres con extensiones en Windows. Actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-29vq-49wr-vm6x | Media | 3.1.6 | Variante del problema de rutas en Windows. Actualizar. |
| Werkzeug 3.0.1 | Transitiva | GHSA-g6x2-hccm-hh4m | Media | 3.1.9 | Otro caso de nombres de dispositivos de Windows. Comprobar que el parche elegido alcance esta versión. |
| Jinja2 3.1.2 | Transitiva | GHSA-h5c8-rqwp-cp95 | Media | 3.1.3 | La API devuelve JSON y no usa el filtro `xmlattr`. Actualizar. |
| Jinja2 3.1.2 | Transitiva | GHSA-h75v-3vvj-5mfj | Media | 3.1.4 | La API no pasa claves de usuario a `xmlattr`. Actualizar. |
| Jinja2 3.1.2 | Transitiva | GHSA-gmj6-6f8f-6699 | Media | 3.1.5 | La aplicación no compila plantillas con nombres controlados por usuarios. Actualizar. |
| Jinja2 3.1.2 | Transitiva | GHSA-q2x7-8rv6-6q7h | Media | 3.1.5 | La aplicación no usa el sandbox de Jinja. Actualizar. |
| Jinja2 3.1.2 | Transitiva | GHSA-cpwx-vrp4-4pq7 | Media | 3.1.6 | La aplicación no usa el sandbox ni su filtro `attr`. Actualizar. |
| Flask 3.0.0 | Directa | GHSA-68rp-wp8r-4726 | Baja | 3.1.3 | La aplicación no lee datos de sesión en sus endpoints. Actualizar. |

[VEX de ReportAudit](evidencias/reportaudit.openvex.json). El aviso del depurador de Werkzeug sigue siendo válido para la librería. En este servicio, el arranque documentado usa `debug=False`, por lo que no se ejecuta el código afectado.

## Parte L. Trivy

[Trivy](evidencias/trivy-antes.txt) también mostró 13 vulnerabilidades del lockfile: una alta, once medias y una baja. Aunque el escáner de secretos estaba habilitado, este informe no mostró hallazgos de secretos. La revisión del código sí localizó dos valores de práctica en el archivo de lógica. Que no salgan en un informe no demuestra que no existan.

## Parte M. Correcciones y verificación

En el [PR #25](https://github.com/Carlos-PC05/lab-report-audit/pull/25) la consulta usa parámetros; para el PDF se valida el nombre, se busca el archivo local y se llama al conversor sin shell; YAML se lee con `safe_load`; el hash usa PBKDF2 con sal y los valores de configuración salen de variables de entorno. El registro solo dice si la clave está configurada. Los valores sembrados son de práctica según la guía. Si se hubieran reutilizado credenciales reales, habría que rotarlas en su proveedor.

[Pruebas locales](evidencias/verificacion-auditoria.txt): la consulta devolvió dos reportes para `acme_corp` y uno para el cliente con apóstrofo. Un nombre con espacio o con ruta recibió HTTP 400. Para el nombre válido se simuló la llamada a `wkhtmltopdf` porque el binario no estaba instalado. Semgrep pasó después del cambio. Las cuatro pruebas añadidas al CI pasaron localmente con Python 3.12 y cubrieron el 95 % de las líneas del módulo de lógica.

El PR #25 se fusionó y el análisis de `main` terminó bien. Las cuatro alertas de CodeQL se cerraron automáticamente como [Fixed](evidencias/codeql-despues.json). SonarQube sigue mostrando `python:S4502`, sobre CSRF. No quedan hotspots en el panel. La actualización de dependencias va en el [PR #21](https://github.com/Carlos-PC05/lab-report-audit/pull/21), que propone Flask 3.1.3, Jinja2 3.1.6 y Werkzeug 3.1.9. CodeQL señala el código de la aplicación; Dependabot mira versiones de paquetes. Por eso corregir uno de los dos grupos no cierra automáticamente el otro.

## Parte N. Antes y después

| Medida | Antes | Después |
| --- | --- | --- |
| Semgrep, archivos de `app/` | 3 hallazgos bloqueantes | 0 bloqueantes en la rama del PR #25 |
| CodeQL, alertas abiertas en `main` | 4 | 0 abiertas; 4 cerradas como Fixed |
| SonarQube Cloud, vulnerabilidades y hotspots de `main` | 6 vulnerabilidades y 0 hotspots | 1 vulnerabilidad y 0 hotspots |
| Grype, avisos del SBOM | 13 | Pendiente de actualizar dependencias |
| Trivy, avisos del lockfile | 13 | Pendiente de actualizar dependencias |
| Dependabot, alertas abiertas | 12 | Pendiente de actualizar dependencias |

## Partes O a T

Pendientes de completar con evidencias de las ejecuciones y los PR correspondientes.

## Preguntas de comprobación

1. En el escenario de la guía, Windows aloja el editor y el navegador, Ubuntu en WSL2 contiene el clon, el entorno y las herramientas, y GitHub guarda el repositorio, las revisiones y CI. Aquí trabajé directamente en Linux. La ventaja es ejecutar todo en el mismo entorno.
2. Flask es directa porque está en `requirements.in`. Werkzeug es transitiva porque Flask la necesita y eso aparece en `# via flask`. Las dos aparecen en el SBOM.
3. Un *source* es la entrada de datos. Un *sink* es la operación que puede ser peligrosa si esa entrada llega sin tratar. Antes, el parámetro `cliente` de `servicio.py` llegaba a la consulta de SQLite que construía `reporte_auditoria.py`.
4. El apóstrofo de un nombre normal rompía la cadena SQL porque se pegaba dentro del texto de la consulta. Esto muestra que parte de la entrada podía cambiar cómo SQLite interpreta la orden. Con un parámetro, el apóstrofo forma parte del dato.
5. Semgrep avisa en el equipo antes de que salga un commit. El análisis en GitHub deja resultados visibles para toda la revisión, incluso si alguien no ejecutó el hook. Los tres dependen de sus reglas y del contexto que reconocen.
6. Las herramientas tienen alcances distintos. En la medición de partida CodeQL abrió cuatro alertas, Semgrep bloqueó por tres hallazgos, SonarQube mostró seis vulnerabilidades y Trivy marcó trece avisos del lockfile.
7. Cambiar el código arregla hallazgos de análisis estático. Cambiar las versiones del lockfile retira dependencias afectadas. Cada cambio responde a un tipo diferente de alerta.
8. Borrar un valor corta su exposición en el archivo actual. Si el valor era real, también hay que invalidarlo o rotarlo, revisar su uso y guardar el sustituto fuera del código. El valor anterior sigue en commits y clones.
9. Un VEX deja registrada la razón por la que un aviso no afecta a un producto en una configuración concreta. En este proyecto el aviso del depurador de Werkzeug no aplica al arranque documentado porque el depurador está apagado. Aun así conviene actualizar.
10. El instalador compara el SHA-256 del archivo descargado con el publicado para la versión fijada. La coincidencia comprueba la integridad respecto a esa referencia, pero no demuestra que el proyecto o su canal de publicación estuvieran libres de manipulación.

Preguntas 11 a 17 pendientes de completar con las evidencias de O a T.
