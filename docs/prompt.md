[ ] PRE-BUCLE:
    1. Leer docs/task/7-1-classic-email-auth.md
    2. 📢 **LLAMADA AL PERSONAL SUB-DROID: test-generator**
        - **Instrucción de Ejecución:** Invocar al sub-droid con el nombre `test-generator`.
        - **Argumentos a pasar:**
            - `issue_id`: 7-1
            - `issue_title`: "classic-email-auth"
        - **Reglas Dinámicas:** El sub-droid consultará `AGENTS.md` para las reglas específicas de testing.
    3. ✋ **ESPERAR RESPUESTA DE Sub-Droid:**
        - Continuar si el sub-droid devuelve **"TESTS_GENERATED"** o **"TESTS_SKIPPED_BY_AGENTS_MD"**.
        - Si el sub-droid devuelve **"GENERATION_ERROR"**, analizar el reporte y saltar al paso 6 del BUCLE.
    4. No continuar hasta que el resultado de la llamada al sub-droid sea procesado.