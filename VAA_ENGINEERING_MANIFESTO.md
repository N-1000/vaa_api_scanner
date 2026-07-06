# VAA Engineering Manifesto (v1.0)

Este documento define las reglas inquebrantables para el desarrollo de **LOKITRACE_ (VAA v8.0+)**. El objetivo es construir un motor de grado de producción, resiliente y escalable, eliminando parches técnicos y soluciones ad-hoc.

---

### 1. El Fin de la Dualidad (Unificación Local/Real)
*   **Regla**: El motor debe comportarse de forma idéntica independientemente del target.
*   **Prohibición**: Prohibido el uso de flags `is_local` o chequeos de IP (127.0.0.1) para alterar el comportamiento del motor.
*   **Solución**: Implementar **Heurísticas de Feedback**. 
    *   Si el servidor es rápido, el motor acelera.
    *   Si el servidor falla (429, timeouts), el `CircuitBreaker` frena.
*   **Principio**: El motor debe ser adaptativo, no predictivo.

### 2. Red Silenciosa y Resiliente (Network Layer)
*   **Regla**: El core de escaneo no debe gestionar el estado de las sesiones.
*   **Solución**: El `NetworkManager` debe implementar un patrón de **Auto-Sanación**.
    *   Cualquier error de `Session Closed` o `Connection Reset` debe ser capturado y resuelto internamente (re-conectando o rotando la sesión) antes de devolver el control al fuzzer o auditor.
*   **Mandato**: Eliminar guards preventivos como `getattr(session, '_closed')`. La resiliencia se delega al `try/except` durante la ejecución real para evitar chequeos de estado redundantes.

### 3. Fuzzing por Información (Gatekeeping)
*   **Regla**: No dispares por disparar.
*   **Solución**: El `ShannonOracle` actúa como portero, no como un monitor pasivo.
    *   Antes de encolar un ataque, el fuzzer consulta si el endpoint o parámetro ya está "exhausto" (si ya no aporta entropía o información nueva).
*   **Prohibición**: Prohibido encolar miles de tareas para luego cancelarlas con timeouts arbitrarios. El flujo debe ser limpio desde el origen.

### 4. Clasificación Contextual (M3)
*   **Regla**: Los Falsos Positivos se eliminan con lógica, no con simples filtros de Status Code.
*   **Solución**: La detección de reflexiones (Echos) es parte integral de la heurística de riesgo en el módulo M3.
    *   Si un payload se refleja en un cuerpo de error (422/500), el clasificador reduce el riesgo basándose en el contexto HTML/JSON, en lugar de ignorarlo automáticamente por el código de estado.

### 5. Arquitectura sobre Parches
*   **Regla**: Si una viga está agrietada, se refactoriza el componente original.
*   **Mandato**: No escribir código "de soporte" o wrappers alrededor de un bug conocido. 
*   **Mandato**: Corregir la implementación base aunque requiera modificar el core. La deuda técnica no se negocia. Todas las peticiones HTTP **deben** pasar por el `NetworkManager` para garantizar observabilidad y control.

---
*VAA v8.0 — Build to Last.*
