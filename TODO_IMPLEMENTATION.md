# TODO: Implementatie & Bugfix Rapport (Auth Service)

**Datum:** 21 November 2025
**Status:** 52 Tests Geslaagd, 12 Overgeslagen (Skipped)
**Doel:** 100% Test Coverage en volledig werkende functionaliteit bereiken.

Hieronder volgen de taken die uitgevoerd moeten worden om de overgeslagen tests te laten slagen.

## 1. Organisatie Management (Multi-tenancy)
*Tests overgeslagen omdat endpoints `501 Not Implemented` retourneren.*

De database tabellen (`organizations`, `organization_members`) bestaan, maar de API-logica ontbreekt.

*   **Bestanden:** `app/api/v1/admin.py`, `app/api/v1/users.py`, `app/services/auth_service.py`
*   **Te implementeren functionaliteit:**
    1.  **Create Organization (Admin):** Implementeer `POST /api/v1/admin/organizations`. Moet een nieuwe organisatie in de DB aanmaken.
    2.  **List User Organizations:** Implementeer `GET /api/v1/users/organizations`. Moet alle organisaties teruggeven waar de ingelogde gebruiker lid van is.
    3.  **Switch Organization:** Implementeer `POST /api/v1/users/switch-org`.
        *   Verifieer of de gebruiker lid is van de doel-organisatie.
        *   Genereer een **nieuw** access token met de `org_id` en bijbehorende `roles` in de claims.

## 2. Bugfixes & Logica Verbeteringen

### A. Admin Self-Ban Preventie
*Test:* `tests/test_admin.py::TestAdminBanUser::test_admin_cannot_ban_self`

*   **Probleem:** Een admin kan momenteel zichzelf bannen (`POST /users/{id}/ban`). Dit kan leiden tot situaties waarin niemand meer toegang heeft.
*   **Taak:** Voeg een check toe in `app/api/v1/admin.py` (endpoint `ban_user`) om te voorkomen dat `user_id == current_user.id`.
*   **Gewenst resultaat:** Return HTTP `403 Forbidden` als een admin zichzelf probeert te bannen.

### B. GDPR Self-Deletion (500 Error)
*Test:* `tests/test_flows.py::TestGDPRSelfDeletion::test_self_deletion_flow`

*   **Probleem:** `DELETE /api/v1/users/me` crasht met een `500 Internal Server Error`. Waarschijnlijk door *Foreign Key constraints* (bijv. openstaande audit logs, tokens, of organisatie-lidmaatschappen die aan de gebruiker hangen).
*   **Taak:**
    *   Debug de 500 error.
    *   Zorg voor een "soft delete" (anonimiseren van data) OF een correcte "hard delete" met `CASCADE` verwijdering van gerelateerde records.
    *   Zorg dat tokens direct worden ingetrokken.

## 3. Data Persistentie: Wachtwoord Reset & Email Verificatie
*Tests:* `TestPasswordResetFlow` & `TestEmailVerificationFlow` (meerdere tests)

*   **Probleem:** De tests verwachten dat verificatiecodes worden opgeslagen in de PostgreSQL tabellen `password_reset_codes` en `email_verification_codes`. De huidige implementatie lijkt alleen Redis te gebruiken of genereert alleen tokens zonder ze op te slaan.
*   **Taak:**
    *   Update `AuthService.forgot_password`: Sla de gegenereerde code/token op in de tabel `password_reset_codes`.
    *   Update `AuthService.resend_verification`: Sla de verificatiecode op in de tabel `email_verification_codes`.
    *   *Alternatief:* Als Redis de *single source of truth* blijft, moeten de tests worden aangepast om in Redis te kijken in plaats van in de SQL database. Echter, voor audit-doeleinden is opslag in SQL aanbevolen.

## 4. HTTP Headers & Security
*Test:* `tests/test_security.py::TestRateLimiting::test_rate_limit_headers`

*   **Probleem:** De API retourneert geen headers die de client informeren over de rate limits.
*   **Taak:** Configureer de rate limiter (of middleware) zodat de volgende headers worden meegestuurd bij elk request (of in ieder geval bij 429 responses):
    *   `X-RateLimit-Limit`
    *   `X-RateLimit-Remaining`
    *   `X-RateLimit-Reset`

***

### Aanbevolen Volgorde van Uitvoering:
1.  **Bugfixes (Punt 2):** Snel op te lossen en verhoogt de stabiliteit.
2.  **Data Persistentie (Punt 3):** Cruciaal voor een betrouwbare user flow.
3.  **Organisatie Management (Punt 1):** Grote feature, maar essentieel voor multi-tenancy.
4.  **Headers (Punt 4):** "Nice to have", kan als laatste.
