
-- =====================================================
-- RLS POLICIES - TANDARTSPRAKTIJK
-- Receptionist autorisatie
-- =====================================================

-- -----------------------------------------------------
-- 1. FUNCTIE: controleren of ingelogde gebruiker een rol heeft
-- -----------------------------------------------------

CREATE OR REPLACE FUNCTION public.heeft_rol(rol text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO ''
AS $function$

SELECT
    EXISTS (
        SELECT 1
        FROM public.arts a
        WHERE a.user_id = (SELECT auth.uid())
          AND LOWER(TRIM(a.type)) = LOWER(TRIM(rol))
    )
        OR EXISTS (
        SELECT 1
        FROM public.ondersteuning o
        WHERE o.user_id = (SELECT auth.uid())
          AND LOWER(TRIM(o.type)) = LOWER(TRIM(rol))
    )
        OR EXISTS (
        SELECT 1
        FROM public.client c
        WHERE c.user_id = (SELECT auth.uid())
          AND LOWER(TRIM(c.type)) = LOWER(TRIM(rol))
    );
$function$;

REVOKE ALL ON FUNCTION public.heeft_rol(text)
FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.heeft_rol(text)
TO authenticated;


-- -----------------------------------------------------
-- 2. RLS INSCHAKELEN
-- -----------------------------------------------------

ALTER TABLE public.arts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reserveringen ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.client ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.beschikbaarheid ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ondersteuning ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behandelingen ENABLE ROW LEVEL SECURITY;


-- -----------------------------------------------------
-- 3. ARTS
-- -----------------------------------------------------

DROP POLICY IF EXISTS "receptionist_mag_alle_artsen_lezen" ON public.arts;

CREATE POLICY "receptionist_mag_alle_artsen_lezen"
ON public.arts
FOR SELECT TO authenticated
                    USING (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_mag_alle_artsen_wijzigen" ON public.arts;

CREATE POLICY "receptionist_mag_alle_artsen_wijzigen"
ON public.arts
FOR UPDATE TO authenticated
                    USING (public.heeft_rol('receptionist'))
    WITH CHECK (public.heeft_rol('receptionist'));


-- -----------------------------------------------------
-- 4. RESERVERINGEN
-- -----------------------------------------------------

DROP POLICY IF EXISTS "Receptionist mag reserveringen bekijken" ON public.reserveringen;

CREATE POLICY "Receptionist mag reserveringen bekijken"
ON public.reserveringen
FOR SELECT TO authenticated
                    USING (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "Receptionist mag reserveringen aanmaken" ON public.reserveringen;

CREATE POLICY "Receptionist mag reserveringen aanmaken"
ON public.reserveringen
FOR INSERT TO authenticated
WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "Receptionist mag reserveringen wijzigen" ON public.reserveringen;

CREATE POLICY "Receptionist mag reserveringen wijzigen"
ON public.reserveringen
FOR UPDATE TO authenticated
                                USING (public.heeft_rol('receptionist'))
    WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "Receptionist mag reserveringen verwijderen" ON public.reserveringen;

CREATE POLICY "Receptionist mag reserveringen verwijderen"
ON public.reserveringen
FOR DELETE TO authenticated
USING (public.heeft_rol('receptionist'));


-- -----------------------------------------------------
-- 5. CLIENT
-- -----------------------------------------------------

DROP POLICY IF EXISTS "receptionist_client_lezen" ON public.client;

CREATE POLICY "receptionist_client_lezen"
ON public.client
FOR SELECT TO authenticated
USING (public.heeft_rol('receptionist'));

-- Een cliënt mag alleen het eigen profiel bekijken
DROP POLICY IF EXISTS "client_mag_eigen_profiel_inzien"
ON public.client;

CREATE POLICY "client_mag_eigen_profiel_inzien"
ON public.client
FOR SELECT
TO authenticated
USING (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS "receptionist_client_toevoegen" ON public.client;

CREATE POLICY "receptionist_client_toevoegen"
ON public.client
FOR INSERT TO authenticated
WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_client_wijzigen" ON public.client;

CREATE POLICY "receptionist_client_wijzigen"
ON public.client
FOR UPDATE TO authenticated
                                USING (public.heeft_rol('receptionist'))
    WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_client_verwijderen" ON public.client;

CREATE POLICY "receptionist_client_verwijderen"
ON public.client
FOR DELETE TO authenticated
USING (public.heeft_rol('receptionist'));


-- -----------------------------------------------------
-- 6. BESCHIKBAARHEID
-- -----------------------------------------------------

DROP POLICY IF EXISTS "receptionist_beschikbaarheid_lezen" ON public.beschikbaarheid;

CREATE POLICY "receptionist_beschikbaarheid_lezen"
ON public.beschikbaarheid
FOR SELECT TO authenticated
                                           USING (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_beschikbaarheid_toevoegen" ON public.beschikbaarheid;

CREATE POLICY "receptionist_beschikbaarheid_toevoegen"
ON public.beschikbaarheid
FOR INSERT TO authenticated
WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_beschikbaarheid_wijzigen" ON public.beschikbaarheid;

CREATE POLICY "receptionist_beschikbaarheid_wijzigen"
ON public.beschikbaarheid
FOR UPDATE TO authenticated
                                USING (public.heeft_rol('receptionist'))
    WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_beschikbaarheid_verwijderen" ON public.beschikbaarheid;

CREATE POLICY "receptionist_beschikbaarheid_verwijderen"
ON public.beschikbaarheid
FOR DELETE TO authenticated
USING (public.heeft_rol('receptionist'));

           -- -----------------------------------------------------
-- 7. ARTS: eigen profiel bekijken
-- -----------------------------------------------------

DROP POLICY IF EXISTS "arts_mag_eigen_profiel_inzien"
ON public.arts;

CREATE POLICY "arts_mag_eigen_profiel_inzien"
ON public.arts
FOR SELECT TO authenticated
USING (user_id = (SELECT auth.uid()));


-- -----------------------------------------------------
-- 8. BEHANDELINGEN: publiek bekijken
-- -----------------------------------------------------

DROP POLICY IF EXISTS "behandelingen voor publiek"
ON public.behandelingen;

CREATE POLICY "behandelingen voor publiek"
ON public.behandelingen
FOR SELECT TO anon, authenticated
                    USING (true);


-- -----------------------------------------------------
-- 9. RESERVERINGEN: tandarts eigen afspraken
-- -----------------------------------------------------

DROP POLICY IF EXISTS "afspraken_tandarts"
ON public.reserveringen;

CREATE POLICY "afspraken_tandarts"
ON public.reserveringen
FOR SELECT TO authenticated
USING (
arts_id IN (
SELECT arts.id
FROM public.arts
WHERE arts.user_id = (SELECT auth.uid())
)
);
-- =====================================================
-- 10. Ondersteunend personeel
-- =====================================================

-- Ondersteunend personeel mag alleen het eigen profiel bekijken
DROP POLICY IF EXISTS "ondersteuning_mag_eigen_profiel_inzien"
ON public.ondersteuning;

CREATE POLICY "ondersteuning_mag_eigen_profiel_inzien"
ON public.ondersteuning
FOR SELECT TO authenticated
                    USING (user_id = (SELECT auth.uid()));

-- =====================================================
-- 11. TABELRECHTEN BEPERKEN
-- =====================================================

-- Publieke bezoekers: geen rechtstreekse tabeltoegang
REVOKE ALL ON TABLE
    public.arts,
    public.beschikbaarheid,
    public.reserveringen,
    public.client,
    public.ondersteuning
    FROM anon;

-- Behandelingen mogen publiek gelezen worden
REVOKE ALL ON TABLE public.behandelingen FROM anon;
GRANT SELECT ON TABLE public.behandelingen TO anon;

-- Ingelogde gebruikers krijgen alleen rechten
-- die door hun RLS-policies verder worden beperkt.
GRANT SELECT, INSERT, UPDATE, DELETE
      ON TABLE
          public.arts,
          public.beschikbaarheid,
          public.reserveringen,
          public.client,
          public.ondersteuning,
          public.behandelingen
          TO authenticated;


-- -----------------------------------------------------
-- 12. FUNCTIERECHTEN VOOR AFSPRAKEN
-- -----------------------------------------------------

GRANT EXECUTE ON FUNCTION
public.beschikbare_tijden(text, date, integer)
TO anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION
    public.boek_afspraak(text, date, time, text, text)
TO anon, authenticated, service_role;