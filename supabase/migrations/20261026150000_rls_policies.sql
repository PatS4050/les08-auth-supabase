
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

DROP POLICY IF EXISTS "receptionist_mag_alle_reserveringen_lezen" ON public.reserveringen;

CREATE POLICY "receptionist_mag_alle_reserveringen_lezen"
ON public.reserveringen
FOR SELECT TO authenticated
                    USING (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_mag_reserveringen_toevoegen" ON public.reserveringen;

CREATE POLICY "receptionist_mag_reserveringen_toevoegen"
ON public.reserveringen
FOR INSERT TO authenticated
WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_mag_reserveringen_wijzigen" ON public.reserveringen;

CREATE POLICY "receptionist_mag_reserveringen_wijzigen"
ON public.reserveringen
FOR UPDATE TO authenticated
                                USING (public.heeft_rol('receptionist'))
    WITH CHECK (public.heeft_rol('receptionist'));

DROP POLICY IF EXISTS "receptionist_mag_reserveringen_verwijderen" ON public.reserveringen;

CREATE POLICY "receptionist_mag_reserveringen_verwijderen"
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
