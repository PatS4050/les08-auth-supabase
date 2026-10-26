/* eslint-disable @typescript-eslint/no-unused-vars -- startpunt: deze import gebruik je in stap 2. Haal deze regel weg als je klaar bent. */
import "server-only";
import {cache} from "react";
import {redirect} from "next/navigation";
import {createSupabaseServerClient} from "./supabase/server";

export type Arts = {
    id: number;
    naam: string;
    type: string;
};

/**
 * Geeft de ingelogde arts terug, of `null` als er niemand is ingelogd.
 *
 * `cache` zorgt dat dit per request maar één keer gebeurt, ook als meerdere
 * onderdelen van een pagina het vragen.
 */
export const getIngelogdeArts = cache(async (): Promise<Arts | null> => {
    // TODO stap 2: zoek uit wie er is ingelogd.
    //  - Maak een client met createSupabaseServerClient().
    //  - Vraag de gebruiker op uit het token van de sessie. Er zijn meerdere
    //    functies in supabase.auth die iets over de sessie teruggeven. Kies er
    //    één die het token écht controleert. Waarom mag je op de server
    //    getSession() níet vertrouwen?
    //  - Is er niemand ingelogd? Geef dan null terug.
    //  - Zoek in de tabel `arts` de rij waarvan user_id gelijk is aan het id van
    //    de gebruiker, en geef die terug (id, naam, type).
    // server getSession haalt de gegevens uit de cache en niet uit de database
    const supabase = await createSupabaseServerClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    // Is er niemand ingelogd? Geeft null terug
    if (error || !user) {
    return null;
};
    // Zoek de arts in database
    const { data: arts, error: artsError } = await supabase
        .from("arts")
        .select("id, naam, type")
        .eq("user_id", user.id)
        .maybeSingle();

    // Geen arts, geeft null terug
    if (artsError || !arts) {
        return null;
    }

    // Geeft arts terug
    return arts;
});


/** Voor pagina's achter de login: stuurt door naar /inloggen als er niemand is ingelogd. */
export async function vereisIngelogdeArts(): Promise<Arts> {
    const arts = await getIngelogdeArts();
    if (!arts) {
        redirect("/inloggen");
    }
    return arts;
}

/** Voor /inloggen en /registreren: wie al is ingelogd, gaat direct naar zijn afspraken. */
export async function stuurIngelogdeArtsDoor(): Promise<void> {
    if (await getIngelogdeArts()) {
        redirect("/mijn-afspraken");
    }
}
