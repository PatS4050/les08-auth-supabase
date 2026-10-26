/* eslint-disable @typescript-eslint/no-unused-vars -- startpunt: deze imports en helpers gebruik je in stap 2. Haal deze regel weg als je klaar bent. */
"use server";

import {headers} from "next/headers";
import {redirect} from "next/navigation";
import {isArtsType} from "@/lib/arts";
import {createSupabaseServerClient} from "@/lib/supabase/server";
import {isGeldigEmail, leesTekst} from "@/lib/validatie";

type Veld = "naam" | "type" | "email" | "wachtwoord" | "wachtwoordHerhaling";

export type RegistratieResultaat =
    | { status: "idle" }
    /** Account aangemaakt, maar het e-mailadres moet nog bevestigd worden. */
    | { status: "bevestig-email"; email: string }
    | {
    status: "error";
    veldFouten: Partial<Record<Veld, string>>;
    /** Fout die niet bij één veld hoort. */
    melding?: string;
    /** Ingevulde waarden om het formulier mee te vullen. Wachtwoorden sturen we bewust nooit terug. */
    invoer: { naam: string; type: string; email: string };
};

const NAAM_MAX_LENGTE = 100;
// Minimaal 8 tekens; maximaal 72 omdat bcrypt (ook gebruikt door Supabase Auth) de rest negeert.
const WACHTWOORD_MIN_LENGTE = 8;
const WACHTWOORD_MAX_LENGTE = 72;

export async function registreer(
    _vorigResultaat: RegistratieResultaat,
    formData: FormData
): Promise<RegistratieResultaat> {
    const invoer = {
        naam: leesTekst(formData, "naam").trim(),
        type: leesTekst(formData, "type"),
        email: leesTekst(formData, "email").trim().toLowerCase(),
    };
    const wachtwoord = leesTekst(formData, "wachtwoord");
    const wachtwoordHerhaling = leesTekst(formData, "wachtwoordHerhaling");

    const veldFouten = valideer({...invoer, wachtwoord, wachtwoordHerhaling});
    if (veldFouten) {
        return {status: "error", veldFouten, invoer};
    }

    // TODO stap 2: registreer de gebruiker bij Supabase.
    //  - Maak een client met createSupabaseServerClient().
    //  - Gebruik de juiste functie van supabase.auth om een account aan te maken.
    //  - Stuur naam en type mee als metadata (options.data). De database-trigger
    //    maak_arts_na_registratie (zie de migratie auth_basis) maakt daarmee
    //    automatisch de rij in `arts` aan.
    //  - Geef ook options.emailRedirectTo mee, zodat de link in de bevestigingsmail
    //    naar `${await siteUrl()}/auth/callback?next=/mijn-afspraken` gaat.
    //  - Gaat het mis? Geef een foutresultaat terug; registratieFout() vertaalt
    //    de foutcode van Supabase naar veldfouten of een melding.
    //  - Krijg je direct een sessie terug ("Confirm email" staat uit)? Dan ben
    //    je ingelogd: stuur de arts door naar /mijn-afspraken.
    //  - Anders moet de arts eerst op de link in de mail klikken: geef dan
    //    {status: "bevestig-email", email: invoer.email} terug.
    //    Let op: bestaat het e-mailadres al, dan geeft Supabase hier bewust géén
    //    fout (zodat niemand kan uitzoeken welke adressen een account hebben).


    // return {
    //     status: "error",
    //     veldFouten: {},
    //     melding: "Registreren is nog niet gebouwd (stap 2).",
    //     invoer,
    // };


    const supabase = await createSupabaseServerClient();
    const { data, error } = await supabase.auth.signUp({
        email: invoer.email,
        password: wachtwoord,
        options: {
            data: {
                naam: invoer.naam,
                type: invoer.type
            },
            emailRedirectTo: `${await siteUrl()}/auth/callback?next=/mijn-afspraken`
        }
    });
    if (error) {
        const fout = registratieFout(error.code);
        return {
            status: "error",
            ...fout,
            invoer
        };
    }
    if (data.session) {
        redirect("/mijn-afspraken");
    }
    return {
        status: "bevestig-email",
        email: invoer.email
    };
}

function registratieFout(code: string | undefined): {
    veldFouten: Partial<Record<Veld, string>>;
    melding?: string;
} {
    switch (code) {
        case "user_already_exists":
        case "email_exists":
            return {veldFouten: {email: "Er bestaat al een account met dit e-mailadres."}};
        case "weak_password":
            return {veldFouten: {wachtwoord: "Dit wachtwoord is te zwak. Kies een langer of minder voorspelbaar wachtwoord."}};
        case "email_address_invalid":
            return {veldFouten: {email: "Dit e-mailadres wordt niet geaccepteerd."}};
        case "over_email_send_rate_limit":
        case "over_request_rate_limit":
            return {veldFouten: {}, melding: "Te veel pogingen. Wacht even en probeer het opnieuw."};
        default:
            return {veldFouten: {}, melding: "Registreren is niet gelukt. Probeer het later opnieuw."};
    }
}

/** De url van deze site, bijv. "http://localhost:3000", afgeleid van het request. */
async function siteUrl(): Promise<string> {
    const requestHeaders = await headers();
    const origin = requestHeaders.get("origin");
    if (origin) {
        return origin;
    }
    const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host");
    const protocol = requestHeaders.get("x-forwarded-proto") ?? "http";
    return `${protocol}://${host}`;
}

function valideer(velden: {
    naam: string;
    type: string;
    email: string;
    wachtwoord: string;
    wachtwoordHerhaling: string;
}): Partial<Record<Veld, string>> | null {
    const fouten: Partial<Record<Veld, string>> = {};

    if (velden.naam.length === 0) {
        fouten.naam = "Vul je naam in.";
    } else if (velden.naam.length > NAAM_MAX_LENGTE) {
        fouten.naam = `Je naam mag maximaal ${NAAM_MAX_LENGTE} tekens zijn.`;
    }

    if (!isArtsType(velden.type)) {
        fouten.type = "Kies je functie.";
    }

    if (!isGeldigEmail(velden.email)) {
        fouten.email = "Vul een geldig e-mailadres in.";
    }

    if (velden.wachtwoord.length < WACHTWOORD_MIN_LENGTE) {
        fouten.wachtwoord = `Je wachtwoord moet minimaal ${WACHTWOORD_MIN_LENGTE} tekens zijn.`;
    } else if (velden.wachtwoord.length > WACHTWOORD_MAX_LENGTE) {
        fouten.wachtwoord = `Je wachtwoord mag maximaal ${WACHTWOORD_MAX_LENGTE} tekens zijn.`;
    } else if (velden.wachtwoordHerhaling !== velden.wachtwoord) {
        fouten.wachtwoordHerhaling = "De wachtwoorden komen niet overeen.";
    }

    return Object.keys(fouten).length > 0 ? fouten : null;
}
