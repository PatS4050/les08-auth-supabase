/* eslint-disable @typescript-eslint/no-unused-vars -- startpunt: deze imports en helpers gebruik je in stap 2. Haal deze regel weg als je klaar bent. */
"use server";

import {redirect} from "next/navigation";
import {createSupabaseServerClient} from "@/lib/supabase/server";
import {leesTekst} from "@/lib/validatie";
import {error} from "next/dist/build/output/log";

export type LoginResultaat =
    | { status: "idle" }
    | { status: "error"; melding: string; email: string };

export async function login(_vorigResultaat: LoginResultaat, formData: FormData): Promise<LoginResultaat> {
    const email = leesTekst(formData, "email").trim().toLowerCase();
    const password = leesTekst(formData, "password");

    if (!email || !password) {
            return {
                status: "error",
                melding: loginFoutmelding(error.code),
                email
            };
        }
    // Maak Supabase-serverclient
    const supabase = await createSupabaseServerClient();
    // Log gebruiker in met e-mailadres en wachtwoord
    const { error } = await supabase.auth.signInWithPassword({
        email,
        password
    });
    // Controleer of het inloggen is gelukt
    if (error) {
        if (error) {
            return {
                status: "error",
                melding: loginFoutmelding(error.code),
                email
            };
        }
        // Inloggen gelukt: stuur door naar de afspraken
        redirect("/mijn-afspraken");
    }

    // TODO stap 2: log de gebruiker in bij Supabase.
    //  - Maak een client met createSupabaseServerClient(). Die zet na het inloggen
    //    automatisch de sessie-cookies.
    //  - Gebruik de juiste functie van supabase.auth om in te loggen met e-mail en wachtwoord.
    //  - Gaat het mis? Geef dan een foutresultaat terug. loginFoutmelding()
    //    hieronder vertaalt de foutcode van Supabase naar een nette Nederlandse melding.
    //  - Gaat het goed? Stuur de gebruiker dan door naar /mijn-afspraken.
    return {status: "error", melding: "Inloggen is niet gelukt.", email};
}

export async function uitloggen(): Promise<void> {
    // TODO stap 2: log de gebruiker uit bij Supabase. Daarmee worden ook de sessie-cookies verwijderd.
    const supabase = await createSupabaseServerClient();
    await supabase.auth.signOut();
    redirect("/inloggen");
}

function loginFoutmelding(code: string | undefined): string {
    switch (code) {
        case "invalid_credentials":
            // Bewust niet zeggen wát er fout is: anders kun je uitzoeken welke
            // e-mailadressen een account hebben.
            return "E-mailadres of wachtwoord klopt niet.";
        case "email_not_confirmed":
            return "Bevestig eerst je e-mailadres via de link in de e-mail die je hebt ontvangen.";
        case "over_request_rate_limit":
            return "Te veel pogingen. Wacht even en probeer het opnieuw.";
        default:
            return "Inloggen is niet gelukt. Probeer het later opnieuw.";
    }
}
