import { base } from "$app/paths";
import { redirect } from "@sveltejs/kit";

export async function load() {
	// Model settings removed - redirect to application settings
	redirect(302, `${base}/settings/application`);
}
