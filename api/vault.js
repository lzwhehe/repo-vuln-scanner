import { clearVault, getVault } from "../server/vault.js";

export async function GET() {
  try {
    return Response.json(await getVault());
  } catch (error) {
    console.error(error);
    return Response.json(
      { error: error instanceof Error ? error.message : "Failed to load vault." },
      { status: 500 }
    );
  }
}

export async function DELETE() {
  try {
    return Response.json(await clearVault());
  } catch (error) {
    console.error(error);
    return Response.json(
      { error: error instanceof Error ? error.message : "Failed to clear vault." },
      { status: 500 }
    );
  }
}
