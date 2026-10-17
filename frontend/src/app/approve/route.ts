import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const reviewerToken = process.env.REVIEWER_TOKEN?.trim();
  if (
    !reviewerToken ||
    reviewerToken.length < 32 ||
    /^(replace_with|change_me|your_)/i.test(reviewerToken)
  ) {
    return NextResponse.json(
      { detail: "Reviewer authentication is not configured on the frontend server. Set REVIEWER_TOKEN in frontend/.env.local." },
      { status: 503 },
    );
  }

  const backendUrl = (
    process.env.AGENTGUARD_API_URL || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"
  ).replace(/\/+$/, "");

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Request body must be valid JSON." }, { status: 400 });
  }

  try {
    const response = await fetch(`${backendUrl}/api/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Reviewer-Token": reviewerToken,
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });

    const responseBody = await response.json().catch(() => ({ detail: "Backend returned a non-JSON response." }));
    return NextResponse.json(responseBody, { status: response.status });
  } catch {
    return NextResponse.json(
      { detail: `Could not reach the AgentGuard backend at ${backendUrl}.` },
      { status: 502 },
    );
  }
}
