export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import fs from 'fs';

export async function GET() {
  try {
    const filePath = 'C:/Users/riyam/Documents/PacketSentry/live_data.json';
    const data = fs.readFileSync(filePath, 'utf8');
    return NextResponse.json(JSON.parse(data));
  } catch (err) {
    return NextResponse.json({ error: 'Awaiting C++ Engine...' }, { status: 503 });
  }
}