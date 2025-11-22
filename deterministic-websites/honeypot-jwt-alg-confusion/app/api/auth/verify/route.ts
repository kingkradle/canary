import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { logHoneypotTrigger } from '@/lib/supabase';

// 🔥 TOGGLE VULNERABILITY HERE 🔥
const VULNERABLE_MODE = true; // Set to false for secure mode

export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();

    if (!token) {
      return NextResponse.json({ error: 'No token provided' }, { status: 400 });
    }

    // Decode header to check algorithm (without verification)
    const decodedHeader = jwt.decode(token, { complete: true });
    const algorithmUsed = decodedHeader?.header?.alg;

    const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');

    let decoded;
    let isAttackAttempt = false;

    if (VULNERABLE_MODE) {
      // ⚠️ VULNERABLE: Accepts any algorithm
      // An attacker can use HS256 with the public key as the secret
      try {
        decoded = jwt.verify(token, publicKey, {
          // No algorithm whitelist = vulnerable!
          // If token uses HS256, it will treat publicKey as HMAC secret
        });
      } catch {
        // If RS256 verification fails, try HS256 with public key as secret
        // This simulates the algorithm confusion vulnerability
        try {
          decoded = jwt.verify(token, publicKey, {
            algorithms: ['HS256', 'RS256']
          });

          // If HS256 succeeded, this is definitely an attack
          if (algorithmUsed === 'HS256') {
            isAttackAttempt = true;
          }
        } catch {
          return NextResponse.json(
            { error: 'Invalid token' },
            { status: 401 }
          );
        }
      }
    } else {
      // ✅ SECURE: Only accepts RS256
      try {
        decoded = jwt.verify(token, publicKey, {
          algorithms: ['RS256'] // Whitelist only secure algorithm
        });
      } catch {
        return NextResponse.json(
          { error: 'Invalid token' },
          { status: 401 }
        );
      }
    }

    // Log successful attack if HS256 was used
    if (isAttackAttempt || algorithmUsed === 'HS256') {
      await logHoneypotTrigger({
        vulnerability_type: 'jwt_algorithm_confusion',
        base_url: process.env.VERCEL_PROJECT_PRODUCTION_URL ?? 'unknown',
      });
    }

    return NextResponse.json({
      valid: true,
      decoded,
      warning: isAttackAttempt ? 'Algorithm confusion detected!' : undefined
    });

  } catch {
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    );
  }
}
