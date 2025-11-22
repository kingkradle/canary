import { createClient } from '@supabase/supabase-js';

// Server-side only - no NEXT_PUBLIC prefix
// Use service role key for server-side operations that bypass RLS
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Database types for vulnerability logging
export interface VulnerabilityLog {
  id?: string;
  base_url: string;
  path?: string;
  vulnerability_type: string;
  timestamp?: string;
  attack_id?: string;
}

/**
 * Log honeypot trigger to Supabase database
 */
export async function logHoneypotTrigger(result: VulnerabilityLog) {
  try {
    const { error } = await supabase
      .from('vulnerability_logs')
      .insert(result);

    if (error) {
      console.error('Failed to log to Supabase:', error);
    }
  } catch (err) {
    console.error('Error logging honeypot trigger:', err);
  }
}
