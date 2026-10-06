import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { supabase } from '../services/supabase';

const router = Router();

const KIWIFY_SECRET = process.env.KIWIFY_WEBHOOK_SECRET ?? '';

/**
 * Valida a assinatura HMAC-SHA1 que a Kiwify envia no query param `signature`.
 * A assinatura é o HMAC-SHA1 do corpo bruto (raw body) usando o token secreto.
 * Se nenhum secret estiver configurado, a validação é pulada (modo dev/teste).
 */
function isValidSignature(rawBody: string, signature?: string): boolean {
  if (!KIWIFY_SECRET) return true; // sem secret configurado → aceita (apenas para testes)
  if (!signature) return false;

  const expected = crypto
    .createHmac('sha1', KIWIFY_SECRET)
    .update(rawBody)
    .digest('hex');

  // Comparação em tempo constante para evitar timing attacks
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// POST /api/webhooks/kiwify
// Recebe a notificação de venda da Kiwify e cadastra o aluno automaticamente.
router.post('/kiwify', async (req: Request, res: Response) => {
  const rawBody = (req as any).rawBody ?? JSON.stringify(req.body);
  const signature = req.query.signature as string | undefined;

  if (!isValidSignature(rawBody, signature)) {
    console.warn('[Webhook Kiwify] Assinatura inválida — requisição rejeitada.');
    return res.status(401).json({ error: 'Assinatura inválida.' });
  }

  const body = req.body ?? {};

  console.log('[Webhook Kiwify] Payload recebido:', JSON.stringify(body, null, 2));

  const orderStatus: string | undefined = body.order_status;
  const customer = body.Customer ?? body.customer ?? {};

  const email: string | undefined = customer.email?.trim?.()?.toLowerCase();
  const name: string = customer.full_name ?? customer.name ?? '';

  if (!email || !email.includes('@')) {
    console.warn('[Webhook Kiwify] Payload sem email válido.', { orderStatus });
    return res.status(400).json({ error: 'Email não encontrado no payload.' });
  }

  // Venda aprovada → cadastra/ativa o aluno
  if (orderStatus === 'paid') {
    const { error } = await supabase.from('students').upsert(
      { email, name, role: 'student', active: true },
      { onConflict: 'email', ignoreDuplicates: false }
    );

    if (error) {
      console.error('[Webhook Kiwify] Erro ao cadastrar aluno:', error);
      return res.status(500).json({ error: 'Erro ao cadastrar aluno.' });
    }

    console.log(`[Webhook Kiwify] Aluno cadastrado/ativado: ${email}`);
    return res.status(200).json({ message: 'Aluno cadastrado com sucesso.' });
  }

  // Reembolso ou chargeback → desativa o acesso (mantém o registro)
  if (orderStatus === 'refunded' || orderStatus === 'chargedback') {
    const { error } = await supabase
      .from('students')
      .update({ active: false })
      .eq('email', email);

    if (error) {
      console.error('[Webhook Kiwify] Erro ao desativar aluno:', error);
      return res.status(500).json({ error: 'Erro ao desativar aluno.' });
    }

    console.log(`[Webhook Kiwify] Acesso desativado (${orderStatus}): ${email}`);
    return res.status(200).json({ message: 'Acesso desativado.' });
  }

  // Outros status (waiting_payment, refused, etc.) → ignora
  console.log(`[Webhook Kiwify] Evento ignorado (status: ${orderStatus}): ${email}`);
  return res.status(200).json({ message: 'Evento ignorado.' });
});

const HOTMART_HOTTOK = process.env.HOTMART_HOTTOK ?? '';

/**
 * Valida o token (hottok) que a Hotmart envia no header `X-HOTMART-HOTTOK`.
 * Diferente da Kiwify, não é HMAC: é um token fixo gerado no painel da Hotmart.
 * Sem token configurado, a requisição é recusada (evita cadastro por terceiros).
 */
function isValidHottok(received?: string): boolean {
  if (!HOTMART_HOTTOK || !received) return false;
  const a = Buffer.from(received);
  const b = Buffer.from(HOTMART_HOTTOK);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// POST /api/webhooks/hotmart
// Recebe a notificação (Webhook v2.0.0) da Hotmart e cadastra/desativa o aluno.
router.post('/hotmart', async (req: Request, res: Response) => {
  if (!isValidHottok(req.header('x-hotmart-hottok'))) {
    console.warn('[Webhook Hotmart] Hottok inválido ou ausente — requisição rejeitada.');
    return res.status(401).json({ error: 'Token inválido.' });
  }

  const body = req.body ?? {};
  const event: string | undefined = body.event;
  const buyer = body.data?.buyer ?? {};
  const transaction: string | undefined = body.data?.purchase?.transaction;

  console.log('[Webhook Hotmart] Evento recebido:', event, transaction ?? '');

  const email: string | undefined = buyer.email?.trim?.()?.toLowerCase();
  const name: string = buyer.name ?? '';

  if (!email || !email.includes('@')) {
    console.warn('[Webhook Hotmart] Payload sem email válido.', { event });
    return res.status(400).json({ error: 'Email não encontrado no payload.' });
  }

  // Compra aprovada → cadastra/ativa o aluno (sem rebaixar quem já é admin)
  if (event === 'PURCHASE_APPROVED' || event === 'PURCHASE_COMPLETE') {
    const { data: existing, error: findError } = await supabase
      .from('students')
      .select('email')
      .eq('email', email)
      .maybeSingle();

    if (findError) {
      console.error('[Webhook Hotmart] Erro ao consultar aluno:', findError);
      return res.status(500).json({ error: 'Erro ao cadastrar aluno.' });
    }

    const { error } = existing
      ? await supabase.from('students').update({ active: true }).eq('email', email)
      : await supabase.from('students').insert({ email, name, role: 'student', active: true });

    if (error) {
      console.error('[Webhook Hotmart] Erro ao cadastrar aluno:', error);
      return res.status(500).json({ error: 'Erro ao cadastrar aluno.' });
    }

    console.log(`[Webhook Hotmart] Aluno cadastrado/ativado: ${email}`);
    return res.status(200).json({ message: 'Aluno cadastrado com sucesso.' });
  }

  // Reembolso, chargeback, cancelamento → desativa o acesso (mantém o registro)
  if (
    event === 'PURCHASE_REFUNDED' ||
    event === 'PURCHASE_CHARGEBACK' ||
    event === 'PURCHASE_CANCELED'
  ) {
    const { error } = await supabase
      .from('students')
      .update({ active: false })
      .eq('email', email)
      .eq('role', 'student');

    if (error) {
      console.error('[Webhook Hotmart] Erro ao desativar aluno:', error);
      return res.status(500).json({ error: 'Erro ao desativar aluno.' });
    }

    console.log(`[Webhook Hotmart] Acesso desativado (${event}): ${email}`);
    return res.status(200).json({ message: 'Acesso desativado.' });
  }

  console.log(`[Webhook Hotmart] Evento ignorado (${event}): ${email}`);
  return res.status(200).json({ message: 'Evento ignorado.' });
});

export default router;
