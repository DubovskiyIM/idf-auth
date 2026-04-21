import { Resend } from 'resend';
import type { Env } from '../env.js';
import { logger } from '../logger.js';

export type EmailSender = {
  sendMagicLink(to: string, link: string): Promise<void>;
  sendInvite(to: string, link: string, inviterEmail: string, domainSlug: string): Promise<void>;
};

export function createEmailSender(env: Env): EmailSender {
  if (env.EMAIL_DEV_MODE) {
    return {
      async sendMagicLink(to, link) {
        logger.info({ to, link }, '[dev-mail] magic-link');
      },
      async sendInvite(to, link, inviter, slug) {
        logger.info({ to, link, inviter, slug }, '[dev-mail] invite');
      },
    };
  }

  const resend = new Resend(env.RESEND_API_KEY);

  return {
    async sendMagicLink(to, link) {
      await resend.emails.send({
        from: 'IDF <no-reply@idf.dev>',
        to,
        subject: 'Ваша ссылка для входа',
        html: `<p>Нажмите чтобы войти: <a href="${link}">${link}</a></p><p>Ссылка действует 15 минут.</p>`,
      });
    },
    async sendInvite(to, link, inviter, slug) {
      await resend.emails.send({
        from: 'IDF <no-reply@idf.dev>',
        to,
        subject: `${inviter} приглашает вас в ${slug}`,
        html: `<p>${inviter} приглашает в приложение <b>${slug}</b>.</p><p><a href="${link}">Принять приглашение</a></p>`,
      });
    },
  };
}

export type EmailOutbox = Array<{ kind: 'magic' | 'invite'; to: string; link: string; meta?: any }>;

export function createOutboxSender(outbox: EmailOutbox): EmailSender {
  return {
    async sendMagicLink(to, link) {
      outbox.push({ kind: 'magic', to, link });
    },
    async sendInvite(to, link, inviter, slug) {
      outbox.push({ kind: 'invite', to, link, meta: { inviter, slug } });
    },
  };
}
