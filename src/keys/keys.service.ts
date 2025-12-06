import { Injectable } from '@nestjs/common';

import * as crypto from 'crypto';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class KeysService {
  constructor(private prisma: PrismaService) {}

  async create(userId: string, name: string, days = 90) {
    const id = crypto.randomUUID();
    const random = crypto.randomBytes(32).toString('hex');
    const signature = crypto
      .createHmac('sha256', process.env.API_KEY_SECRET!)
      .update(`${id}:${random}`)
      .digest('hex');

    const fullKey = `sk_${id}_${random}_${signature}`;

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);

    const saved = await this.prisma.apiKey.create({
      data: {
        key: fullKey,
        name,
        expiresAt,
        userId,
      },
    });

    return {
      message: 'SAVE THIS KEY — shown only once!',
      apiKey: fullKey,
      details: {
        id: saved.id,
        name: saved.name,
        expiresAt: saved.expiresAt,
        preview: fullKey.slice(0, 12) + '...' + fullKey.slice(-8),
      },
    };
  }

  async validate(key: string) {
    if (!key.startsWith('sk_')) return null;

    const apiKey = await this.prisma.apiKey.findUnique({
      where: { key, isActive: true },
      include: { user: true },
    });

    if (!apiKey) return null;
    if (apiKey.expiresAt && new Date() > apiKey.expiresAt) {
      await this.prisma.apiKey.update({
        where: { id: apiKey.id },
        data: { isActive: false },
      });
      return null;
    }

    return { user: apiKey.user, apiKey: apiKey };
  }

  async revoke(userId: string, id: string) {
    await this.prisma.apiKey.updateMany({
      where: { id, userId },
      data: { isActive: false },
    });
  }
}
