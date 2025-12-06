import { Injectable } from '@nestjs/common';

import * as crypto from 'crypto';
import { PrismaService } from 'prisma/prisma.service';

/**
 * Service responsible for managing API keys for service-to-service authentication.
 * Provides functionality to create, validate, and revoke API keys with secure generation.
 */
@Injectable()
export class KeysService {
  constructor(private prisma: PrismaService) {}

  /**
   * Creates a new API key for a user
   * @param userId - ID of the user creating the API key
   * @param name - Descriptive name for the API key
   * @param days - Number of days until the key expires (default: 90)
   * @returns Created API key information with a warning that it's shown only once
   */
  async create(userId: string, name: string, days = 90) {
    // Generate a UUID for the key identifier
    const id = crypto.randomUUID();
    // Generate 32 bytes of cryptographically secure random data
    const random = crypto.randomBytes(32).toString('hex');
    // Create HMAC-SHA256 signature to verify key authenticity
    const signature = crypto
      .createHmac('sha256', process.env.API_KEY_SECRET!)
      .update(`${id}:${random}`)
      .digest('hex');

    // Combine parts into the final API key format
    const fullKey = `sk_${id}_${random}_${signature}`;

    // Calculate expiration date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);

    // Save the API key to the database
    const saved = await this.prisma.apiKey.create({
      data: {
        key: fullKey,
        name,
        expiresAt,
        userId,
      },
    });

    // Return the key with a warning that it won't be shown again
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

  /**
   * Validates an API key and returns the associated user
   * @param key - API key to validate
   * @returns User and API key information if valid, null otherwise
   */
  async validate(key: string) {
    // Quick format check - all keys should start with 'sk_'
    if (!key.startsWith('sk_')) return null;

    // Look up the key in the database, ensuring it's active
    const apiKey = await this.prisma.apiKey.findUnique({
      where: { key, isActive: true },
      include: { user: true },
    });

    // Return null if key doesn't exist
    if (!apiKey) return null;

    // Check if the key has expired
    if (apiKey.expiresAt && new Date() > apiKey.expiresAt) {
      // Deactivate expired keys to prevent future use
      await this.prisma.apiKey.update({
        where: { id: apiKey.id },
        data: { isActive: false },
      });
      return null;
    }

    // Return the user and API key information for successful validation
    return { user: apiKey.user, apiKey: apiKey };
  }

  /**
   * Revokes (deactivates) an API key
   * @param userId - ID of the user revoking the key
   * @param id - ID of the API key to revoke
   */
  async revoke(userId: string, id: string) {
    // Deactivate the API key instead of deleting it for audit purposes
    await this.prisma.apiKey.updateMany({
      where: { id, userId },
      data: { isActive: false },
    });
  }
}
