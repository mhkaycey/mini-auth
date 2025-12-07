// src/test/example.test.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

import * as bcrypt from 'bcrypt';
import { PrismaService } from 'prisma/prisma.service';

describe('Example Controller (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let jwtToken: string;
  let apiKey: string;
  let testUserId: string;
  let testApiKeyId: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    prisma = moduleFixture.get<PrismaService>(PrismaService);

    await app.init();

    // Create a test user
    const hashedPassword = await bcrypt.hash('password123', 10);
    const user = await prisma.user.create({
      data: {
        email: 'test@example.com',
        password: hashedPassword,
        name: 'Test User',
      },
    });

    testUserId = user.id;

    // Get JWT token
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'password123',
      });

    jwtToken = loginResponse.body.accessToken;

    // Create an API key
    const apiKeyEntity = await prisma.apiKey.create({
      data: {
        key: 'test-api-key-12345',
        name: 'Test API Key',
        expiresAt: new Date(),
        userId: user.id,
      },
    });

    testApiKeyId = apiKeyEntity.id;
    apiKey = apiKeyEntity.key;
  });

  afterAll(async () => {
    // Clean up test data
    await prisma.apiKey.delete({
      where: { id: testApiKeyId },
    });

    await prisma.user.delete({
      where: { id: testUserId },
    });

    await prisma.$disconnect();
    await app.close();
  });

  describe('/example/public (GET)', () => {
    it('should return a public message without authentication', () => {
      return request(app.getHttpServer())
        .get('/example/public')
        .expect(200)
        .expect((res) => {
          expect(res.body).toEqual({ message: 'Anyone can access this' });
        });
    });
  });

  describe('/example/user-only (GET)', () => {
    it('should return a user message with JWT authentication', () => {
      return request(app.getHttpServer())
        .get('/example/user-only')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.message).toBe('Hello user!');
          expect(res.body.email).toBe('test@example.com');
        });
    });

    it('should return 401 without authentication', () => {
      return request(app.getHttpServer()).get('/example/user-only').expect(401);
    });

    it('should return 401 with API key authentication', () => {
      return request(app.getHttpServer())
        .get('/example/user-only')
        .set('X-API-KEY', apiKey)
        .expect(401);
    });
  });

  describe('/example/service-only (GET)', () => {
    it('should return a service message with API key authentication', () => {
      return request(app.getHttpServer())
        .get('/example/service-only')
        .set('X-API-KEY', apiKey)
        .expect(200)
        .expect((res) => {
          expect(res.body.message).toContain('Hello');
          expect(res.body.token_type).toBe('api-key');
          expect(res.body.keyId).toBeDefined();
        });
    });

    it('should return 401 without authentication', () => {
      return request(app.getHttpServer())
        .get('/example/service-only')
        .expect(401);
    });

    it('should return 401 with JWT authentication', () => {
      return request(app.getHttpServer())
        .get('/example/service-only')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(401);
    });
  });

  describe('/example/both (GET)', () => {
    it('should return a message with JWT authentication', () => {
      return request(app.getHttpServer())
        .get('/example/both')
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.message).toBe('You are authenticated!');
          expect(res.body.type).toBe('jwt');
          expect(res.body.email).toBe('test@example.com');
        });
    });

    it('should return a message with API key authentication', () => {
      return request(app.getHttpServer())
        .get('/example/both')
        .set('X-API-KEY', apiKey)
        .expect(200)
        .expect((res) => {
          expect(res.body.message).toBe('You are authenticated!');
          expect(res.body.type).toBe('api-key');
          expect(res.body.email).toBe('test@example.com');
        });
    });

    it('should return 401 without authentication', () => {
      return request(app.getHttpServer()).get('/example/both').expect(401);
    });
  });
});
