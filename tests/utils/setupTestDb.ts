import { beforeAll, beforeEach, afterAll } from '@jest/globals';

import prisma from '~/client';

const setupTestDB = () => {
  beforeAll(async () => {
    await prisma.$connect();
  });

  beforeEach(async () => {
    await prisma.token.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.token.deleteMany();
    await prisma.user.deleteMany();
    await prisma.$disconnect();
  });
};

export default setupTestDB;
