import { Strategy as JwtStrategy, ExtractJwt, VerifyCallback } from 'passport-jwt';
import { Request } from 'express-serve-static-core';
import { TokenType } from '@prisma/client';

import prisma from '@src/client';

import config from './config';

const cookieExtractor = function (req: Request) {
  const accessToken = req.cookies[config.jwt.accessTokenName];

  if (!accessToken) {
    return null;
  }

  return accessToken;
};

const jwtOptions = {
  secretOrKey: config.jwt.secret,
  jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor])
};

const jwtVerify: VerifyCallback = async (payload, done) => {
  try {
    if (payload.type !== TokenType.ACCESS) {
      throw new Error('Invalid token type');
    }
    const user = await prisma.user.findUnique({
      select: {
        id: true,
        email: true,
        name: true
      },
      where: { id: payload.sub }
    });
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    done(error, false);
  }
};

export const jwtStrategy = new JwtStrategy(jwtOptions, jwtVerify);
