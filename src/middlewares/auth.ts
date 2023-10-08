import type { RoleRights } from '@src/config/roles';

import passport from 'passport';
import httpStatus from 'http-status';
import { NextFunction, Request, Response } from 'express';
import { User } from '@prisma/client';

import ApiError from '@src/utils/ApiError';
import { userService } from '@src/services';
import config from '@src/config/config';
import { roleRights } from '@src/config/roles';
import { authService } from '@src/services';
import { setRefreshToken, setAccessToken } from '@src/utils/cookies';

const verifyCallback =
  (
    req: Request,
    res: Response,
    resolve: (value?: unknown) => void,
    reject: (reason?: unknown) => void,
    requiredRights: RoleRights[]
  ) =>
  async (err: unknown, userFromAccessToken: User | false, info: unknown) => {
    let user = userFromAccessToken;

    if (err || info || !user) {
      const existingRefreshToken = req.cookies[config.jwt.refreshTokenName];

      if (!existingRefreshToken)
        return reject(new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate'));

      try {
        const newTokens = await authService.refreshAuth(existingRefreshToken);
        user = (await userService.getUserByToken(newTokens.access.token)) as User;

        setRefreshToken(res, newTokens.refresh);
        setAccessToken(res, newTokens.access);
      } catch {
        return reject(new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate'));
      }
    }

    req.user = user;

    if (requiredRights.length) {
      const userRights = roleRights.get(user.role) ?? [];
      const hasRequiredRights = requiredRights.every((requiredRight) =>
        userRights.includes(requiredRight)
      );
      if (!hasRequiredRights && Number(req.params.userId) !== user.id) {
        return reject(new ApiError(httpStatus.FORBIDDEN, 'Forbidden'));
      }
    }

    resolve();
  };

const auth =
  (...requiredRights: RoleRights[]) =>
  async (req: Request, res: Response, next: NextFunction) => {
    return new Promise((resolve, reject) => {
      passport.authenticate(
        'jwt',
        { session: false },
        verifyCallback(req, res, resolve, reject, requiredRights)
      )(req, res, next);
    })
      .then(() => next())
      .catch((err) => next(err));
  };

export default auth;
