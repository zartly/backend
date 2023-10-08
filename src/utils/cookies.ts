import { Response } from 'express';
import { TokenResponse } from '@src/types/response';

import config from '@src/config/config';

export const setRefreshToken = (res: Response, { token, expires }: TokenResponse) => {
  res.cookie(config.jwt.refreshTokenName, token, {
    httpOnly: true,
    expires: expires
  });
};

export const setAccessToken = (res: Response, { token, expires }: TokenResponse) => {
  res.cookie(config.jwt.accessTokenName, token, {
    httpOnly: true,
    expires: expires
  });
};
