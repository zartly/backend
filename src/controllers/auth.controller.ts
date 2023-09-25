import httpStatus from 'http-status';
import { User } from '@prisma/client';

import { authService, userService, tokenService, emailService } from '@src/services';
import exclude from '@src/utils/exclude';
import catchAsync from '@src/utils/catchAsync';
import config from '@src/config/config';

const register = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await userService.createUser(email, password);
  const userWithoutPassword = exclude(user, ['password', 'createdAt', 'updatedAt']);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user: userWithoutPassword, tokens });
});

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ user, tokens });
});

const session = catchAsync(async (req, res) => {
  const existingRefreshToken = req.cookies[config.jwt.refreshTokenName];

  if (existingRefreshToken) {
    res.clearCookie(config.jwt.refreshTokenName);
    const newTokens = await authService.refreshAuth(existingRefreshToken);
    const user = await authService.loginUserWithToken(newTokens.refresh.token);

    res.cookie(config.jwt.refreshTokenName, newTokens.refresh.token, {
      httpOnly: true,
      expires: newTokens.refresh.expires
    });
    res.cookie(config.jwt.accessTokenName, newTokens.access.token, {
      httpOnly: true,
      expires: newTokens.access.expires
    });
    return res.send({ user });
  }

  res.status(httpStatus.OK).send({ user: null });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token as string, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const user = req.user as User;
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(user);
  await emailService.sendVerificationEmail(user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token as string);
  res.status(httpStatus.NO_CONTENT).send();
});

export default {
  register,
  login,
  session,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail
};
