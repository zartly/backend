import { Role } from '@prisma/client';

export type RoleRights = 'getUsers' | 'manageUsers';
export type AllRoles = {
  [Role.USER]: [];
  [Role.ADMIN]: RoleRights[];
};

const allRoles = {
  [Role.USER]: [],
  [Role.ADMIN]: ['getUsers', 'manageUsers']
} satisfies AllRoles;

export const roles = Object.keys(allRoles) as (keyof typeof allRoles)[];
export const roleRights = new Map(Object.entries(allRoles));
