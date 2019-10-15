import { get, post, requestBody, HttpErrors } from '@loopback/rest';
import { User } from '../models';
import { UserRepository, UserRoleRepository } from '../repositories';
import { repository } from '@loopback/repository';
import { Credentials, JWT_SECRET, secured, SecuredType, ResetPasswordRequest } from '../auth';
import { promisify } from 'util';
import { inject } from '@loopback/core';
import { SecurityBindings, UserProfile, securityId } from '@loopback/security';
import { PasswordHasher } from '../services/hash.password.bcryptjs';
import { PasswordHasherBindings } from '../keys';

const { sign } = require('jsonwebtoken');
const signAsync = promisify(sign);

export class AuthController {
  constructor(
    @repository(UserRepository) private userRepository: UserRepository,
    @repository(UserRoleRepository) private userRoleRepository: UserRoleRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHasher: PasswordHasher,
  ) { }

  @post('/auth/register')
  @secured(SecuredType.PERMIT_ALL)
  async register(@requestBody() user: User): Promise<User> {
    const foundUser = await this.userRepository.findOne({
      where: { email: user.email }
    });

    // if not exists
    if (!foundUser) {
      user.password = await this.passwordHasher.hashPassword(user.password);
      return await this.userRepository.create(user);
    }
    //if it exists, throw error
    throw new HttpErrors.Conflict("Email value is already taken (ScopedCode:1)");
  }

  @post('/auth/login')
  @secured(SecuredType.PERMIT_ALL)
  async login(@requestBody() credentials: Credentials) {
    if (!credentials.username || !credentials.password) throw new HttpErrors.BadRequest('Missing Username or Password');
    const user = await this.userRepository.findOne({ where: { id: credentials.username } });
    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');

    console.log(user);
    //const isPasswordMatched = user.password === credentials.password;
    const isPasswordMatched = await this.passwordHasher.comparePassword(
      credentials.password,
      user.password,
    );
    if (!isPasswordMatched) throw new HttpErrors.Unauthorized('Invalid credentials');

    const tokenObject = { username: credentials.username };
    const token = await signAsync(tokenObject, JWT_SECRET);
    const roles = await this.userRoleRepository.find({ where: { userId: user.id } });
    const { id, email } = user;

    return {
      token,
      id: id as string,
      email,
      roles: roles.map(r => r.roleId),
    };
  }


}
