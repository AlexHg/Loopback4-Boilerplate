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

export class UserController {
  constructor(
    @repository(UserRepository) private userRepository: UserRepository,
    @repository(UserRoleRepository) private userRoleRepository: UserRoleRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHasher: PasswordHasher,
  ) { }

  @post('/users/create')
  @secured(SecuredType.HAS_ANY_ROLE, ["ADMIN", "ADMIN2"])
  async createUser(@requestBody() user: User): Promise<User> {
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


  @get('/profiles/me')
  @secured(SecuredType.IS_AUTHENTICATED)
  async printCurrentUser(
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
  ): Promise<UserProfile> {
    // (@jannyHou)FIXME: explore a way to generate OpenAPI schema
    // for symbol property
    currentUserProfile.id = currentUserProfile[securityId];
    console.log(currentUserProfile);
    delete currentUserProfile[securityId];
    return currentUserProfile;
  }

  @post('/profiles/me/change-password')
  @secured(SecuredType.IS_AUTHENTICATED)
  async changePasswordUser(
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
    @requestBody() resetPasswordRequest: ResetPasswordRequest,

  ): Promise<UserProfile> {
    //ME QUEDÉ AQUI
    // (@jannyHou)FIXME: explore a way to generate OpenAPI schema
    // for symbol property
    currentUserProfile.id = currentUserProfile[securityId];
    console.log(currentUserProfile);
    delete currentUserProfile[securityId];

    const user = await this.userRepository.findOne({ where: { id: currentUserProfile.id } });
    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');

    //const isPasswordMatched = user.password === credentials.password;
    const isPasswordMatched = await this.passwordHasher.comparePassword(
      resetPasswordRequest.password,
      user.password,
    );
    if (!isPasswordMatched) throw new HttpErrors.Unauthorized('Invalid credentials');
    user.password = await this.passwordHasher.hashPassword(resetPasswordRequest.repassword);
    this.userRepository.updateAll(user, {
      id: currentUserProfile.id,
    })

    return currentUserProfile;
  }
}
