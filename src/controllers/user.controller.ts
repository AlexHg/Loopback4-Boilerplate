import { get, post, requestBody, HttpErrors, getModelSchemaRef } from '@loopback/rest';
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

  @post('/users/create', {
    responses: {
      '200': { description: 'Retorna el usuario y email' },
      '400': { description: 'Faltan datos en la petición' },
      '409': { description: 'Error de conflicto: El Email ya existe' }
    }
  })
  @secured(SecuredType.HAS_ANY_ROLE, ["ADMIN", "ADMIN2"])
  async createUser(@requestBody({
    description: "<h3>Registro privado de usuarios.</h3><p>Usuarios con alguno de los roles ['ADMIN','ADMIN2'] podrán crear usuarios con status=true saltandose la confirmación de correo electrónico.</p>",
    content: {
      'application/json': {
        schema: getModelSchemaRef(User, {
          title: 'NewUser',
          exclude: ['status', 'regtoken'],
        }),
      },
    },
  }) user: User): Promise<User> {
    if (!user.email || !user.password || !user.id) throw new HttpErrors.BadRequest('Missing Username, Password or Email');
    const foundUser = await this.userRepository.findOne({
      where: { email: user.email }
    });

    // if not exists
    if (!foundUser) {
      user.status = true;
      user.regtoken = "";
      user.password = await this.passwordHasher.hashPassword(user.password);
      return await this.userRepository.create(user);
    }
    //if it exists, throw error
    throw new HttpErrors.Conflict("Email value is already taken (ScopedCode:1)");
  }

  @get('/profiles/me')
  @secured(SecuredType.IS_AUTHENTICATED)
  async printCurrentUser(
    @requestBody({
      description: "<h3>Perfil de usuario.</h3><p>Cuando un usuario que ha iniciado sesión e ingresa a esta ruta con su token de autenticación, obtendrá los datos de su perfil.</p>",
    }) req: any,
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
  ): Promise<UserProfile> {
    // (@jannyHou)FIXME: explore a way to generate OpenAPI schema
    // for symbol property
    currentUserProfile.id = currentUserProfile[securityId];
    //console.log(currentUserProfile);
    delete currentUserProfile[securityId];
    return currentUserProfile;
  }

  @post('/profiles/me/change-password')
  @secured(SecuredType.IS_AUTHENTICATED)
  async changePasswordUser(
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
    @requestBody({
      description: "<h3>Perfil de usuario.</h3><p>Cuando un usuario que ha iniciado sesión e ingresa a esta ruta con su token de autenticación, obtendrá los datos de su perfil.</p>",
    }) resetPasswordRequest: ResetPasswordRequest,

  ): Promise<UserProfile> {
    //ME QUEDÉ AQUI
    // (@jannyHou)FIXME: explore a way to generate OpenAPI schema
    // for symbol property
    currentUserProfile.id = currentUserProfile[securityId];
    //console.log(currentUserProfile);
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
