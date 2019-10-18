import { get, post, requestBody, HttpErrors, getModelSchemaRef, param } from '@loopback/rest';
import { User } from '../models';
import { UserRepository, UserRoleRepository } from '../repositories';
import { repository } from '@loopback/repository';
import { Credentials, JWT_SECRET, secured, SecuredType, ResetPasswordRequest } from '../auth';
import { promisify } from 'util';
import { inject } from '@loopback/core';
import { SecurityBindings, UserProfile, securityId } from '@loopback/security';
import { PasswordHasher } from '../services/hash.password.bcryptjs';
import { PasswordHasherBindings } from '../keys';
import { Mailer } from '../services/mailer.service';

const { sign } = require('jsonwebtoken');
const signAsync = promisify(sign);


export class AuthController {
  constructor(
    @repository(UserRepository) private userRepository: UserRepository,
    @repository(UserRoleRepository) private userRoleRepository: UserRoleRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER) public passwordHasher: PasswordHasher,
  ) { }

  @post('/auth/register', {
    responses: {
      '200': { description: 'Retorna el usuario y email' },
      '400': { description: 'Faltan datos en la petición' },
      '409': { description: 'Error de conflicto: El Email ya existe' }
    }
  })
  @secured(SecuredType.PERMIT_ALL)
  async register(@requestBody({
    description: "<h3>Registro publico de usuarios.</h3><p>Cuando el usuario se registra, el api envía un correo al usuario con un token de confirmación para usarse en GET /auth/confirm/{token}.</p>",
    content: {
      'application/json': {
        schema: getModelSchemaRef(User, {
          title: 'NewUser',
          exclude: ['status', 'regtoken'],
        }),
      },
    },
  }) user: User): Promise<Object> {
    if (!user.id || !user.password || !user.email) throw new HttpErrors.BadRequest('Missing Username, Password or Email');

    const foundUser = await this.userRepository.findOne({
      where: { email: user.email }
    });

    // if not exists
    if (!foundUser) {
      user.status = false;
      user.regtoken = await this.passwordHasher.hashPassword(user.email + user.password);
      user.password = await this.passwordHasher.hashPassword(user.password);

      await (new Mailer).sendMail({
        to: user.email,
        subject: "Confirmación de correo",
        html: `auth/recovery/${user.regtoken}`
      });

      const newUser = await this.userRepository.create(user);
      return { id: newUser.id, email: newUser.email };
    }
    //if it exists, throw error
    throw new HttpErrors.Conflict("Email value is already taken (ScopedCode:1)");
  }

  @get('/auth/confirm/{token}', {
    responses: {
      '200': { description: 'No retorna nada, la operación fue exitosa' },
      '404': { description: 'El token ingresado no exite' }
    }
  })
  @secured(SecuredType.PERMIT_ALL)
  async confirm(@requestBody({
    description: "<h3>Confirmación publica de usuarios.</h3><p>Los usuarios registrados recibirán un correo electrónico con un token que deberán ingresar como parametro; de esta petición de forma que posteriormente podrán iniciar sesión</p>",
  }) @param.path.string('token') token: string): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { regtoken: token }
    });

    // if not exists
    if (user) {
      user.status = true;
      user.regtoken = "";
      user.password = await this.passwordHasher.hashPassword(user.password);

      this.userRepository.replaceById(user.id, user);
      //return user.email + " confirmado correctamente";
    }
    //if it exists, throw error
    throw new HttpErrors.NotFound("Token not found");
  }

  @post('/auth/login', {
    responses: {
      '200': { description: 'Retorna datos del usuario, los roles asignados y el token de JWT' },
      '400': { description: 'Faltan datos en la peticiòn' },
      '401': { description: 'Los datos ingresados son invalidos' },
    }
  })
  @secured(SecuredType.PERMIT_ALL)
  async login(@requestBody({
    description: "<h3>Inicio de sesión publico.</h3><p>Los usuarios registrados que han confirmado su cuenta podrán iniciar sesión</p>",
  }) credentials: Credentials) {

    if (!credentials.username || !credentials.password) throw new HttpErrors.BadRequest('Missing Username or Password');

    const user = await this.userRepository.findOne({ where: { id: credentials.username } });
    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');

    const isPasswordMatched = await this.passwordHasher.comparePassword(
      credentials.password,
      user.password,
    );
    if (!isPasswordMatched) throw new HttpErrors.Unauthorized('Invalid credentials');
    if (!user.status) throw new HttpErrors.Unauthorized('User not confirmated');

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

  @post('/auth/recovery', {
    responses: {
      '200': { description: 'No retorna nada, la operación ha sido exitosa y el correo ha sido enviado' },
      '400': { description: 'Faltan datos en la peticiòn' },
      '401': { description: 'El usuario no ha sido confirmado por el correo electrónico' },
      '404': { description: 'El correo electrónico no existe' },
    }
  })
  @secured(SecuredType.PERMIT_ALL)
  async recovery(@requestBody({
    description: "<h3>Recuperación publica de contraseña.</h3><p>Los usuarios que se han registrados y que hayan confirmado su cuenta previamente podrán recuperar contraseña, al ingresar su correo electrónico se enviará un correo electronico con un token de recuperación</p>",
  }) req: { email: string }): Promise<void> {
    if (!req.email) throw new HttpErrors.BadRequest("Missing Email");
    const user = await this.userRepository.findOne({
      where: { email: req.email }
    });

    // if not exists
    if (user) {
      if (!user.status) throw new HttpErrors.Unauthorized("User not confirmated");
      //user.status = true;
      user.regtoken = await this.passwordHasher.hashPassword(user.email + "recoveryToken");

      await (new Mailer).sendMail({
        to: user.email,
        subject: "Restablecer contraseña",
        html: `auth/recovery POST {${user.regtoken}, newPassword}`
      });

      this.userRepository.replaceById(user.id, user);

    } else throw new HttpErrors.NotFound("Email does not exist");
  }

  @post('/auth/recovery-confirm', {
    responses: {
      '200': { description: 'No retorna nada, la operación ha sido exitosa y la contraseña ha sido cambiada' },
      '404': { description: 'Token ingresado no existe' },
    }
  })
  @secured(SecuredType.PERMIT_ALL)
  async recoveryConfirm(@requestBody({
    description: "<h3>Confirmación de recuperación publica de contraseña.</h3><p>Los usuarios que han recibido un correo electrónico con el token de recuperación de contraseña podrán ingresar una nueva contraseña</p>",
  }) req: { token: string, password: string }): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { regtoken: req.token }
    });

    // if not exists
    if (user) {
      user.regtoken = "";
      user.password = await this.passwordHasher.hashPassword(req.password);

      this.userRepository.replaceById(user.id, user);

    } else throw new HttpErrors.NotFound("Token does not exist");
  }
}
