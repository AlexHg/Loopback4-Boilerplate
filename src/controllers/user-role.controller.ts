import {
  Count,
  CountSchema,
  Filter,
  repository,
  Where,
} from '@loopback/repository';
import {
  post,
  param,
  get,
  getFilterSchemaFor,
  getModelSchemaRef,
  getWhereSchemaFor,
  patch,
  put,
  del,
  requestBody,
} from '@loopback/rest';
import { UserRole } from '../models';
import { UserRoleRepository } from '../repositories';
import { HttpErrors } from '@loopback/rest';
import { secured, SecuredType } from '../auth';

export class UserRoleController {
  constructor(
    @repository(UserRoleRepository)
    public userRoleRepository: UserRoleRepository,
  ) { }

  @post('/user-roles/assoc', {
    responses: {
      '200': {
        description: 'UserRole model instance',
        content: { 'application/json': { schema: getModelSchemaRef(UserRole) } },
      },
    },
  })
  @secured(SecuredType.HAS_ROLES, ['ADMIN'])
  async assoc(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(UserRole, {
            title: 'NewUserRole',
            exclude: ['id'],
          }),
        },
      },
    })
    userRole: Omit<UserRole, 'id'>,
  ): Promise<UserRole> {
    const roleRelation = await this.userRoleRepository.findOne({
      where: {
        userId: userRole.userId,
        roleId: userRole.roleId
      }
    });
    if (roleRelation != null) throw new HttpErrors.Conflict("User - Role relationship already exists ");
    return this.userRoleRepository.create(userRole);
  }

  @post('/user-roles/disassoc', {
    responses: {
      '204': {
        description: 'UserRole DELETE success',
      },
    },
  })
  @secured(SecuredType.HAS_ROLES, ['ADMIN'])
  async disassoc(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(UserRole, {
            title: 'NewUserRole',
            exclude: ['id'],
          }),
        },
      },
    })
    userRole: UserRole
  ): Promise<void> {
    const roleRelation = await this.userRoleRepository.findOne({
      where: {
        userId: userRole.userId,
        roleId: userRole.roleId
      }
    });
    if (roleRelation != null) this.userRoleRepository.delete(roleRelation);
    else throw new HttpErrors.Conflict("User - Role relationship not exists");
  }

  @get('/user-roles/{roleId}', {
    responses: {
      '200': {
        description: 'UserRole model instance',
        content: { 'application/json': { schema: getModelSchemaRef(UserRole) } },
      },
    },
  })
  @secured(SecuredType.HAS_ANY_ROLE, ['ADMIN', 'ADMIN2'])
  async userListByRole(@param.path.string('roleId') roleId: string): Promise<Array<String>> {

    const userListByRole = await this.userRoleRepository.find({
      where: {
        roleId: roleId
      }
    });
    //if (userListByRole.length == 0) throw new HttpErrors.Conflict(`There is no user related to the ${roleId} role`);
    return userListByRole.map((userRole) => userRole.userId);
  }
}
