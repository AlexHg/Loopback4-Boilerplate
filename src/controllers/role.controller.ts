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
import { Role } from '../models';
import { RoleRepository } from '../repositories';
import { secured, SecuredType } from '../auth';

export class RoleController {
  constructor(
    @repository(RoleRepository)
    public roleRepository: RoleRepository,
  ) { }

  @post('/roles/create', {
    responses: {
      '200': {
        description: 'Role model instance',
        content: { 'application/json': { schema: getModelSchemaRef(Role) } },
      },
    },
  })
  @secured(SecuredType.HAS_ANY_ROLE, ['ADMIN', 'ADMIN2'])
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Role, {
            title: 'NewRole',

          }),
        },
      },
    })
    role: Role,
  ): Promise<Role> {
    return this.roleRepository.create(role);
  }

  @get('/roles/count', {
    responses: {
      '200': {
        description: 'Role model count',
        content: { 'application/json': { schema: CountSchema } },
      },
    },
  })
  @secured(SecuredType.PERMIT_ALL)
  async count(
    @param.query.object('where', getWhereSchemaFor(Role)) where?: Where<Role>,
  ): Promise<Count> {
    return this.roleRepository.count(where);
  }

  @get('/roles/list', {
    responses: {
      '200': {
        description: 'Array of Role model instances',
        content: {
          'application/json': {
            schema: { type: 'array', items: getModelSchemaRef(Role) },
          },
        },
      },
    },
  })
  @secured(SecuredType.HAS_ANY_ROLE, ['ADMIN', 'ADMIN2'])
  async find(
    @param.query.object('filter', getFilterSchemaFor(Role)) filter?: Filter<Role>,
  ): Promise<Role[]> {
    return this.roleRepository.find(filter);
  }

  @get('/roles/{id}', {
    responses: {
      '200': {
        description: 'Role model instance',
        content: { 'application/json': { schema: getModelSchemaRef(Role) } },
      },
    },
  })
  async findById(@param.path.string('id') id: string): Promise<Role> {
    return this.roleRepository.findById(id);
  }

  @put('/roles/{id}', {
    responses: {
      '204': {
        description: 'Role PUT success',
      },
    },
  })
  @secured(SecuredType.HAS_ANY_ROLE, ['ADMIN', 'ADMIN2'])
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() role: Role,
  ): Promise<void> {
    await this.roleRepository.replaceById(id, role);
  }


  @del('/roles/{id}', {
    responses: {
      '204': {
        description: 'Role DELETE success',
      },
    },
  })
  @secured(SecuredType.HAS_ANY_ROLE, ['ADMIN', 'ADMIN2'])
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.roleRepository.deleteById(id);
  }
}
