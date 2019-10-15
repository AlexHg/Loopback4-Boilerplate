import { DefaultCrudRepository } from '@loopback/repository';
import { Role } from '../models';
import { MongoDataSource } from '../datasources';
import { inject } from '@loopback/core';

export class RoleRepository extends DefaultCrudRepository<Role, typeof Role.prototype.id> {
  constructor(@inject('datasources.mongo') dataSource: MongoDataSource) {
    super(Role, dataSource);
  }
}
