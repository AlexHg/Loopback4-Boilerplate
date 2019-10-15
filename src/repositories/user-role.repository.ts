import { DefaultCrudRepository } from '@loopback/repository';
import { UserRole } from '../models';
import { MongoDataSource } from '../datasources';
import { inject } from '@loopback/core';

export class UserRoleRepository extends DefaultCrudRepository<UserRole, typeof UserRole.prototype.id> {
  constructor(@inject('datasources.mongo') dataSource: MongoDataSource) {
    super(UserRole, dataSource);
  }
}
