import { Entity, model, property } from '@loopback/repository';

@model()
export class User extends Entity {
  @property({
    type: 'string',
    id: true,
  })
  id?: string;

  @property({
    type: 'string',
    required: true,
  })
  email: string;

  @property({
    type: 'string',
    required: true,
  })
  password: string;

  @property({
    type: 'string'
  })
  regtoken?: string;

  @property({
    type: 'boolean',
    required: true,
    default: 0
  })
  status: boolean;

  constructor(data?: Partial<User>) {
    super(data);
  }
}
