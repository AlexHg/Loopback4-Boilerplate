import {
  inject,
  lifeCycleObserver,
  LifeCycleObserver,
  ValueOrPromise,
} from '@loopback/core';
import { juggler } from '@loopback/repository';

@lifeCycleObserver('datasource')
export class MongoDataSource extends juggler.DataSource
  implements LifeCycleObserver {
  static dataSourceName = 'mongo';

  constructor() {
    const dsConfig = {
      name: MongoDataSource.dataSourceName,
      connector: "mongodb",
      url: process.env.DB_URL,
      database: process.env.DB_NAME,
      useNewUrlParser: true,
      useUnifiedTopology: true
    }

    super(dsConfig);
  }

  /**
   * Start the datasource when application is started
   */
  start(): ValueOrPromise<void> {
    // Add your logic here to be invoked when the application is started
  }

  /**
   * Disconnect the datasource when application is stopped. This allows the
   * application to be shut down gracefully.
   */
  stop(): ValueOrPromise<void> {
    return super.disconnect();
  }
}
