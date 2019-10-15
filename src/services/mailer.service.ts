import { bind, /* inject, */ BindingScope } from '@loopback/core';
import { SentMessageInfo } from 'nodemailer';
import Mail = require('nodemailer/lib/mailer');

const nodemailer = require("nodemailer");

@bind({ scope: BindingScope.TRANSIENT })
export class Mailer {
  constructor(/* Add @inject to inject parameters */) { }

  /*
   * Add service methods here
   */
  async sendMail(mailOptions: Mail.Options): Promise<SentMessageInfo> {
    console.log(process.env.SMTP_USERNAME);
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_SECURE,
      auth: {
        user: process.env.SMTP_USERNAME, // generated ethereal user
        pass: process.env.SMTP_PASSWORD // generated ethereal password
      }
    });
    return transporter.sendMail(mailOptions);
  }

}
