import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as nodemailer from 'nodemailer';


const EMAIL_USER = process.env.EMAIL_USER
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD

export enum MailTemplate {
  emailVerify = 'Email Verify Requested',
  forgotPassword = 'Password Reset Requested',
  insufficentFunds = 'Transaction failed'
}

const templates = {
  [MailTemplate.emailVerify]: 'email-verify.html',
  [MailTemplate.forgotPassword]: 'reset-password.html'
};

@Injectable()
export class MailService {

  async sendTemplate<IArgs>(
    template: MailTemplate,
    subject: string,
    user: { name?: string; email: string },
    args?: IArgs
  ) {
    let argsData = args ? args : {};


    // Retrieve Markup
    let templateMarkup: string = fs.readFileSync(
      path.join(__dirname, `../../templates/${templates[template]}`),
      'utf8'
    );

    // Replace markup keys
    Object.entries({
      ...user,
      ...(argsData as Record<string, any>),
    }).forEach(([key, value]) => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      templateMarkup = templateMarkup.replace(regex, value);
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject,
      html: templateMarkup,
    };

    try {
      const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
      await transporter.sendMail(mailOptions);
    } catch (err) {
      console.log(err);
      throw new Error('Failed to send email');
    }
  }
}
