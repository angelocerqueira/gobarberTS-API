import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';
import User from '../models/User';
import { jwtConfig } from '../config/JWT';

interface Request {
  email: string;
  password: string;
}

interface Response {
  user: User;
  token: string;
}

class AuthenticateUserSession {
  public async execute({ email, password }: Request): Promise<Response> {
    const usersRepository = getRepository(User);
    const { secret, expires_in } = jwtConfig;

    const user = await usersRepository.findOne({
      where: { email },
    });
    if (!user) {
      throw new Error('Incorret email/password conbination.');
    }

    const passwordMatched = await compare(password, user.password);
    if (!passwordMatched) {
      throw new Error('Incorret email/password conbination.');
    }

    const token = sign({}, secret, {
      subject: user.id,
      expiresIn: expires_in,
    });
    return {
      user,
      token,
    };
  }
}

export default AuthenticateUserSession;
