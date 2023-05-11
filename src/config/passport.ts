import passport from "passport";
import dotenv from 'dotenv'
import { Strategy as JWTStartegy, ExtractJwt } from 'passport-jwt'
import { Response, Request, NextFunction } from "express";
import jwt from 'jsonwebtoken';

import { User } from "../models/User";


dotenv.config();


const notAuthorazationJson = {status: 401, message: "Não autorizado"}
const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET as string
}

passport.use(new JWTStartegy(options, async (payload, done) => {
    var user = await User.findByPk(payload.id);
    if(user) {
        return done(null, user)
    }else {
        return done(notAuthorazationJson, false)
    }
}))

export const generationToken = (data: object) => {
    return jwt.sign(data, process.env.JWT_SECRET as string)
}

type AuthenticateCallback = (err: Error | null, user?: any, info?: any) => void;

export const privateRoute = (req: Request, res: Response, next: NextFunction) => {
  const authFunction: AuthenticateCallback = (err: Error | null, user?: any) => {
    req.user = user;
    return user ? next() : next(notAuthorazationJson);
  };

  passport.authenticate('jwt', { session: false }, authFunction)(req, res, next);
};

export default passport;