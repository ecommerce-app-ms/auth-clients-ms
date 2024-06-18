import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  DATABASE_URL: string;

  NAST_SERVERS: string[];
}

const envSchema = joi
  .object({
    PORT: joi.number().required(),
    DATABASE_URL: joi.string().required(),
    NAST_SERVERS: joi.array().items(joi.string().required()),
  })
  .unknown(true);
const { error, value } = envSchema.validate({
  ...process.env,
  NAST_SERVERS: process.env.NAST_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  dataBaseUrl: envVars.DATABASE_URL,
  nastServers: envVars.NAST_SERVERS,
};
