import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcript from 'bcrypt'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, require: true },
  username: { type: String, require: true },
  password: { type: String, require: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })

    if (user) throw new Error('username already exists')

    const id = crypto.randomUUID()
    const hashPassword = await bcript.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashPassword
    }).save()

    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })

    if (!user) throw new Error('username does not exits')

    const isValid = await bcript.compare(password, user.password)
    if (!isValid) throw new Error('password is invalid')

    const { password: _, ...publicUser } = user

    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (typeof username.length < 3) throw new Error('username must be at least 3 characters long')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (typeof password.length < 6) throw new Error('password must be at least 6 characters long')
  }
}
