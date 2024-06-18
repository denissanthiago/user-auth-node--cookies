import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { NODE_ENV, PORT, SECRET_KEY_JWT } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use((request, response, next) => {
  const token = request.cookies.access_token

  request.session = { user: null }

  try {
    request.session.user = jwt.verify(token, SECRET_KEY_JWT)
  } catch (error) {}

  next() // seguir a la siguiente ruta o middleware
})

app.set('view engine', 'ejs')

app.get('/', (request, response) => {
  const { user } = request.session
  response.render('index', user)
})

app.post('/login', async (request, response) => {
  const { username, password } = request.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY_JWT, { expiresIn: '1h' })

    response
      .cookie('access_token', token, {
        httpOnly: true, // la cookie solo se puede acceder en el servidor
        secure: NODE_ENV === 'production', // la cookie solo se puede acceder en https
        sameSite: 'strict', // la cookie solo se puede acceder desde el mismo dominio
        maxAge: 1000 * 60 * 60 // la cookie tiene una valides de 1 h
      })
      .send({ user, token })
  } catch (error) {
    response.status(401).send(error.message)
  }
})

app.post('/register', async (request, response) => {
  const { username, password } = request.body
  try {
    const id = await UserRepository.create({ username, password })
    response.send({ id })
  } catch (error) {
    response.status(400).send(error.message)
  }
})

app.post('/logout', (request, response) => {
  response.clearCookie('access_token').json({ message: 'Logout successful' })
})

app.post('/protected', (request, response) => {
  const { user } = request.session
  if (!user) return request.status(403).message('Access not Authorized')
  response.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
