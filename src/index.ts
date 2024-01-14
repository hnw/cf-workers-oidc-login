import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import * as oauth2 from 'oauth4webapi'

type Bindings = {
  JWT_SECRET: string;
  ISSUER: string;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
  REDIRECT_URI: string;
};
type Variables = {
  as: oauth2.AuthorizationServer;
  client: oauth2.Client;
  code_verifier: string;
}
const app = new Hono<{ Variables: Variables, Bindings: Bindings}>()

app.use('*', async (c, next) => {
  const issuer = new URL(c.env.ISSUER)
  const as = await oauth2
  .discoveryRequest(issuer)
  .then((response) => oauth2.processDiscoveryResponse(issuer, response))
  c.set('as', as)
  const client: oauth2.Client = {
    client_id: c.env.CLIENT_ID,
    client_secret: c.env.CLIENT_SECRET,
    token_endpoint_auth_method: 'client_secret_basic',
  }
  c.set('client', client)
  await next()
})

app.use('*', async (c, next) => {
  const session_jwt = getCookie(c, 'session_jwt')
  if (session_jwt) {
    try {
      const payload = await verify(session_jwt, c.env.JWT_SECRET)
      if (payload.expire < Date.now()) {
        if (payload.refresh_token === undefined) {
          throw new Error('No refresh token in cookie')
        }
        const response = await oauth2.refreshTokenGrantRequest(c.var.as, c.var.client, payload.refresh_token)
        const result = await oauth2.processRefreshTokenResponse(c.var.as, c.var.client, response)
        if (oauth2.isOAuth2Error(result)) {
          // refresh_token might be expired or revoked
          throw new Error(`OAuth2Error: [${result.error}] ${result.error_description}`)
        }
        let { refresh_token } = result
        if (refresh_token === undefined) {
          // refresh_token is not returned when refresh_token is not expired
          refresh_token = payload.refresh_token
        }
        const session_jwt = await signedSession(refresh_token!, c.env.JWT_SECRET)
        setCookie(c, 'session_jwt', session_jwt, { path: '/' })
      }
    } catch (e) {
      console.log(e)
      deleteCookie(c, 'session_jwt')
    }
  }
  await next()
})

app.get('/login', async (c) => {
  const code_verifier = oauth2.generateRandomCodeVerifier()
  const code_challenge = await oauth2.calculatePKCECodeChallenge(code_verifier)
  const code_challenge_method = 'S256'
  const state = oauth2.generateRandomState()
  setCookie(c, 'code_verifier', code_verifier, { maxAge: 60 * 60 * 24, path: '/' })
  setCookie(c, 'state', state, { maxAge: 60 * 60 * 24, path: '/' })
  const authorizationUrl = new URL(c.var.as.authorization_endpoint!)
  authorizationUrl.searchParams.set('client_id', c.var.client.client_id)
  authorizationUrl.searchParams.set('code_challenge', code_challenge)
  authorizationUrl.searchParams.set('code_challenge_method', code_challenge_method)
  authorizationUrl.searchParams.set('redirect_uri', c.env.REDIRECT_URI)
  authorizationUrl.searchParams.set('response_type', 'code')
  authorizationUrl.searchParams.set('scope', 'openid offline_access')
  authorizationUrl.searchParams.set('state', state)
  return c.redirect(authorizationUrl.toString())
})

app.get('/callback', async (c) => {
  const code = c.req.query('code')
  const code_verifier = getCookie(c, 'code_verifier') || ''
  deleteCookie(c, 'code_verifier')
  const state = getCookie(c, 'state')
  deleteCookie(c, 'state')
  const currentUrl: URL = new URL(c.req.url)
  let params: URLSearchParams | oauth2.OAuth2Error
  try {
    params = oauth2.validateAuthResponse(c.var.as, c.var.client, currentUrl, state)
  } catch (e) {
    console.log(e)
    return c.text('401 Unauthorized', { status: 401 })
  }
  if (oauth2.isOAuth2Error(params)) {
    console.log('Error 2: ', params)
    return c.text('401 Unauthorized', { status: 401 })
  }
  const response = await oauth2.authorizationCodeGrantRequest(
    c.var.as,
    c.var.client,
    params,
    c.env.REDIRECT_URI,
    code_verifier,
  )
  let challenges: oauth2.WWWAuthenticateChallenge[] | undefined
  if ((challenges = oauth2.parseWwwAuthenticateChallenges(response))) {
    for (const challenge of challenges) {
      console.log('challenge', challenge)
    }
    throw new Error() // Handle www-authenticate challenges as needed
  }
  const result = await oauth2.processAuthorizationCodeOpenIDResponse(c.var.as, c.var.client, response)
  if (oauth2.isOAuth2Error(result)) {
    console.log('Error 3: ', result, c.req.url)
    return c.text('401 Unauthorized', { status: 401 })
  }

  //console.log('result', result)
  const { refresh_token } = result
  //const claims = oauth2.getValidatedIdTokenClaims(result)
  //console.log('ID Token Claims', claims)

  if (refresh_token === undefined) {
    console.log('result', result)
    throw new Error('No refresh token was returned')
  }

  const session_jwt = await signedSession(refresh_token, c.env.JWT_SECRET)
  console.log('session_jwt', session_jwt)
  setCookie(c, 'session_jwt', session_jwt, { path: '/' })

  return c.text(`code: ${code}`)
})

async function signedSession(refresh_token: string, jwt_secret: string) {
  const payload = {
    refresh_token: refresh_token,
    expire: Date.now() + 60 * 60 * 1 * 1000, // 1 hour
  }
  return sign(payload, jwt_secret)
}

export default app
