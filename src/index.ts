import { Hono } from 'hono'
import { oidcAuthMiddleware, getAuth, revokeSession, processOAuthCallback } from "../../middleware/packages/oidc-auth/src";

const app = new Hono()

app.get('/logout', async (c) => {
  await revokeSession(c)
  return c.text(`Logged off`)
})
app.get('/callback', async (c) => {
  return processOAuthCallback(c)
})
app.use('/*', oidcAuthMiddleware())
app.all('/*', async (c) => {
  const auth = await getAuth(c)
  return c.text(`Hello <${auth?.email}>! ${auth?.rtkexp} ${auth?.ssnexp}`)
})

export default app
