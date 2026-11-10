// QwenWork provider. Chat completions are rewritten as QwenWork's own
// agent_chat_generation request by the vendored adapter (vendor/qoder.mjs):
// the host's tools ride along, tool calls come back structured, and the
// host agent keeps its loop. Magpie auth supplies the account; COSY signing,
// the request codec and the endpoint stay in the adapter.
import { createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'

const defaults = JSON.parse(readFileSync(new URL('./defaults.json', import.meta.url), 'utf8'))
// The provider's picture, as magpie reads it: a data:image URI on the auth hook.
const pluginIcon = (() => {
  try { return `data:image/png;base64,${readFileSync(new URL('./icon.png', import.meta.url)).toString('base64')}` } catch { return '' }
})()

function setting(name) {
  const value = (process.env['QWENWORK_' + name] ?? defaults[name])?.trim()
  if (!value) throw new Error(`QWENWORK_${name} is not configured`)
  return value
}
function origin(name) {
  let url
  try { url = new URL(setting(name)) } catch { throw new Error(`QWENWORK_${name} must be an https address`) }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error(`QWENWORK_${name} must be an https origin`)
  return url.origin
}

// num renders a credit count as magpie shows one: no trailing zeros, at most
// two decimals (1982.1652 -> "1982.17", 2000 -> "2000").
const num = (v) => {
  const n = Number(v)
  if (!Number.isFinite(n)) return '0'
  return String(Math.round(n * 100) / 100)
}

// The account's catalog, as the desktop app lists it (qwork scene), for the
// window before a sign-in and for a listing that can't be read: without a
// static list the provider shows no models at all and no agent can pick one.
const MODELS = [
  { id: 'flash', name: '标准', context: 1_000_000, images: true },
  { id: 'pro', name: '高级', context: 1_000_000, images: true },
  { id: 'qwen3.8-max-preview', name: 'Qwen3.8-Max', context: 1_000_000, images: true },
]

const finite = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined)
// the client's unwrapAdapterResponse: the envelope's data object, else the
// envelope itself
const unwrap = (v) => (v?.data && typeof v.data === 'object' && !Array.isArray(v.data) ? v.data : (v && typeof v === 'object' ? v : {}))

// The credit pools QwenWork's own client reads beside the plan's quota
// (fetchUserWallets): each pool's total_balance. A pool it doesn't have, or
// one at 0, is left out; the read failing is not a usage failure.
const POOLS = [['daily_credits', 'daily'], ['monthly_credits', 'monthly'], ['longterm_credits', 'long-term']]
async function walletPools(openapi, access) {
  try {
    const res = await fetch(`${openapi}/api/v1/adapter/user/wallets`, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${access}` },
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) return []
    const data = unwrap(await res.json())
    const out = []
    for (const [key, name] of POOLS) {
      const n = finite(data[key]?.total_balance)
      if (n !== undefined && n > 0) out.push(`${name} ${num(n)}`)
    }
    return out
  } catch { return [] }
}

// qwenworkUsage reads the account for magpie's usage bar: plan, name and
// credits. A personal account's quota has total and used null and only what
// is left, so that is the balance (with its pools, when it has any) rather
// than a share made up; an account with a total keeps its used / total
// window. Reading it also refreshes the name and plan the panel shows.
function qwenworkUsage(openapi) {
  return async (getAuth) => {
    let signIn = 'kept'
    try {
      const a = await getAuth()
      if (a?.type !== 'oauth' || !String(a.access ?? '').trim() || (a.expires > 0 && a.expires <= Date.now())) return { error: 'QwenWork: not signed in', signIn: 'expired' }
      const res = await fetch(`${openapi}/api/v1/adapter/user/account-context?include=user,plan,quota`, {
        headers: { Accept: 'application/json', Authorization: `Bearer ${a.access}` },
        signal: AbortSignal.timeout(20_000),
      })
      if (res.status === 401 || res.status === 403) return { error: 'QwenWork: the sign-in lapsed — sign in again', signIn: 'expired' }
      if (!res.ok) return { error: `QwenWork: usage read failed (HTTP ${res.status})`, signIn }
      const ctx = unwrap(await res.json())
      const out = { signIn }
      const name = ctx.user?.name || a.name
      if (name) out.user = String(name)
      if (ctx.plan?.name) out.plan = String(ctx.plan.name)
      const refresh = ctx.plan?.next_refresh_date ?? ctx.plan?.next_due_date
      if (refresh) out.until = new Date(refresh).toISOString()
      const q = ctx.quota && typeof ctx.quota === 'object' ? ctx.quota : {}
      const total = finite(q.total)
      const remaining = finite(q.remaining)
      const used = finite(q.used) ?? (total !== undefined && remaining !== undefined ? total - remaining : undefined)
      if (total !== undefined && total > 0 && used !== undefined && used >= 0) {
        out.windows = [{ name: 'Credits', used: Math.min(100, (100 * used) / total), display: `${num(used)} / ${num(total)} credits`, amount: used, limit: total, unit: 'credits' }]
      }
      if (remaining !== undefined) {
        const pools = await walletPools(openapi, a.access)
        out.balance = `${num(remaining)} credits${pools.length ? ` (${pools.join(' · ')})` : ''}`
        // nothing left stops the account: say so as a spent window, since
        // there is no total to show a share of
        const exceeded = q.exceeded === true || q.is_quota_exceeded === true || remaining <= 0
        if (!out.windows && exceeded) out.windows = [{ name: 'Credits', used: 100, display: 'no credits left' }]
      }
      if (!out.windows && out.balance === undefined) out.error = 'QwenWork: the account reports no credits'
      return out
    } catch (e) {
      return { error: String(e?.message ?? e), signIn }
    }
  }
}

export async function QwenWorkAuthPlugin({ client }) {
  const clientId = setting('CLIENT_ID')
  const web = origin('WEB')
  const openapi = origin('OPENAPI')
  const api = origin('API')
  const rsa = setting('RSA_PUBLIC_KEY').replaceAll('\\n', '\n')
  try { if (createPublicKey(rsa).asymmetricKeyType !== 'rsa') throw new Error() } catch { throw new Error('QWENWORK_RSA_PUBLIC_KEY must be an RSA public key in PEM form') }
  const site = {
    id: 'qwenwork', name: 'QwenWork', clientId, web, openapi, api, rsaKey: rsa,
    cosyVersion: setting('COSY_VERSION'), redirect: 'qwenwork-cn://',
    deviceOnly: true, deviceRefreshTarget: 'c', modelScene: 'qwork', listAllModels: true,
    clientType: '6', businessProduct: 'qoder_work', sessionType: 'qoder_work',
    userInfoPath: '/api/v1/adapter/user/account-context?include=user,plan,quota,page,data_sharing',
    normalizeUser: v => (v?.data ?? v)?.user ?? (v?.data ?? v),
    models: MODELS,
    // The adapter prefixes this under the host's own system messages; worded
    // for QwenWork, not the Qoder brand the adapter was shared from.
    systemPrompt: 'You are QwenWork (qw), a helpful assistant. Use the instructions below and the tools available to you to assist the user.',
  }
  const { makePlugin } = await import('./vendor/qoder.mjs')
  const plugin = await makePlugin(site)({ client })
  plugin.auth.usage = qwenworkUsage(openapi)
  plugin.auth.icon = pluginIcon
  return plugin
}
