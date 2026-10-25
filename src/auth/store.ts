import { cleanupBudgetMillis } from "../postgres.js";
import { and, or, createDatabase, appAuthSessionsTable, type Database, type DatabasePort } from "./private/database.js";
import { encodeTimestampValue } from "../orm.js";
import { cleanupCandidates as candidates, emailPolicy, type CleanupCondition } from "./core/rules.js";
import type { Store } from "./core/store.js";

export type { DatabasePort } from "./private/database.js";
export { encodeTimestampValue, cleanupBudgetMillis };

export function cleanupCandidates(policy: Parameters<typeof candidates>[0], now: number) {
  return cleanupFilter(candidates(policy, now));
}

function cleanupFilter({cutoff, idleCutoff, legacyCutoff, absoluteCutoff}: CleanupCondition) {
  const c = appAuthSessionsTable.columns;
  const filters = [c.revokedAt.isNotNull(),
    and(c.transport.eq("browser"), c.expiresAt.lte(cutoff)),
    c.lastRenewedAt.lte(idleCutoff),
    and(c.lastRenewedAt.isNull(), or(c.expiresAt.lte(idleCutoff), c.createdAt.lte(legacyCutoff)))];
  if (absoluteCutoff !== undefined) filters.push(c.firstLoginAt.lte(absoluteCutoff),
    and(c.firstLoginAt.isNull(), c.createdAt.lte(absoluteCutoff)));
  return or(...filters);
}

export interface RuntimeStore extends Store {
  transaction<T>(work: (tx: Store) => Promise<T>): Promise<T>;
}

export function createStore(port: DatabasePort): RuntimeStore {
  return databaseStore(createDatabase(port));
}

function databaseStore(db: Database): RuntimeStore {
  return {
    signup: id => db.appAuthSignupRequests.findById({id}),
    signupsByEmail: email => db.appAuthSignupRequests.findMany({where: c => c.email.eq(email)}),
    lockSignupEmail: async (keyHash, expiresAt) => {
      // The shared row serializes attempts before any signup-row locks, including the first insert.
      await db.appAuthRateLimits.upsert({action: "signup_attempt", keyHash, attemptCount: 0, expiresAt});
    },
    saveSignup: async values => { await db.appAuthSignupRequests.insert(values); },
    lockSignup: (row, at) => db.appAuthSignupRequests.updateIf({id: row.id},
      c => and(c.codeHash.eq(row.codeHash), c.expiresAt.gt(at)), {updatedAt: row.updatedAt}),
    renewSignup: (row, codeHash, codeExpiresAt, updatedAt) => db.appAuthSignupRequests.updateIf({id: row.id},
      c => and(c.codeHash.eq(row.codeHash), c.expiresAt.gt(updatedAt),
        c.updatedAt.lte(new Date(Date.parse(updatedAt) - emailPolicy.codeResendMillis).toISOString())),
      {codeHash, codeExpiresAt, attempts: 0, updatedAt}),
    failSignupCode: async row => { await db.appAuthSignupRequests.updateIf({id: row.id},
      c => c.attempts.lt(emailPolicy.codeMaximumAttempts), {attempts: row.attempts + 1}); },
    deleteSignup: async id => { await db.appAuthSignupRequests.delete({id}); },
    expiredSignupRequests: (cutoff, limit) => db.appAuthSignupRequests.findMany({
      where: c => c.expiresAt.lte(cutoff), orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit,
    }),
    deleteExpiredSignupRequest: async (row, cutoff) => {
      const locked = await db.appAuthSignupRequests.updateIf({id: row.id},
        c => c.expiresAt.lte(cutoff), {updatedAt: row.updatedAt});
      if (locked) await db.appAuthSignupRequests.delete({id: row.id});
    },
    transaction: work => db.transaction(tx => work(databaseStore(tx))),
    user: id => db.appAuthUsers.findById({id}),
    userByEmail: async email => (await db.appAuthUsers.findMany({where: c => c.email.eq(email), limit: 1}))[0],
    createUser: (email, passwordHash) => db.appAuthUsers.insert({email, passwordHash}),
    lockUser: (id, version) => db.appAuthUsers.updateIf({id}, c => and(c.disabledAt.isNull(),
      c.sessionVersion.eq(version)), {sessionVersion: version}),
    markEmailVerified: async (id, emailVerifiedAt) => {
      await db.appAuthUsers.update({id}, {emailVerifiedAt});
    },
    resetPassword: async (id, passwordHash) => {
      await db.appAuthUsers.incrementIf({id}, c => c.disabledAt.isNull(), {sessionVersion: 1}, {passwordHash});
    },
    actionByToken: async (hash, kind) => (await db.appAuthActionTokens.findMany({
      where: c => and(c.tokenHash.eq(hash), c.kind.eq(kind)), limit: 1,
    }))[0],
    failActionCode: async row => { await db.appAuthActionTokens.updateIf({id: row.id},
      c => c.attempts.lt(emailPolicy.codeMaximumAttempts), {attempts: row.attempts + 1}); },
    liveActionToken: async (userId, kind, at) => (await db.appAuthActionTokens.findMany({
      where: c => and(c.userId.eq(userId), c.kind.eq(kind), c.consumedAt.isNull(), c.expiresAt.gt(at)), limit: 1,
    }))[0],
    createActionToken: values => db.appAuthActionTokens.insert(values),
    invalidateActionTokens: async (userId, kind, consumedAt) => {
      const rows = await db.appAuthActionTokens.findMany({
        where: c => and(c.userId.eq(userId), c.kind.eq(kind), c.consumedAt.isNull()),
      });
      for (const row of rows) await db.appAuthActionTokens.updateIf({id: row.id}, c => c.consumedAt.isNull(), {consumedAt});
    },
    consumeActionToken: (id, kind, at) => db.appAuthActionTokens.updateIf({id},
      c => and(c.kind.eq(kind), c.consumedAt.isNull(), c.expiresAt.gt(at)), {consumedAt: at}),
    consumedActionTokens: limit => db.appAuthActionTokens.findMany({
      where: c => c.consumedAt.isNotNull(), orderBy: c => [c.id.asc()], limit,
    }),
    expiredActionTokens: (cutoff, limit) => db.appAuthActionTokens.findMany({
      where: c => c.expiresAt.lte(cutoff),
      orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit,
    }),
    deleteExpiredActionToken: async (row, cutoff) => {
      const locked = await db.appAuthActionTokens.updateIf({id: row.id},
        c => or(c.expiresAt.lte(cutoff), c.consumedAt.isNotNull()), {expiresAt: row.expiresAt});
      if (locked) await db.appAuthActionTokens.delete({id: row.id});
    },
    identity: (provider, subject) => db.appAuthIdentities.findById({provider, subject}),
    createIdentity: (provider, subject, userId) => db.appAuthIdentities.insert({provider, subject, userId}),
    session: id => db.appAuthSessions.findById({id}),
    sessionByToken: async hash => (await db.appAuthSessions.findMany({where: c => c.tokenHash.eq(hash), limit: 1}))[0],
    lockSession: (id, hash) => db.appAuthSessions.updateIf({id}, c => hash
      ? and(c.revokedAt.isNull(), c.tokenHash.eq(hash)) : c.revokedAt.isNull(), {revokedAt: null}),
    lockCleanupSession: row => db.appAuthSessions.updateIf({id: row.id}, c => c.expiresAt.eq(row.expiresAt), {expiresAt: row.expiresAt}),
    updateSession: (id, values) => db.appAuthSessions.update({id}, values),
    createSession: values => db.appAuthSessions.insert(values),
    revokeSession: (id, at, browserHash) => db.appAuthSessions.updateIf({id}, c => browserHash
      ? and(c.tokenHash.eq(browserHash), c.transport.eq("browser"), c.revokedAt.isNull())
      : c.revokedAt.isNull(), {revokedAt: at}),
    deleteSession: async id => { await db.appAuthSessions.delete({id}); },
    cleanupSessions: (condition, start, wrap, limit) => db.appAuthSessions.findMany({
      where: c => and(cleanupFilter(condition), wrap ? c.id.lt(start) : c.id.gte(start)),
      orderBy: c => [c.id.asc()], limit,
    }),
    refresh: id => db.appAuthRefreshTokens.findById({id}),
    refreshByToken: async hash => (await db.appAuthRefreshTokens.findMany({where: c => c.tokenHash.eq(hash), limit: 1}))[0],
    latestRefresh: async sessionId => (await db.appAuthRefreshTokens.findMany({
      where: c => and(c.sessionId.eq(sessionId), c.consumedAt.isNull()), orderBy: c => [c.createdAt.desc(), c.id.desc()], limit: 1,
    }))[0],
    refreshChildren: (sessionId, limit) => db.appAuthRefreshTokens.findMany({where: c => c.sessionId.eq(sessionId),
      orderBy: c => [c.createdAt.asc(), c.id.asc()], limit}),
    createRefresh: values => db.appAuthRefreshTokens.insert(values),
    consumeRefresh: (id, at) => db.appAuthRefreshTokens.updateIf({id}, c => c.consumedAt.isNull(), {consumedAt: at}),
    deleteRefresh: async id => { await db.appAuthRefreshTokens.delete({id}); },
    invite: id => db.appAuthInvites.findById({id}),
    inviteByCode: async hash => (await db.appAuthInvites.findMany({where: c => c.codeHash.eq(hash), limit: 1}))[0],
    createInvite: values => db.appAuthInvites.insert(values),
    updateInvite: (id, values) => db.appAuthInvites.update({id}, values),
    lockInvite: (row, email, hash, now) => db.appAuthInvites.updateIf({id: row.id}, c => and(c.codeHash.eq(hash),
      c.email.eq(email), c.redeemedAt.isNull(), c.redeemedBy.isNull(), c.revokedAt.isNull(),
      c.expiresAt.eq(row.expiresAt), c.expiresAt.gt(now)), {expiresAt: row.expiresAt}),
    lockInviteExpiry: (row, cutoff) => db.appAuthInvites.updateIf({id: row.id},
      c => cutoff === undefined ? c.expiresAt.eq(row.expiresAt)
        : and(c.expiresAt.eq(row.expiresAt), c.expiresAt.lte(cutoff)), {expiresAt: row.expiresAt}),
    listInvites: after => db.appAuthInvites.findMany({
      where: after ? c => or(c.createdAt.gt(after[0]), and(c.createdAt.eq(after[0]), c.id.gt(after[1]))) : undefined,
      orderBy: c => [c.createdAt.asc(), c.id.asc()], limit: 51,
    }),
    expiredInvites: (cutoff, limit) => db.appAuthInvites.findMany({where: c => c.expiresAt.lte(cutoff),
      orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit}),
    deleteInvite: async id => { await db.appAuthInvites.delete({id}); },
    rateLimit: key => db.appAuthRateLimits.findById(key),
    createRateLimit: values => db.appAuthRateLimits.insert(values),
    updateRateLimit: (row, values, maximum) => values.expiresAt === row.expiresAt
      ? db.appAuthRateLimits.incrementIf({action: row.action, keyHash: row.keyHash},
        c => and(c.expiresAt.eq(row.expiresAt), c.attemptCount.lt(maximum)), {attemptCount: 1}, {expiresAt: row.expiresAt})
      : db.appAuthRateLimits.updateIf({action: row.action, keyHash: row.keyHash},
        c => c.expiresAt.eq(row.expiresAt), values),
    expiredRateLimits: (cutoff, limit) => db.appAuthRateLimits.findMany({where: c => c.expiresAt.lte(cutoff),
      orderBy: c => [c.expiresAt.asc(), c.action.asc(), c.keyHash.asc()], limit}),
    lockRateLimit: (row, cutoff) => db.appAuthRateLimits.updateIf({action: row.action, keyHash: row.keyHash},
      c => and(c.expiresAt.eq(row.expiresAt), c.attemptCount.eq(row.attemptCount), c.expiresAt.lte(cutoff)),
      {attemptCount: row.attemptCount}),
    deleteRateLimit: async key => { await db.appAuthRateLimits.delete(key); },
  };
}
