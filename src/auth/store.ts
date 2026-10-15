import { cleanupBudgetMillis } from "../postgres.js";
import { and, or, createDatabase, appAuthSessionsTable, type Database, type DatabasePort } from "./private/database.js";
import { encodeTimestampValue } from "../orm.js";
import { cleanupCandidates as candidates, type CleanupCondition } from "./core/rules.js";
import type { Store } from "./core/store.js";

export type { DatabasePort } from "./private/database.js";
export { encodeTimestampValue, cleanupBudgetMillis };

export function cleanupCandidates(policy: Parameters<typeof candidates>[0], now: number) {
  return cleanupFilter(candidates(policy, now));
}

function cleanupFilter({cutoff, idleCutoff, legacyCutoff, absoluteCutoff}: CleanupCondition) {
  const c = appAuthSessionsTable.columns;
  const filters = [c.revokedAt.isNotNull(),
    and(c.transport.equals("browser"), c.expiresAt.lessThanOrEquals(cutoff)),
    c.lastRenewedAt.lessThanOrEquals(idleCutoff),
    and(c.lastRenewedAt.isNull(), or(c.expiresAt.lessThanOrEquals(idleCutoff), c.createdAt.lessThanOrEquals(legacyCutoff)))];
  if (absoluteCutoff !== undefined) filters.push(c.firstLoginAt.lessThanOrEquals(absoluteCutoff),
    and(c.firstLoginAt.isNull(), c.createdAt.lessThanOrEquals(absoluteCutoff)));
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
    transaction: work => db.transaction(tx => work(databaseStore(tx))),
    user: id => db.appAuthUsers.findById({id}),
    userByEmail: async email => (await db.appAuthUsers.findMany({where: c => c.email.equals(email), limit: 1}))[0],
    createUser: (email, passwordHash) => db.appAuthUsers.insert({email, passwordHash}),
    lockUser: (id, version) => db.appAuthUsers.updateIf({id}, c => and(c.disabledAt.isNull(),
      c.sessionVersion.equals(version)), {sessionVersion: version}),
    identity: (provider, subject) => db.appAuthIdentities.findById({provider, subject}),
    createIdentity: (provider, subject, userId) => db.appAuthIdentities.insert({provider, subject, userId}),
    session: id => db.appAuthSessions.findById({id}),
    sessionByToken: async hash => (await db.appAuthSessions.findMany({where: c => c.tokenHash.equals(hash), limit: 1}))[0],
    lockSession: (id, hash) => db.appAuthSessions.updateIf({id}, c => hash
      ? and(c.revokedAt.isNull(), c.tokenHash.equals(hash)) : c.revokedAt.isNull(), {revokedAt: null}),
    lockCleanupSession: row => db.appAuthSessions.updateIf({id: row.id}, c => c.expiresAt.equals(row.expiresAt), {expiresAt: row.expiresAt}),
    updateSession: (id, values) => db.appAuthSessions.update({id}, values),
    createSession: values => db.appAuthSessions.insert(values),
    revokeSession: (id, at, browserHash) => db.appAuthSessions.updateIf({id}, c => browserHash
      ? and(c.tokenHash.equals(browserHash), c.transport.equals("browser"), c.revokedAt.isNull())
      : c.revokedAt.isNull(), {revokedAt: at}),
    deleteSession: async id => { await db.appAuthSessions.delete({id}); },
    cleanupSessions: (condition, start, wrap, limit) => db.appAuthSessions.findMany({
      where: c => and(cleanupFilter(condition), wrap ? c.id.lessThan(start) : c.id.greaterThanOrEquals(start)),
      orderBy: c => [c.id.asc()], limit,
    }),
    refresh: id => db.appAuthRefreshTokens.findById({id}),
    refreshByToken: async hash => (await db.appAuthRefreshTokens.findMany({where: c => c.tokenHash.equals(hash), limit: 1}))[0],
    latestRefresh: async sessionId => (await db.appAuthRefreshTokens.findMany({
      where: c => and(c.sessionId.equals(sessionId), c.consumedAt.isNull()), orderBy: c => [c.createdAt.desc(), c.id.desc()], limit: 1,
    }))[0],
    refreshChildren: (sessionId, limit) => db.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(sessionId),
      orderBy: c => [c.createdAt.asc(), c.id.asc()], limit}),
    createRefresh: values => db.appAuthRefreshTokens.insert(values),
    consumeRefresh: (id, at) => db.appAuthRefreshTokens.updateIf({id}, c => c.consumedAt.isNull(), {consumedAt: at}),
    deleteRefresh: async id => { await db.appAuthRefreshTokens.delete({id}); },
    invite: id => db.appAuthInvites.findById({id}),
    inviteByCode: async hash => (await db.appAuthInvites.findMany({where: c => c.codeHash.equals(hash), limit: 1}))[0],
    createInvite: values => db.appAuthInvites.insert(values),
    updateInvite: (id, values) => db.appAuthInvites.update({id}, values),
    lockInvite: (row, email, hash, now) => db.appAuthInvites.updateIf({id: row.id}, c => and(c.codeHash.equals(hash),
      c.email.equals(email), c.redeemedAt.isNull(), c.redeemedBy.isNull(), c.revokedAt.isNull(),
      c.expiresAt.equals(row.expiresAt), c.expiresAt.greaterThan(now)), {expiresAt: row.expiresAt}),
    lockInviteExpiry: (row, cutoff) => db.appAuthInvites.updateIf({id: row.id},
      c => cutoff === undefined ? c.expiresAt.equals(row.expiresAt)
        : and(c.expiresAt.equals(row.expiresAt), c.expiresAt.lessThanOrEquals(cutoff)), {expiresAt: row.expiresAt}),
    listInvites: after => db.appAuthInvites.findMany({
      where: after ? c => or(c.createdAt.greaterThan(after[0]), and(c.createdAt.equals(after[0]), c.id.greaterThan(after[1]))) : undefined,
      orderBy: c => [c.createdAt.asc(), c.id.asc()], limit: 51,
    }),
    expiredInvites: (cutoff, limit) => db.appAuthInvites.findMany({where: c => c.expiresAt.lessThanOrEquals(cutoff),
      orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit}),
    deleteInvite: async id => { await db.appAuthInvites.delete({id}); },
    rateLimit: key => db.appAuthRateLimits.findById(key),
    createRateLimit: values => db.appAuthRateLimits.insert(values),
    updateRateLimit: (row, values) => db.appAuthRateLimits.updateIf({action: row.action, keyHash: row.keyHash},
      c => and(c.attemptCount.equals(row.attemptCount), c.expiresAt.equals(row.expiresAt)), values),
    expiredRateLimits: (cutoff, limit) => db.appAuthRateLimits.findMany({where: c => c.expiresAt.lessThanOrEquals(cutoff),
      orderBy: c => [c.expiresAt.asc(), c.action.asc(), c.keyHash.asc()], limit}),
    lockRateLimit: (row, cutoff) => db.appAuthRateLimits.updateIf({action: row.action, keyHash: row.keyHash},
      c => and(c.expiresAt.equals(row.expiresAt), c.attemptCount.equals(row.attemptCount), c.expiresAt.lessThanOrEquals(cutoff)),
      {attemptCount: row.attemptCount}),
    deleteRateLimit: async key => { await db.appAuthRateLimits.delete(key); },
  };
}
