// Business storage used by /user/checkUser.
//
// REPLACE THIS FILE WHEN INTEGRATING: both functions are in-memory demo implementations.
// Keep the signatures (async, same arguments / return values) and back them with your own
// user store and mapping table.

/**
 * @param {Iterable<string>} users demo user IDs (from the USERS environment variable)
 */
export function createUserStore(users) {
  const userIds = new Set(users);
  // openId + miniAppId <-> userId mapping: composite key `${miniAppId}:${openId}` is unique
  const openIdMapping = new Map();

  return {
    /**
     * Look up a user by your own user ID (the uid set by the Super App via setAccount).
     * @returns {Promise<boolean>} whether the user exists
     */
    async findUser(userId) {
      return userIds.has(userId);
    },

    /**
     * Persist the openId + miniAppId <-> userId mapping. Called only when the user exists
     * and the request carried encryptedData. Overwrite on conflict (upsert).
     */
    async saveOpenIdMapping({ openId, miniAppId, userId }) {
      openIdMapping.set(`${miniAppId}:${openId}`, { openId, miniAppId, userId, updateTime: Date.now() });
    },
  };
}
