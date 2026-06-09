import * as jose from "jose";

/**
 * Decoded representation of a Trust Mark JWT.
 *
 * The raw JWT lives on entity-configuration trust_marks[].trust_mark.
 * We parse it once and hand this object to every check.
 */
export interface TrustMarkData {
  /** The original signed JWT string */
  jwt: string;
  /** Decoded JOSE header */
  header: {
    alg?: string;
    kid?: string;
    typ?: string;
    [key: string]: unknown;
  };
  /** Decoded payload claims */
  payload: {
    iss?: string;
    sub?: string;
    id?: string;
    iat?: number;
    exp?: number;
    ref?: string;
    delegation?: string;
    [key: string]: unknown;
  };
}

/**
 * Subset of EntityConfiguration needed to cross-check trust mark claims.
 * Pass the full EC payload so checks can compare sub, and the EC JWKS so
 * the signature can be verified against the issuer's published keys.
 */
export interface TrustMarkContext {
  /** sub claim from the Entity Configuration */
  ecSub?: string;
  /**
   * The id value from the *outer* trust_marks[] entry in the EC
   * (i.e. trust_marks[i].id). Used to verify it matches the
   * id claim inside the Trust Mark JWT payload.
   */
  outerId?: string;
  /**
   * JWKS from the *issuer's* Entity Configuration (not the subject's).
   * When the tool resolves each trust mark it should fetch the issuer EC
   * and pass its jwks here. If unavailable, signature check will be skipped.
   */
  issuerJwks?: { keys: jose.JWK[] };
}

export type CheckStatus = "pass" | "fail" | "warn" | "skip";

export interface TrustMarkCheckResult {
  id: string;
  labelId: string;
  status: CheckStatus;
  detailId?: string;
  detail?: string;
}

// Format: [labelId, failDetailId?, skipDetailId?, warnDetailId?]

export const TM_CHECK_KEYS = {
  idMatchesOuter: ["tm_check_id_matches_outer", "tm_check_id_mismatch", "tm_check_id_skip", "tm_check_id_missing"],
  iatNotFuture:    ["tm_check_iat_not_future",    "tm_check_iat_future_fail",  "tm_check_iat_missing"],
  notExpired:      ["tm_check_not_expired",       "tm_check_exp_fail",         "tm_check_exp_missing"],
  algNotNone:      ["tm_check_alg_not_none",      "tm_check_alg_none_fail",    "tm_check_alg_missing"],
  jwtSignature:    ["tm_check_jwt_signature",     "tm_check_jwt_sig_fail",     "tm_check_jwt_sig_skip"],
  subMatchesEc:    ["tm_check_sub_matches_ec",    "tm_check_sub_ec_mismatch",  "tm_check_sub_ec_skip"],
} as const;

// helpers

const tryVerifyJWT = async (jwt: string, key: jose.JWK): Promise<boolean> => {
  try {
    const cryptoKey = await jose.importJWK(key);
    await jose.jwtVerify(jwt, cryptoKey);
    return true;
  } catch {
    return false;
  }
};

/**
 * Parse a raw Trust Mark JWT into a TrustMarkData object.
 * Returns null if the string is not a valid compact JWS.
 */
export const parseTrustMark = (jwt: string): TrustMarkData | null => {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { jwt, header, payload };
  } catch {
    return null;
  }
};

// individual checks

/** Check 1 – id in JWT payload matches the outer trust_marks[].id in the EC */
export const tmCheckIdMatchesOuter = (
  tm: TrustMarkData,
  ctx: TrustMarkContext
): TrustMarkCheckResult => {
  const [labelId, mismatchId, skipId, missingId] = TM_CHECK_KEYS.idMatchesOuter;
  if (!ctx.outerId) {
    return { id: "tm_id_matches_outer", labelId, status: "skip", detailId: skipId };
  }
  const inner = tm.payload.id;
  if (!inner) {
    return { id: "tm_id_matches_outer", labelId, status: "fail", detailId: missingId };
  }
  if (inner !== ctx.outerId) {
    return {
      id: "tm_id_matches_outer",
      labelId,
      status: "fail",
      detailId: mismatchId,
      detail: inner,
    };
  }
  return { id: "tm_id_matches_outer", labelId, status: "pass" };
};

/** Check 2 – iat is present and not in the future */
export const tmCheckIatNotFuture = (tm: TrustMarkData): TrustMarkCheckResult => {
  const [labelId, failId, missingId] = TM_CHECK_KEYS.iatNotFuture;
  const iat = tm.payload.iat;
  if (iat === undefined || iat === null) {
    return { id: "tm_iat_not_future", labelId, status: "fail", detailId: missingId };
  }
  if (iat > Date.now() / 1000) {
    return {
      id: "tm_iat_not_future",
      labelId,
      status: "fail",
      detailId: failId,
      detail: new Date(iat * 1000).toLocaleString(),
    };
  }
  return { id: "tm_iat_not_future", labelId, status: "pass" };
};

/** Check 3 – token is not expired (exp present and in the future) */
export const tmCheckNotExpired = (tm: TrustMarkData): TrustMarkCheckResult => {
  const [labelId, failId, missingId] = TM_CHECK_KEYS.notExpired;
  const exp = tm.payload.exp;
  if (exp === undefined || exp === null) {
    // exp is OPTIONAL in trust marks per spec, so warn rather than hard-fail
    return { id: "tm_not_expired", labelId, status: "warn", detailId: missingId };
  }
  if (exp < Date.now() / 1000) {
    return {
      id: "tm_not_expired",
      labelId,
      status: "fail",
      detailId: failId,
      detail: new Date(exp * 1000).toLocaleString(),
    };
  }
  return { id: "tm_not_expired", labelId, status: "pass" };
};

/** Check 4 – alg in header is not "none" */
export const tmCheckAlgNotNone = (tm: TrustMarkData): TrustMarkCheckResult => {
  const [labelId, failId, missingId] = TM_CHECK_KEYS.algNotNone;
  const alg = tm.header.alg;
  if (!alg) {
    return { id: "tm_alg_not_none", labelId, status: "fail", detailId: missingId };
  }
  if (alg.toLowerCase() === "none") {
    return { id: "tm_alg_not_none", labelId, status: "fail", detailId: failId };
  }
  return { id: "tm_alg_not_none", labelId, status: "pass" };
};

/** Check 5 – JWT signature is valid (async) using issuer JWKS */
export const tmCheckJwtSignature = async (
  tm: TrustMarkData,
  ctx: TrustMarkContext
): Promise<TrustMarkCheckResult> => {
  const [labelId, failId, skipId] = TM_CHECK_KEYS.jwtSignature;
  const keys = ctx.issuerJwks?.keys ?? [];
  if (keys.length === 0) {
    return { id: "tm_jwt_signature", labelId, status: "skip", detailId: skipId };
  }

  // Prefer the key matching the kid in the trust mark header; fall back to trying all keys.
  const kid = tm.header.kid;
  const candidates = kid ? keys.filter((k) => k.kid === kid) : keys;
  const keysToTry = candidates.length > 0 ? candidates : keys;

  for (const key of keysToTry) {
    if (await tryVerifyJWT(tm.jwt, key)) {
      return { id: "tm_jwt_signature", labelId, status: "pass" };
    }
  }
  return { id: "tm_jwt_signature", labelId, status: "fail", detailId: failId };
};

/** Check 6 – sub in trust mark matches sub of the Entity Configuration */
export const tmCheckSubMatchesEc = (
  tm: TrustMarkData,
  ctx: TrustMarkContext
): TrustMarkCheckResult => {
  const [labelId, failId, skipId] = TM_CHECK_KEYS.subMatchesEc;
  if (!ctx.ecSub) {
    return { id: "tm_sub_matches_ec", labelId, status: "skip", detailId: skipId };
  }
  if (!tm.payload.sub) {
    return { id: "tm_sub_matches_ec", labelId, status: "skip", detailId: skipId };
  }
  if (tm.payload.sub !== ctx.ecSub) {
    return {
      id: "tm_sub_matches_ec",
      labelId,
      status: "fail",
      detailId: failId,
      detail: tm.payload.sub,
    };
  }
  return { id: "tm_sub_matches_ec", labelId, status: "pass" };
};

// aggregate runner

/**
 * Run all trust mark checks for a single decoded TrustMarkData.
 * Async because signature verification requires crypto operations.
 *
 * @param tm      - Decoded trust mark (use parseTrustMark() to obtain it)
 * @param ctx     - Context from the entity configuration (ecSub, issuerJwks)
 */
export const runTrustMarkChecks = async (
  tm: TrustMarkData,
  ctx: TrustMarkContext
): Promise<TrustMarkCheckResult[]> => {
  const syncResults: TrustMarkCheckResult[] = [
    tmCheckIdMatchesOuter(tm, ctx),
    tmCheckIatNotFuture(tm),
    tmCheckNotExpired(tm),
    tmCheckAlgNotNone(tm),
    tmCheckSubMatchesEc(tm, ctx),
  ];

  const sigResult = await tmCheckJwtSignature(tm, ctx);

  return [...syncResults, sigResult];
};
