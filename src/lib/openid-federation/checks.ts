import * as jose from "jose";
import { EntityConfiguration } from "./types";

export type CheckStatus = "pass" | "fail" | "warn" | "skip";

export interface CheckResult {
  id: string;
  labelId: string;
  status: CheckStatus;
  detailId?: string;
  detail?: string;
}

// Each entry: [labelId, failDetailId?, skipDetailId?, warnDetailId?]
export const CHECK_KEYS = {
  kidMatchesJwks:  ["check_kid_matches_jwks", "check_kid_jwks_fail", "check_kid_jwks_skip"],
  jwksNotEmpty:    ["check_jwks_not_empty", "check_jwks_empty_fail"],
  allKeysHaveKid:  ["check_all_keys_kid", "check_all_keys_kid_fail", "check_all_keys_kid_skip", "check_all_keys_kid_warn"],
  jwtSignature:    ["check_jwt_signature", "check_jwt_sig_fail", "check_jwt_sig_skip"],
  notExpired:      ["check_not_expired", "check_exp_fail", "check_exp_missing"],
  iatNotFuture:    ["check_iat_not_future", "check_iat_future_fail", "check_iat_missing"],
  issSub:          ["check_iss_sub", "check_iss_sub_fail", "check_iss_sub_missing"]
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

// individual checks

/** Check 1 – kid in header matches at least one kid in jwks body */
export const checkKidMatchesJwks = (ec: EntityConfiguration): CheckResult => {
  const [labelId, failId, skipId] = CHECK_KEYS.kidMatchesJwks;
  const kid = ec.header.kid;
  if (!kid) {
    return { id: "kid_matches_jwks", labelId, status: "skip", detailId: skipId };
  }
  const keys = ec.payload?.jwks?.keys ?? [];
  const match = keys.find((k) => k.kid === kid);
  if (!match) {
    return { id: "kid_matches_jwks", labelId, status: "fail", detailId: failId, detail: kid };
  }
  return { id: "kid_matches_jwks", labelId, status: "pass" };
};

/** Check 2 – at least one key in jwks */
export const checkJwksNotEmpty = (ec: EntityConfiguration): CheckResult => {
  const [labelId, failId] = CHECK_KEYS.jwksNotEmpty;
  const keys = ec.payload?.jwks?.keys ?? [];
  if (keys.length === 0) {
    return { id: "jwks_not_empty", labelId, status: "fail", detailId: failId };
  }
  return { id: "jwks_not_empty", labelId, status: "pass" };
};

/** Check 3 – all keys in jwks have a kid */
export const checkAllKeysHaveKid = (ec: EntityConfiguration): CheckResult => {
  const [labelId, , skipId, warnId] = CHECK_KEYS.allKeysHaveKid;
  const keys = ec.payload?.jwks?.keys ?? [];
  if (keys.length === 0) {
    return { id: "all_keys_have_kid", labelId, status: "skip", detailId: skipId };
  }
  const missing = keys.filter((k) => !k.kid || k.kid.trim() === "");
  if (missing.length > 0) {
    return { id: "all_keys_have_kid", labelId, status: "warn", detailId: warnId, detail: String(missing.length) };
  }
  return { id: "all_keys_have_kid", labelId, status: "pass" };
};

/** Check 4 – JWT signature is valid (async) */
export const checkJwtSignature = async (ec: EntityConfiguration): Promise<CheckResult> => {
  const [labelId, failId, skipId] = CHECK_KEYS.jwtSignature;
  const kid = ec.header.kid;
  const keys = ec.payload?.jwks?.keys ?? [];
  const key = keys.find((k) => k.kid === kid);
  if (!key) {
    return { id: "jwt_signature", labelId, status: "skip", detailId: skipId };
  }
  const valid = await tryVerifyJWT(ec.jwt, key);
  if (!valid) {
    return { id: "jwt_signature", labelId, status: "fail", detailId: failId };
  }
  return { id: "jwt_signature", labelId, status: "pass" };
};

/** Check 5 – token is not expired */
export const checkNotExpired = (ec: EntityConfiguration): CheckResult => {
  const [labelId, failId, missingId] = CHECK_KEYS.notExpired;
  const exp = ec.payload?.exp;
  if (!exp) {
    return { id: "not_expired", labelId, status: "fail", detailId: missingId };
  }
  if (exp < Date.now() / 1000) {
    return { id: "not_expired", labelId, status: "fail", detailId: failId, detail: new Date(exp * 1000).toLocaleString() };
  }
  return { id: "not_expired", labelId, status: "pass" };
};

/** Check 6 – iat is not in the future */
export const checkIatNotFuture = (ec: EntityConfiguration): CheckResult => {
  const [labelId, failId, missingId] = CHECK_KEYS.iatNotFuture;
  const iat = ec.payload?.iat;
  if (!iat) {
    return { id: "iat_not_future", labelId, status: "fail", detailId: missingId };
  }
  if (iat > Date.now() / 1000) {
    return { id: "iat_not_future", labelId, status: "fail", detailId: failId, detail: new Date(iat * 1000).toLocaleString() };
  }
  return { id: "iat_not_future", labelId, status: "pass" };
};

/** Check 7 – iss matches sub (self-issued configuration) */
export const checkIssSub = (ec: EntityConfiguration): CheckResult => {
  const [labelId, failId, missingId] = CHECK_KEYS.issSub;
  const iss = ec.payload?.iss;
  const sub = ec.payload?.sub;
  if (!iss || !sub) {
    return { id: "iss_sub_match", labelId, status: "fail", detailId: missingId };
  }
  if (iss !== sub) {
    return { id: "iss_sub_match", labelId, status: "fail", detailId: failId };
  }
  return { id: "iss_sub_match", labelId, status: "pass" };
};

/** Check 8 – alg none */
export const checkAlgNotNone = (ec: EntityConfiguration): CheckResult => {
  const labelId = "check_alg_not_none";
  const alg = ec.header.alg;
  if (!alg) {
    return { id: "alg_not_none", labelId, status: "fail", detailId: "check_alg_missing" };
  }
  if (alg.toLowerCase() === "none") {
    return { id: "alg_not_none", labelId, status: "fail", detailId: "check_alg_none_fail" };
  }
  return { id: "alg_not_none", labelId, status: "pass" };
};

// aggregate
/**
 * Run all checks on an EntityConfiguration and return the results array.
 * Async because the signature check requires crypto operations.
 */
export const runEntityConfigurationChecks = async (
  ec: EntityConfiguration
): Promise<CheckResult[]> => {
  const syncResults: CheckResult[] = [
    checkKidMatchesJwks(ec),
    checkJwksNotEmpty(ec),
    checkAllKeysHaveKid(ec),
    checkNotExpired(ec),
    checkIatNotFuture(ec),
    checkIssSub(ec),
  ];

  const sigResult = await checkJwtSignature(ec);

  return [...syncResults, sigResult];
};