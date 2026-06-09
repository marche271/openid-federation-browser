import { FormattedMessage, useIntl } from "react-intl";
import { TrustMarkCheckResult, CheckStatus } from "../lib/openid-federation/trustMarkChecks";
import { IconAtom } from "./Icon";
import style from "../css/ContextMenu.module.css";

// status icon mapping

const statusConfig: Record<
  CheckStatus,
  { iconId: string; iconClass: string; badgeClass: string; labelId: string }
> = {
  pass: {
    iconId: "#it-check",
    iconClass: "icon-sm icon-success",
    badgeClass: "badge bg-success",
    labelId: "check_status_pass",
  },
  fail: {
    iconId: "#it-close",
    iconClass: "icon-sm icon-danger",
    badgeClass: "badge bg-danger",
    labelId: "check_status_fail",
  },
  warn: {
    iconId: "#it-warning",
    iconClass: "icon-sm icon-warning",
    badgeClass: "badge bg-warning text-dark",
    labelId: "check_status_warn",
  },
  skip: {
    iconId: "#it-minus",
    iconClass: "icon-sm",
    badgeClass: "badge bg-secondary",
    labelId: "check_status_skip",
  },
};

// SummaryBadge

const SummaryBadge = ({ results }: { results: TrustMarkCheckResult[] }) => {
  const hasFailure = results.some((r) => r.status === "fail");
  const hasWarn = results.some((r) => r.status === "warn");

  if (hasFailure) {
    return (
      <span className="badge bg-danger ms-2" style={{ fontSize: "0.7rem" }}>
        <FormattedMessage id="checks_summary_fail" />
      </span>
    );
  }
  if (hasWarn) {
    return (
      <span className="badge bg-warning text-dark ms-2" style={{ fontSize: "0.7rem" }}>
        <FormattedMessage id="checks_summary_warn" />
      </span>
    );
  }
  return (
    <span className="badge bg-success ms-2" style={{ fontSize: "0.7rem" }}>
      <FormattedMessage id="checks_summary_pass" />
    </span>
  );
};

// CheckRow

const CheckRow = ({ check }: { check: TrustMarkCheckResult }) => {
  const intl = useIntl();
  const cfg = statusConfig[check.status];

  const detailText = check.detailId
    ? intl.formatMessage(
        { id: check.detailId },
        check.detail ? { detail: check.detail } : undefined
      )
    : check.detail;

  return (
    <tr data-testid={`tm-check-row-${check.id}`}>
      {/* status icon */}
      <td style={{ width: "28px", verticalAlign: "middle" }}>
        <IconAtom
          iconID={cfg.iconId}
          className={cfg.iconClass}
          isRounded={false}
        />
      </td>

      {/* check label + optional detail */}
      <td style={{ verticalAlign: "middle" }}>
        <span className={style.contextAccordinText}>
          <FormattedMessage id={check.labelId} />
        </span>
        {detailText && check.status !== "pass" && (
          <div
            style={{
              fontSize: "0.78rem",
              color: check.status === "warn" ? "#856404" : "#842029",
              marginTop: "2px",
              wordBreak: "break-all",
            }}
          >
            {detailText}
          </div>
        )}
      </td>

      {/* status badge */}
      <td style={{ width: "60px", textAlign: "right", verticalAlign: "middle" }}>
        <span className={cfg.badgeClass} style={{ fontSize: "0.68rem" }}>
          <FormattedMessage id={cfg.labelId} />
        </span>
      </td>
    </tr>
  );
};

// TrustMarkChecks

export interface TrustMarkChecksProps {
  /** The decoded id of this trust mark (displayed as section heading) */
  trustMarkId?: string;
  results: TrustMarkCheckResult[];
  loading?: boolean;
}

export const TrustMarkChecks = ({
  trustMarkId,
  results,
  loading,
}: TrustMarkChecksProps) => {
  if (loading) {
    return (
      <div
        className="container"
        style={{ padding: "14px 24px" }}
        data-testid="tm-checks-loading"
      >
        <div className="d-flex align-items-center gap-2">
          <div
            className="spinner-border spinner-border-sm text-primary"
            role="status"
          />
          <span className={style.contextAccordinText}>
            <FormattedMessage id="checks_loading" />
          </span>
        </div>
      </div>
    );
  }

  return (
    <div
      className="container"
      style={{ padding: "14px 24px" }}
      data-testid="tm-checks"
    >
      {/* header */}
      <div className="d-flex align-items-center mb-2" style={{ gap: "8px" }}>
        <span
          className={style.contextAccordinText}
          style={{ fontWeight: 600 }}
        >
          <FormattedMessage id="trust_mark_checks_title" />
        </span>
        {results.length > 0 && <SummaryBadge results={results} />}
      </div>

      {/* optional trust_mark id sub-label */}
      {trustMarkId && (
        <div
          style={{
            fontSize: "0.75rem",
            color: "#5a6473",
            marginBottom: "8px",
            wordBreak: "break-all",
          }}
          data-testid="tm-checks-id"
        >
          {trustMarkId}
        </div>
      )}

      <table
        style={{
          width: "100%",
          borderCollapse: "separate",
          borderSpacing: "0 4px",
        }}
        data-testid="tm-checks-table"
      >
        <tbody>
          {results.map((check) => (
            <CheckRow key={check.id} check={check} />
          ))}
        </tbody>
      </table>
    </div>
  );
};

// TrustMarkChecksList — renders checks for every trust mark in the array

export interface TrustMarkEntry {
  /** The raw trust_mark_type id (from entity config trust_marks[].id) */
  id: string;
  results: TrustMarkCheckResult[];
  loading?: boolean;
}

export interface TrustMarkChecksListProps {
  entries: TrustMarkEntry[];
}

export const TrustMarkChecksList = ({ entries }: TrustMarkChecksListProps) => {
  if (entries.length === 0) {
    return (
      <div
        className="container"
        style={{ padding: "14px 24px", color: "#5a6473", fontSize: "0.85rem" }}
        data-testid="tm-checks-empty"
      >
        <FormattedMessage id="trust_mark_checks_none" />
      </div>
    );
  }

  return (
    <>
      {entries.map((entry, idx) => (
        <div key={entry.id}>
          {idx > 0 && (
            <hr style={{ margin: "0 24px", borderColor: "#d9e3f0" }} />
          )}
          <TrustMarkChecks
            trustMarkId={entry.id}
            results={entry.results}
            loading={entry.loading}
          />
        </div>
      ))}
    </>
  );
};
