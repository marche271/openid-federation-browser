import { FormattedMessage, useIntl } from "react-intl";
import { CheckResult, CheckStatus } from "../lib/openid-federation/checks";
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

// summary badge

const SummaryBadge = ({ results }: { results: CheckResult[] }) => {
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
      <span
        className="badge bg-warning text-dark ms-2"
        style={{ fontSize: "0.7rem" }}
      >
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

// check row

const CheckRow = ({ check }: { check: CheckResult }) => {
  const intl = useIntl();
  const cfg = statusConfig[check.status];

  const detailText = check.detailId
    ? intl.formatMessage(
        { id: check.detailId },
        check.detail ? { detail: check.detail } : undefined
      )
    : check.detail;

  return (
    <tr data-testid={`check-row-${check.id}`}>
      {/* status icon */}
      <td style={{ width: "28px", verticalAlign: "middle" }}>
        <IconAtom
          iconID={cfg.iconId}
          className={cfg.iconClass}
          isRounded={false}
        />
      </td>

      {/* check label */}
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

// main component

export interface EntityChecksProps {
  results: CheckResult[];
  loading?: boolean;
}

export const EntityChecks = ({ results, loading }: EntityChecksProps) => {
  if (loading) {
    return (
      <div
        className="container"
        style={{ padding: "14px 24px" }}
        data-testid="entity-checks-loading"
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
      data-testid="entity-checks"
    >
      {/* header row with summary */}
      <div
        className="d-flex align-items-center mb-2"
        style={{ gap: "8px" }}
      >
        <span
          className={style.contextAccordinText}
          style={{ fontWeight: 600 }}
        >
          <FormattedMessage id="entity_checks_title" />
        </span>
        <SummaryBadge results={results} />
      </div>

      <table
        style={{ width: "100%", borderCollapse: "separate", borderSpacing: "0 4px" }}
        data-testid="entity-checks-table"
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
