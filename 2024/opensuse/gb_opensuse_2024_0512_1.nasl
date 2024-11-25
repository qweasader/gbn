# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833803");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2023-40577");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 14:45:39 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:29 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for golang (SUSE-SU-2024:0512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0512-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/R7KOAT3NTU7F4PYW5T354XJKBLDPBXVX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang'
  package(s) announced via the SUSE-SU-2024:0512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-alertmanager fixes the following
  issues:

  golang-github-prometheus-alertmanager was updated from version 0.23.0 to 0.26.0
  (jsc#PED-7353):

  * Version 0.26.0:

  * Security fixes:

  * CVE-2023-40577: Fix stored XSS via the /api/v1/alerts endpoint in the Alertmanager UI (bsc#1218838)

  * Other changes and bugs fixed:

  * Configuration: Fix empty list of receivers and inhibit_rules would cause the alertmanager to crash

  * Templating: Fixed a race condition when using the title function. It is now race-safe

  * API: Fixed duplicate receiver names in the api/v2/receivers API endpoint

  * API: Attempting to delete a silence now returns the correct status code, 404 instead of 500

  * Clustering: Fixes a panic when tls_client_config is empty

  * Webhook: url is now marked as a secret. It will no longer show up in the logs as clear-text

  * Metrics: New label reason for alertmanager_notifications_failed_total metric to indicate the type of error of the alert delivery

  * Clustering: New flag --cluster.label, to help to block any traffic that is not meant for the cluster

  * Integrations: Add Microsoft Teams as a supported integration

  * Version 0.25.0:

  * Fail configuration loading if api_key and api_key_file are defined at the
      same time

  * Fix the alertmanager_alerts metric to avoid counting resolved alerts as
      active. Also added a new alertmanager_marked_alerts metric that retain the
      old behavior

  * Trim contents of Slack API URLs when reading from files

  * amtool: Avoid panic when the label value matcher is empty

  * Fail configuration loading if api_url is empty for OpsGenie

  * Fix email template for resolved notifications

  * Add proxy_url support for OAuth2 in HTTP client configuration

  * Reload TLS certificate and key from disk when updated

  * Add Discord integration

  * Add Webex integration

  * Add min_version support to select the minimum TLS version in HTTP client
      configuration

  * Add max_version support to select the maximum TLS version in HTTP client
      configuration

  * Emit warning logs when truncating messages in notifications

  * Support HEAD method for the /-/healthy and /-/ready endpoints

  * Add support for reading global and local SMTP passwords from files

  * UI: Add 'Link' button to alerts in list

  * UI: Allow to choose the first day of the week as Sunday or Monday

  * Version 0.24.0:

  * Fix HTTP client configuration for the SNS receiver

  * Fix unclosed file des ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'golang' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.26.0~150100.4.19.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.26.0~150100.4.19.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
