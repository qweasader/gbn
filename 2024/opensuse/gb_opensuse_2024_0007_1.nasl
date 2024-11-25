# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833631");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-3559", "CVE-2023-42114", "CVE-2023-42115", "CVE-2023-42116", "CVE-2023-42117", "CVE-2023-42119", "CVE-2023-51766");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-20 12:33:30 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:30 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for exim (openSUSE-SU-2024:0007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0007-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HHLYW3QLWRHGQXVXSQUL2DBTCFFCJGNB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim'
  package(s) announced via the openSUSE-SU-2024:0007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exim fixes the following issues:

     exim was updated to 4.97.1 (boo#1218387, CVE-2023-51766):

  * Fixes for the smtp protocol smuggling (CVE-2023-51766)

     exim was updated to exim 4.96:

  * Move from using the pcre library to pcre2.

  * Constification work in the filters module required a major version
         bump for the local-scan API.  Specifically, the 'headers_charset'
         global which is visible via the API is now const and may therefore not
         be modified by local-scan code.

  * Bug 2819: speed up command-line messages being read in.  Previously a
         time check was being done for every character  replace that with one
         per buffer.

  * Bug 2815: Fix ALPN sent by server under OpenSSL.  Previously the
         string sent was prefixed with a length byte.

  * Change the SMTP feature name for pipelining connect to be compliant
         with RFC 5321.  Previously Dovecot (at least) would log errors during
         submission.

  * Fix macro-definition during '-be' expansion testing.  The move to
         write-protected store for macros had not accounted for these runtime
         additions  fix by removing this protection for '-be' mode.

  * Convert all uses of select() to poll().

  * Fix use of $sender_host_name in daemon process.  When used in certain
         main-section options or in a connect ACL, the value from the first
         ever connection was never replaced for subsequent connections.

  * Bug 2838: Fix for i32lp64 hard-align platforms

  * Bug 2845: Fix handling of tls_require_ciphers for OpenSSL when a value
         with underbars is given.

  * Bug 1895: TLS: Deprecate RFC 5114 Diffie-Hellman parameters.

  * Debugging initiated by an ACL control now continues through into
         routing and transport processes.

  * The 'expand' debug selector now gives more detail, specifically on the
         result of expansion operators and items.

  * Bug 2751: Fix include_directory in redirect routers.  Previously a bad
         comparison between the option value and the name of the file to be
         included was done, and a mismatch was wrongly identified.

  * Support for Berkeley DB versions 1 and 2 is withdrawn.

  * When built with NDBM for hints DB's check for nonexistence of a name
         supplied as the db file-pair basename.

  * Remove the 'allow_insecure_tainted_data' main config option and the
         'taint' log_selector.

  * Fix static address-list lookups to properly return the matched item.
         Previous ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'exim' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximon", rpm:"eximon~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximstats-html", rpm:"eximstats-html~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximon", rpm:"eximon~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eximstats-html", rpm:"eximstats-html~4.97.1~bp155.5.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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