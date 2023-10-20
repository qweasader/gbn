# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0389.1");
  script_cve_id("CVE-2011-3368", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0883", "CVE-2012-2687", "CVE-2012-4557");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0389-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130389-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Apache' package(s) announced via the SUSE-SU-2013:0389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

 * CVE-2012-4557: Denial of Service via special requests in mod_proxy_ajp
 * CVE-2012-0883: improper LD_LIBRARY_PATH handling
 * CVE-2012-2687: filename escaping problem

Additionally, some non-security bugs have been fixed:

 * ignore case when checking against SNI server names.
[bnc#798733]
 *
httpd-2.2.x-CVE-2011-3368_CVE-2011-4317-bnc722545.diff reworked to reflect the upstream changes. This will prevent the 'Invalid URI in request OPTIONS *' messages in the error log. [bnc#722545]
 * new sysconfig variable APACHE_DISABLE_SSL_COMPRESSION, if set to on,
OPENSSL_NO_DEFAULT_ZLIB will be inherited to the apache process, openssl will then transparently disable compression. This change affects start script and sysconfig fillup template. Default is on, SSL compression disabled.
Please see mod_deflate for compressed transfer at http layer. [bnc#782956]

Security Issue references:

 * CVE-2012-4557
>
 * CVE-2012-2687
>
 * CVE-2012-0883
>
 * CVE-2012-0021
>");

  script_tag(name:"affected", value:"'Apache' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.12~1.36.1", rls:"SLES11.0SP2"))) {
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
